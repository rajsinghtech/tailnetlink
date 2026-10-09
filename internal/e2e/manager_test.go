package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/bridge"
	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/metrics"
	"github.com/rajsinghtech/tailnetlink/internal/server"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	"tailscale.com/net/netns"
)

// e2eSetup skips in -short mode and turns off netns for in-process nodes.
func e2eSetup(t *testing.T) context.Context {
	t.Helper()
	if testing.Short() {
		t.Skip("e2e: starts real tsnet nodes")
	}
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func randSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// border is two testcontrol tailnets, each with its own admin API bridge.
type border struct {
	sfx              string
	src, dst         *tailnet
	srcAPI, dstAPI   *ctlBridge
	srcName, dstName string // tailnet names in the tailnetlink config
	stateDir         string
	secretFiles      []string // the secrets, one per file, mode 0600
}

func newBorder(t *testing.T) *border {
	t.Helper()
	b := &border{sfx: randSuffix(t), stateDir: t.TempDir()}
	b.src = newTailnet(t, "src.ts.net")
	b.dst = newTailnet(t, "dst.ts.net")
	b.srcAPI = newCtlBridge(t, b.src)
	b.dstAPI = newCtlBridge(t, b.dst)
	// The keys a compiled border uses, so b.config and b.border agree.
	b.srcName = "e2e-" + b.sfx + "-src"
	b.dstName = "e2e-" + b.sfx + "-dst"
	// The bridges only hand out tokens for the right secret, and
	// tailnetlink only ever sees the secrets through files.
	dir := t.TempDir()
	for i, sec := range b.secrets() {
		f := filepath.Join(dir, fmt.Sprintf("secret-%d", i))
		if err := os.WriteFile(f, []byte(sec+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		b.secretFiles = append(b.secretFiles, f)
	}
	b.srcAPI.secret = b.secrets()[0]
	b.dstAPI.secret = b.secrets()[1]
	return b
}

// secrets are the OAuth client secrets in the config. They must never show
// up in anything tailnetlink serves.
func (b *border) secrets() []string {
	return []string{"src-secret-" + b.sfx, "dst-secret-" + b.sfx}
}

func (b *border) tailnetConfig(tn *tailnet, api *ctlBridge, secretFile string) config.TailnetConfig {
	return config.TailnetConfig{
		OAuth:      config.OAuthCreds{ClientID: "client-" + b.sfx, ClientSecretFile: secretFile},
		Tags:       []string{"tag:tailnetlink"},
		Tailnet:    tn.domain,
		ControlURL: tn.url,
		APIBaseURL: api.URL(),
	}
}

func (b *border) config(rules ...config.BridgeRule) *config.Config {
	return &config.Config{
		InstanceID: "e2e-" + b.sfx,
		Tailnets: map[string]config.TailnetConfig{
			b.srcName: b.tailnetConfig(b.src, b.srcAPI, b.secretFiles[0]),
			b.dstName: b.tailnetConfig(b.dst, b.dstAPI, b.secretFiles[1]),
		},
		Bridges:      rules,
		StateDir:     b.stateDir,
		PollInterval: config.Duration{Duration: 200 * time.Millisecond},
		DialTimeout:  config.Duration{Duration: 5 * time.Second},
	}
}

// fileLink is one device target the way a config file writes it.
type fileLink struct {
	Name, Host, Short string
	Ports             []int
	Authz             config.AuthzConfig
}

func (b *border) tailnetSpec(tn *tailnet, api *ctlBridge, secretFile string) config.TailnetSpec {
	tc := b.tailnetConfig(tn, api, secretFile)
	return config.TailnetSpec{
		Tailnet: tc.Tailnet, Auth: tc.OAuth, Tags: tc.Tags,
		ControlURL: tc.ControlURL, APIBaseURL: tc.APIBaseURL,
	}
}

// fileConfig is the config-file form of b.config.
func (b *border) fileConfig(links ...fileLink) *config.File {
	poll, dial := config.Duration{Duration: 200 * time.Millisecond}, config.Duration{Duration: 5 * time.Second}
	f := &config.File{
		Name:     "e2e-" + b.sfx,
		StateDir: b.stateDir,
		Tailnets: map[string]config.TailnetSpec{
			b.srcName: b.tailnetSpec(b.src, b.srcAPI, b.secretFiles[0]),
			b.dstName: b.tailnetSpec(b.dst, b.dstAPI, b.secretFiles[1]),
		},
		Targets:      map[string]config.TargetSpec{},
		PollInterval: &poll,
		DialTimeout:  &dial,
	}
	for _, l := range links {
		ports := config.LocalPortList(l.Ports...)
		f.Targets[l.Name] = config.TargetSpec{In: b.srcName, Device: l.Host + "." + b.src.domain, Ports: ports}
		ex := config.ExportSpec{Target: l.Name, To: []string{b.dstName}, Name: l.Short, Authz: l.Authz}
		f.Exports = append(f.Exports, ex)
	}
	return f
}

// writeBorder writes f to path as a config file.
func writeBorder(t *testing.T, path string, f *config.File) {
	t.Helper()
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// deviceLink is deviceRule as a config-file target.
func (b *border) deviceLink(name, host, shortName string, ports ...int) fileLink {
	return fileLink{Name: name, Host: host, Short: shortName, Ports: ports}
}

// deviceRule bridges one source device by FQDN.
func (b *border) deviceRule(name, host, shortName string, ports ...int) config.BridgeRule {
	return config.BridgeRule{
		Name:          name,
		SourceTailnet: b.srcName,
		DestTailnets:  []string{b.dstName},
		SourceDevices: []config.DeviceSpec{{FQDN: host + "." + b.src.domain, ShortName: shortName}},
		Ports:         ports,
	}
}

func (b *border) serviceName(host, shortName string) string {
	return bridge.ServiceName(b.srcName, host+"."+b.src.domain, shortName)
}

// lockedBuffer is a log sink safe for concurrent writes.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

type running struct {
	m       *bridge.Manager
	metrics *metrics.Metrics
	logger  *slog.Logger
	store   *state.Store
	logs    *lockedBuffer
	ctx     context.Context
	cancel  context.CancelFunc

	cfgMu sync.Mutex
	cfg   *config.Config // last config passed to reconcile
}

// startManager runs a bridge manager with cfg until the test ends. With
// webAddr set it also runs the read-only UI: served locally on webAddr and
// handed to the manager to publish in each tailnet, the way main does.
func startManager(t *testing.T, cfg *config.Config, webAddr string) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{store: state.New(), logs: &lockedBuffer{}, ctx: ctx, cancel: cancel, cfg: cfg.Clone()}
	r.logger = slog.New(slog.NewTextHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	var ui http.Handler
	if webAddr != "" {
		srv := server.New(webAddr, r.store, r.config, r.logger)
		ui = srv.Handler()
		go srv.Run(ctx) //nolint:errcheck // stops with the manager
	}
	r.m = bridge.New(r.store, r.logger, ui)
	r.metrics = metrics.New()
	r.m.SetMetrics(r.metrics)
	t.Cleanup(func() {
		r.stop(t)
		if t.Failed() {
			t.Logf("tailnetlink log:\n%s", r.logs.String())
		}
	})
	r.m.Reconcile(ctx, cfg)
	return r
}

// config returns the last config given to the manager.
func (r *running) config() *config.Config {
	r.cfgMu.Lock()
	defer r.cfgMu.Unlock()
	return r.cfg.Clone()
}

// reconcile applies a new config.
func (r *running) reconcile(cfg *config.Config) {
	r.cfgMu.Lock()
	r.cfg = cfg.Clone()
	r.cfgMu.Unlock()
	r.m.Reconcile(r.ctx, cfg)
}

// stop shuts the manager down the way SIGTERM does: cancel, then Close with
// the default 20 s limit. Calling it twice is fine.
func (r *running) stop(t *testing.T) {
	t.Helper()
	r.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := r.m.Close(ctx); err != nil {
		t.Errorf("close: %v", err)
	}
}

// bridgeStatus returns the status and error of a bridge entry, or "" if it
// does not exist.
func (r *running) bridgeStatus(id string) (string, string) {
	for _, b := range r.store.GetBridges() {
		if b.ID == id {
			return string(b.Status), b.Error
		}
	}
	return "", ""
}

func (r *running) logged(substr string) bool {
	for _, l := range r.store.GetLogs(1000) {
		if strings.Contains(l.Message, substr) {
			return true
		}
	}
	return false
}

// echoBackend starts a node in tn that answers lines on port.
func echoBackend(t *testing.T, ctx context.Context, tn *tailnet, host string, port int) (node, chan string) {
	t.Helper()
	n := tn.node(t, ctx, host)
	ln, err := n.srv.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	peers := make(chan string, 16)
	go serveEcho(ln, peers)
	return n, peers
}

// client starts a node in tn that accepts subnet routes, so it can reach
// VIP services. RouteAll is set before Up so the first netmap can install
// a VIP prefix that is already published.
func client(t *testing.T, ctx context.Context, tn *tailnet, host string) node {
	t.Helper()
	return tn.startNode(t, ctx, host, true)
}

// waitVIP waits for a service to exist in api and returns its first address.
func waitVIP(t *testing.T, api *ctlBridge, name string) netip.Addr {
	t.Helper()
	var vip netip.Addr
	waitFor(t, 30*time.Second, "VIP service "+name, func() bool {
		s, ok := api.Service(name)
		if !ok || len(s.Addrs) == 0 {
			return false
		}
		vip = netip.MustParseAddr(s.Addrs[0])
		return true
	})
	return vip
}

// echoVia dials addr from n and checks that a line comes back echoed.
func echoVia(t *testing.T, ctx context.Context, n node, addr netip.AddrPort, msg string) {
	t.Helper()
	var last error
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if last = tryEcho(ctx, n, addr, msg); last == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("echo %q via %s: %v", msg, addr, last)
}

func tryEcho(ctx context.Context, n node, addr netip.AddrPort, msg string) error {
	dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	c, err := n.srv.Dial(dctx, "tcp", addr.String())
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(c, msg+"\n"); err != nil {
		return err
	}
	got, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return err
	}
	if want := "echo: " + msg + "\n"; got != want {
		return fmt.Errorf("reply %q, want %q", got, want)
	}
	return nil
}

// httpVia returns an HTTP client that sends every request to addr through n.
func httpVia(n node, addr netip.AddrPort) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return n.srv.Dial(ctx, "tcp", addr.String())
		}},
	}
}

// TestManagerEndToEnd runs the whole manager: a backend in src gets a VIP
// service in dst, traffic flows through it, and the service goes away when
// the backend does.
func TestManagerEndToEnd(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	_, peers := echoBackend(t, ctx, b.src, "backend", 8080)
	cl := client(t, ctx, b.dst, "client")

	r := startManager(t, b.config(b.deviceRule("web", "backend", "", 8080)), "")
	svc := b.serviceName("backend", "")
	vip := waitVIP(t, b.dstAPI, svc)
	echoVia(t, ctx, cl, netip.AddrPortFrom(vip, 8080), "hello")

	select {
	case p := <-peers:
		if strings.HasPrefix(p, cl.ip.String()+":") {
			t.Errorf("backend saw the client %s directly", p)
		}
	case <-time.After(5 * time.Second):
		t.Error("backend never saw a connection")
	}
	if st, _ := r.bridgeStatus("web/" + b.dstName + "/backend." + b.src.domain); st != string(state.BridgeStatusActive) {
		t.Errorf("bridge status = %q", st)
	}

	b.srcAPI.hide("backend")
	waitFor(t, 30*time.Second, "service removed after the backend left", func() bool {
		_, ok := b.dstAPI.Service(svc)
		return !ok
	})
}

// TestManagerTwoLinksSameBorder runs two rules over one border, one with two
// ports.
func TestManagerTwoLinksSameBorder(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	echoBackend(t, ctx, b.src, "one", 7001)
	two := b.src.node(t, ctx, "two")
	for _, p := range []int{7002, 7003} {
		ln, err := two.srv.Listen("tcp", fmt.Sprintf(":%d", p))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go serveEcho(ln, make(chan string, 16))
	}
	cl := client(t, ctx, b.dst, "client")

	startManager(t, b.config(
		b.deviceRule("one", "one", "", 7001),
		b.deviceRule("two", "two", "two-"+b.sfx, 7002, 7003),
	), "")
	vip1 := waitVIP(t, b.dstAPI, b.serviceName("one", ""))
	vip2 := waitVIP(t, b.dstAPI, "svc:two-"+b.sfx)
	echoVia(t, ctx, cl, netip.AddrPortFrom(vip1, 7001), "one")
	echoVia(t, ctx, cl, netip.AddrPortFrom(vip2, 7002), "two a")
	echoVia(t, ctx, cl, netip.AddrPortFrom(vip2, 7003), "two b")
}
