//go:build e2e

// Package e2e runs tailnetlink against real Tailscale tailnets.
//
// In CI the e2e-real workflow creates two throwaway tailnets (src and dst)
// before the tests and deletes them afterwards in its own job; the tests get
// their IDs and federated identity client IDs from the environment. Run
// locally with only TS_API_ACCESS_TOKEN set (an org token that can create
// tailnets) and the tests create their own pair and delete it in TestMain.
// With no TS_API_ACCESS_TOKEN every test skips.
//
// The layout and the env-driven skip follow rajsinghtech/tailgate's test/e2e.
package e2e

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/bridge"
	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/server"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	"github.com/rajsinghtech/tailnetlink/test/e2e/tailnet"
	tsclient "tailscale.com/client/tailscale/v2"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

// appScopes is what tailnetlink's OAuth client gets in each test tailnet:
// the same least-privilege set the README asks real users for. If the API
// rejects a scope name here (see roadmap problem 13), setup fails loudly.
var appScopes = []string{"auth_keys", "devices:core:read", "services", "dns"}

const linkTag = "tag:tailnetlink"

type side struct {
	role string
	id   string
	dns  string
	tok  tailnet.TokenSource
}

var (
	pairOnce sync.Once
	pair     [2]*side
	pairErr  error
	api      *tailnet.Client
	// local holds tailnets this process created, deleted in TestMain.
	local []localTailnet
)

type localTailnet struct {
	id, name string
	tok      tailnet.TokenSource
}

func TestMain(m *testing.M) {
	code := m.Run()
	if len(local) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		for _, tn := range local {
			if err := api.DeleteAndVerify(ctx, tn.tok, tn.id, tailnet.Retry{}); err != nil {
				fmt.Fprintf(os.Stderr, "FAILED to delete test tailnet %s (%s): %v\n", tn.name, tn.id, err)
				code = 1
			} else {
				fmt.Fprintf(os.Stderr, "deleted test tailnet %s\n", tn.name)
			}
		}
		cancel()
	}
	os.Exit(code)
}

// tailnets returns the shared src and dst tailnets, or skips the test.
func tailnets(t *testing.T) (src, dst *side) {
	t.Helper()
	org := os.Getenv("TS_API_ACCESS_TOKEN")
	if org == "" {
		t.Skip("TS_API_ACCESS_TOKEN not set; skipping real-tailnet e2e")
	}
	pairOnce.Do(func() {
		api = tailnet.New(os.Getenv("TS_API_BASE"), tailnet.StaticToken(org))
		if os.Getenv("E2E_SRC_ID") != "" {
			pair[0], pairErr = fromEnv("SRC", "src")
			if pairErr == nil {
				pair[1], pairErr = fromEnv("DST", "dst")
			}
			return
		}
		pair[0], pairErr = createLocal("src")
		if pairErr == nil {
			pair[1], pairErr = createLocal("dst")
		}
	})
	if pairErr != nil {
		t.Fatalf("test tailnets: %v", pairErr)
	}
	return pair[0], pair[1]
}

// fromEnv reads a tailnet the workflow created. The token comes from the
// federated identity inside it (fresh OIDC token per call) or, failing that,
// a pre-minted E2E_<P>_TOKEN.
func fromEnv(p, role string) (*side, error) {
	s := &side{role: role, id: os.Getenv("E2E_" + p + "_ID"), dns: os.Getenv("E2E_" + p + "_DNS_NAME")}
	if fed := os.Getenv("E2E_" + p + "_FED_CLIENT_ID"); fed != "" {
		if o, ok := tailnet.GitHubOIDCFromEnv(os.Getenv); ok {
			s.tok = api.WIFToken(o, fed, os.Getenv("E2E_"+p+"_FED_AUDIENCE"))
			return s, nil
		}
	}
	if tok := os.Getenv("E2E_" + p + "_TOKEN"); tok != "" {
		s.tok = tailnet.StaticToken(tok)
		return s, nil
	}
	return nil, fmt.Errorf("E2E_%s_ID is set but there is no way to get a token for it", p)
}

func createLocal(role string) (*side, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	name := tailnet.Name(fmt.Sprint(time.Now().Unix()), "0", role)
	tn, err := api.Create(ctx, name)
	if err != nil {
		return nil, err
	}
	tok := api.OAuthToken(tn.OAuthClientID, tn.OAuthClientSecret)
	local = append(local, localTailnet{id: tn.ID, name: name, tok: tok})
	if err := api.ApplyPolicy(ctx, tok, tn.ID, tailnet.Policy); err != nil {
		return nil, err
	}
	return &side{role: role, id: tn.ID, dns: tn.DNSName, tok: tok}, nil
}

// bearer adapts a TokenSource to the Tailscale client's Auth interface.
type bearer struct{ tok tailnet.TokenSource }

func (b bearer) HTTPClient(orig *http.Client, _ string) *http.Client {
	c := *orig
	base := orig.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	c.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		tok, err := b.tok(r.Context())
		if err != nil {
			return nil, err
		}
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer "+tok)
		return base.RoundTrip(r)
	})
	return &c
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func (s *side) client() *tsclient.Client {
	return &tsclient.Client{Tailnet: s.id, Auth: bearer{s.tok}}
}

func suffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

type node struct {
	srv  *tsnet.Server
	ip   netip.Addr
	fqdn string
}

// join starts an ephemeral tsnet node in s with tag.
func join(t *testing.T, ctx context.Context, s *side, hostname, tag string) node {
	t.Helper()
	key, err := api.CreateAuthKey(ctx, s.tok, s.id, []string{tag})
	if err != nil {
		t.Fatalf("auth key for %s: %v", hostname, err)
	}
	srv := &tsnet.Server{
		Hostname:  hostname,
		AuthKey:   key,
		Ephemeral: true,
		Dir:       t.TempDir(),
		Store:     new(mem.Store),
		Logf:      logger.Discard,
	}
	t.Cleanup(func() { srv.Close() })
	st, err := srv.Up(ctx)
	if err != nil {
		t.Fatalf("%s up: %v", hostname, err)
	}
	return node{srv: srv, ip: st.TailscaleIPs[0], fqdn: strings.TrimSuffix(st.Self.DNSName, ".")}
}

func acceptRoutes(t *testing.T, ctx context.Context, n node) {
	t.Helper()
	lc, err := n.srv.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{RouteAllSet: true, Prefs: ipn.Prefs{RouteAll: true}}); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}

func serveEcho(ln net.Listener, peers chan<- string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case peers <- c.RemoteAddr().String():
		default:
		}
		go func(c net.Conn) {
			defer c.Close()
			r := bufio.NewReader(c)
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if _, err := io.WriteString(c, "echo: "+line); err != nil {
					return
				}
			}
		}(c)
	}
}

// link is one running tailnetlink manager bridging a backend in src to dst.
type link struct {
	sfx       string
	svc       string // VIP service name in dst
	cfg       *config.Config
	secrets   []string // OAuth secrets tailnetlink was given
	backend   node
	client    node
	peers     chan string
	cancel    context.CancelFunc
	src, dst  *side
	webAddr   string
	cfgPath   string
	echoPort  int
	logOutput *strings.Builder
	store     *state.Store
	mgr       *bridge.Manager
}

// stop shuts tailnetlink down the way SIGTERM does: cancel, then Close with
// the default 20 s limit.
func (l *link) stop(t *testing.T) {
	t.Helper()
	l.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := l.mgr.Close(ctx); err != nil {
		t.Errorf("close: %v", err)
	}
}

type linkOpts struct {
	shortName  string // default e2e-echo-<sfx>
	webUI      bool   // run the local UI and publish svc:tailnetlink
	persistent bool   // keep node state across restarts; default ephemeral
}

// startLink joins a backend in src and a client in dst, gives tailnetlink a
// fresh least-privilege OAuth client in each tailnet, and starts the manager.
func startLink(t *testing.T, ctx context.Context, o linkOpts) *link {
	t.Helper()
	src, dst := tailnets(t)
	l := &link{sfx: suffix(t), src: src, dst: dst, echoPort: 7000, peers: make(chan string, 16), logOutput: &strings.Builder{}}
	if o.shortName == "" {
		o.shortName = "e2e-echo-" + l.sfx
	}
	l.svc = "svc:" + o.shortName

	l.backend = join(t, ctx, src, "e2e-backend-"+l.sfx, "tag:e2e-backend")
	ln, err := l.backend.srv.Listen("tcp", fmt.Sprintf(":%d", l.echoPort))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go serveEcho(ln, l.peers)

	l.client = join(t, ctx, dst, "e2e-client-"+l.sfx, "tag:e2e-client")
	acceptRoutes(t, ctx, l.client)

	// tailnetlink gets the secrets only through 0600 files.
	creds := map[string]config.OAuthCreds{}
	secretDir := t.TempDir()
	for _, s := range []*side{src, dst} {
		id, secret, err := api.CreateOAuthClient(ctx, s.tok, s.id, "tailnetlink e2e "+l.sfx, appScopes, []string{linkTag})
		if err != nil {
			t.Fatalf("oauth client for tailnetlink in %s: %v", s.role, err)
		}
		f := filepath.Join(secretDir, s.role+"-secret")
		if err := os.WriteFile(f, []byte(secret), 0o600); err != nil {
			t.Fatal(err)
		}
		creds[s.role] = config.OAuthCreds{ClientID: id, ClientSecretFile: f}
		l.secrets = append(l.secrets, secret)
	}
	l.cfg = &config.Config{
		InstanceID: "e2e-" + l.sfx,
		Tailnets: map[string]config.TailnetConfig{
			"src-" + l.sfx: {OAuth: creds["src"], Tags: []string{linkTag}, Tailnet: src.id, Ephemeral: !o.persistent},
			"dst-" + l.sfx: {OAuth: creds["dst"], Tags: []string{linkTag}, Tailnet: dst.id, Ephemeral: !o.persistent},
		},
		StateDir: t.TempDir(),
		Bridges: []config.BridgeRule{{
			Name:          "e2e-" + l.sfx,
			SourceTailnet: "src-" + l.sfx,
			DestTailnets:  []string{"dst-" + l.sfx},
			SourceDevices: []config.DeviceSpec{{FQDN: l.backend.fqdn, ShortName: o.shortName}},
			Ports:         []int{l.echoPort},
		}},
		PollInterval: config.Duration{Duration: 5 * time.Second},
		DialTimeout:  config.Duration{Duration: 10 * time.Second},
	}

	if o.webUI {
		pl, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		l.webAddr = pl.Addr().String()
		pl.Close()
		l.cfg.ListenAddr = l.webAddr
		l.cfgPath = filepath.Join(t.TempDir(), "tailnetlink.json")
		b, _ := json.Marshal(l.cfg)
		if err := os.WriteFile(l.cfgPath, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Shutdown leaves services in place, so clean up with prune once the
	// manager is gone, and drop persistent nodes by hand.
	t.Cleanup(func() {
		pctx, pcancel := context.WithTimeout(context.Background(), time.Minute)
		defer pcancel()
		if _, err := bridge.Prune(pctx, l.cfg, false); err != nil {
			t.Logf("prune: %v", err)
		}
		if o.persistent {
			for _, s := range []*side{src, dst} {
				devs, _ := s.client().Devices().List(pctx)
				for _, d := range devs {
					if strings.HasPrefix(d.Hostname, "tailnetlink-"+s.role+"-"+l.sfx) {
						_ = s.client().Devices().Delete(pctx, d.NodeID)
					}
				}
			}
		}
	})
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("tailnetlink log:\n%s", l.logOutput.String())
		}
	})
	l.run(t, ctx, o.webUI)
	return l
}

// run starts a manager (and the UI if asked) for the link's config.
func (l *link) run(t *testing.T, ctx context.Context, webUI bool) {
	t.Helper()
	mctx, cancel := context.WithCancel(ctx)
	l.cancel = cancel
	t.Cleanup(cancel)
	logger := slog.New(slog.NewTextHandler(l.logOutput, &slog.HandlerOptions{Level: slog.LevelDebug}))
	store := state.New()
	l.store = store
	if webUI {
		cs, err := config.NewStore(l.cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		srv := server.New(l.webAddr, store, cs, logger)
		go srv.Run(mctx) //nolint:errcheck // stops with the manager
	}
	mgr := bridge.New(store, logger, l.webAddr)
	l.mgr = mgr
	go mgr.Reconcile(mctx, l.cfg)
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer ccancel()
		_ = mgr.Close(cctx)
	})
}

// service returns the VIP service name in dst, or nil if it doesn't exist.
func (l *link) service(ctx context.Context, name string) *tsclient.VIPService {
	svc, err := l.dst.client().VIPServices().Get(ctx, name)
	if err != nil {
		return nil
	}
	return svc
}

func (l *link) waitService(t *testing.T, ctx context.Context, name string) netip.Addr {
	t.Helper()
	var vip netip.Addr
	waitFor(t, 3*time.Minute, "VIP service "+name+" in dst", func() bool {
		svc := l.service(ctx, name)
		if svc == nil {
			return false
		}
		for _, a := range svc.Addrs {
			if ip, err := netip.ParseAddr(a); err == nil && ip.Is4() {
				vip = ip
				return true
			}
		}
		return false
	})
	return vip
}

func (l *link) dialVIP(t *testing.T, ctx context.Context, vip netip.Addr, port int) net.Conn {
	t.Helper()
	var conn net.Conn
	waitFor(t, 3*time.Minute, fmt.Sprintf("dial %s:%d from the dst client", vip, port), func() bool {
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		c, err := l.client.srv.Dial(dctx, "tcp", netip.AddrPortFrom(vip, uint16(port)).String())
		if err != nil {
			return false
		}
		conn = c
		return true
	})
	t.Cleanup(func() { conn.Close() })
	return conn
}

func echo(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.WriteString(conn, msg+"\n"); err != nil {
		t.Fatal(err)
	}
	got, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if want := "echo: " + msg + "\n"; got != want {
		t.Fatalf("reply = %q, want %q", got, want)
	}
}

// TestRealTrafficAcrossBorder: a client in dst reaches a backend in src
// through the VIP service tailnetlink creates, and the backend sees the
// source-side tailnetlink node, not the client.
func TestRealTrafficAcrossBorder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	l := startLink(t, ctx, linkOpts{})

	// Different tailnets: no direct path from client to backend.
	dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
	if c, err := l.client.srv.Dial(dctx, "tcp", netip.AddrPortFrom(l.backend.ip, uint16(l.echoPort)).String()); err == nil {
		c.Close()
		t.Fatal("client reached the backend directly; the tailnets are not isolated")
	}
	dcancel()

	vip := l.waitService(t, ctx, l.svc)
	conn := l.dialVIP(t, ctx, vip, l.echoPort)
	echo(t, conn, "hello across the border "+l.sfx)

	select {
	case p := <-l.peers:
		if strings.HasPrefix(p, l.client.ip.String()+":") {
			t.Errorf("backend saw the dst client %s directly", p)
		}
		host, _, _ := net.SplitHostPort(p)
		devs, err := l.src.client().Devices().List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, d := range devs {
			if strings.HasPrefix(d.Hostname, "tailnetlink-src-"+l.sfx) {
				for _, a := range d.Addresses {
					found = found || a == host
				}
			}
		}
		if !found {
			t.Errorf("backend peer %s is not the source tailnetlink node", p)
		}
	case <-time.After(10 * time.Second):
		t.Error("backend never saw a connection")
	}
}

// bridgeError waits for the link's bridge to report an error and returns it.
func (l *link) bridgeError(t *testing.T) string {
	t.Helper()
	var msg string
	waitFor(t, 3*time.Minute, "bridge error", func() bool {
		for _, b := range l.store.GetBridges() {
			if b.Status == state.BridgeStatusError {
				msg = b.Error
				return true
			}
		}
		return false
	})
	return msg
}

func sameService(a, b *tsclient.VIPService) bool {
	return a.Name == b.Name && a.Comment == b.Comment && slices.Equal(a.Ports, b.Ports) &&
		slices.Equal(a.Tags, b.Tags) && slices.Equal(a.Addrs, b.Addrs) && maps.Equal(a.Annotations, b.Annotations)
}

// TestRealLeavesForeignServiceAlone (problem 1, fixed by PR 4): a VIP
// service someone else made is left byte-for-byte unchanged when a rule uses
// the same short name, and the rule reports a name conflict.
func TestRealLeavesForeignServiceAlone(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	_, dst := tailnets(t)
	short := "e2e-api-" + suffix(t)
	if err := dst.client().VIPServices().CreateOrUpdate(ctx, tsclient.VIPService{
		Name:        "svc:" + short,
		Comment:     "hand-made, not tailnetlink",
		Ports:       []string{"tcp:9999"},
		Annotations: map[string]string{"owner": "someone-else"},
	}); err != nil {
		t.Fatalf("create foreign service: %v", err)
	}
	t.Cleanup(func() { _ = dst.client().VIPServices().Delete(context.Background(), "svc:"+short) })
	before, err := dst.client().VIPServices().Get(ctx, "svc:"+short)
	if err != nil {
		t.Fatal(err)
	}

	l := startLink(t, ctx, linkOpts{shortName: short})
	if msg := l.bridgeError(t); !strings.HasPrefix(msg, "name conflict") {
		t.Errorf("bridge error = %q, want a name conflict", msg)
	}
	l.stop(t)
	time.Sleep(10 * time.Second)
	after := l.service(ctx, "svc:"+short)
	if after == nil || !sameService(before, after) {
		t.Errorf("foreign service changed:\n before %+v\n after  %+v", before, after)
	}
}

// TestRealInstancesDoNotTouchEachOther: two instances with different
// instance ids on the same pair of tailnets each own only their own
// services, and one removing its link leaves the other's alone.
func TestRealInstancesDoNotTouchEachOther(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	a := startLink(t, ctx, linkOpts{})
	b := startLink(t, ctx, linkOpts{})
	a.waitService(t, ctx, a.svc)
	b.waitService(t, ctx, b.svc)
	if got := a.service(ctx, a.svc).Annotations["tailnetlink/owner"]; got != a.cfg.InstanceID {
		t.Errorf("%s owner = %q, want %q", a.svc, got, a.cfg.InstanceID)
	}
	if got := b.service(ctx, b.svc).Annotations["tailnetlink/owner"]; got != b.cfg.InstanceID {
		t.Errorf("%s owner = %q, want %q", b.svc, got, b.cfg.InstanceID)
	}
	before := a.service(ctx, a.svc)

	next := *b.cfg
	next.Bridges = nil
	b.mgr.Reconcile(ctx, &next)
	waitFor(t, 2*time.Minute, b.svc+" removed with its link", func() bool {
		return b.service(ctx, b.svc) == nil
	})
	if after := a.service(ctx, a.svc); after == nil || !sameService(before, after) {
		t.Errorf("%s changed when the other instance removed its link: %+v", a.svc, after)
	}
}

// TestRealShutdownKeepsServices (problem 2, fixed by PR 6): stopping
// tailnetlink leaves its VIP service in place, unchanged.
func TestRealShutdownKeepsServices(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	l := startLink(t, ctx, linkOpts{})
	l.waitService(t, ctx, l.svc)
	before := l.service(ctx, l.svc)

	l.stop(t)
	time.Sleep(10 * time.Second)
	if after := l.service(ctx, l.svc); after == nil || !sameService(before, after) {
		t.Errorf("service changed on shutdown:\n before %+v\n after  %+v", before, after)
	}
}

// TestRealRestartReusesNode: with persistent nodes, a restart comes back as
// the same devices with the same VIP, and traffic flows again.
func TestRealRestartReusesNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	l := startLink(t, ctx, linkOpts{persistent: true})
	vip := l.waitService(t, ctx, l.svc)
	echo(t, l.dialVIP(t, ctx, vip, l.echoPort), "before restart "+l.sfx)

	devices := func() []string {
		var ids []string
		for _, s := range []*side{l.src, l.dst} {
			devs, err := s.client().Devices().List(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range devs {
				if strings.HasPrefix(d.Hostname, "tailnetlink-"+s.role+"-"+l.sfx) {
					ids = append(ids, d.NodeID)
				}
			}
		}
		slices.Sort(ids)
		return ids
	}
	before := devices()
	if len(before) != 2 {
		t.Fatalf("tailnetlink devices = %v, want one per tailnet", before)
	}

	l.stop(t)
	l.run(t, ctx, false)
	waitFor(t, 3*time.Minute, "bridge active after restart", func() bool {
		for _, b := range l.store.GetBridges() {
			if b.Status == state.BridgeStatusActive {
				return true
			}
		}
		return false
	})
	if got := l.waitService(t, ctx, l.svc); got != vip {
		t.Errorf("VIP changed across restart: %v -> %v", vip, got)
	}
	echo(t, l.dialVIP(t, ctx, vip, l.echoPort), "after restart "+l.sfx)
	if after := devices(); !slices.Equal(after, before) {
		t.Errorf("devices changed across restart: %v -> %v", before, after)
	}
}

// TestRealNoSecretsOverHTTP (problem 4, fixed by PR 7): neither the local
// UI nor svc:tailnetlink reached from a client in dst hands out an OAuth
// client secret, in any route, the SSE stream or a CORS header.
func TestRealNoSecretsOverHTTP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	l := startLink(t, ctx, linkOpts{webUI: true})

	vip := l.waitService(t, ctx, "svc:tailnetlink")
	viaVIP := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return l.client.srv.Dial(ctx, "tcp", netip.AddrPortFrom(vip, 80).String())
		}},
	}
	for where, c := range map[string]struct {
		hc   *http.Client
		base string
	}{
		"local": {&http.Client{Timeout: 30 * time.Second}, "http://" + l.webAddr},
		"vip":   {viaVIP, "http://tailnetlink"},
	} {
		var all strings.Builder
		waitFor(t, 3*time.Minute, where+" UI reachable", func() bool {
			resp, err := c.hc.Get(c.base + "/api/status")
			if err != nil {
				return false
			}
			resp.Body.Close()
			return resp.StatusCode == http.StatusOK
		})
		for _, p := range []string{"/", "/api/status", "/api/bridges", "/api/connections", "/api/logs", "/api/config",
			"/api/tailnets/src-" + l.sfx + "/devices", "/api/tailnets/dst-" + l.sfx + "/services"} {
			resp, err := c.hc.Get(c.base + p)
			if err != nil {
				t.Errorf("%s GET %s: %v", where, p, err)
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			_ = resp.Header.Write(&all)
			all.Write(body)
			if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "" {
				t.Errorf("%s GET %s: Access-Control-Allow-Origin = %q", where, p, v)
			}
		}
		sctx, scancel := context.WithTimeout(ctx, 2*time.Second)
		req, _ := http.NewRequestWithContext(sctx, http.MethodGet, c.base+"/api/events", nil)
		if resp, err := c.hc.Do(req); err == nil {
			sse, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			all.Write(sse)
		}
		scancel()
		for _, sec := range l.secrets {
			for _, form := range []string{sec, base64.StdEncoding.EncodeToString([]byte(sec)), base64.URLEncoding.EncodeToString([]byte(sec))} {
				if strings.Contains(all.String(), form) {
					t.Errorf("%s: an OAuth client secret leaked over HTTP", where)
				}
			}
		}
		if !strings.Contains(all.String(), "client_secret_file") {
			t.Errorf("%s: no config served", where)
		}
	}
}
