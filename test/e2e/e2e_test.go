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
	pair     [3]*side // src, dst, dst2
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

// ensureTailnets sets up the shared throwaway tailnets once, or skips.
func ensureTailnets(t *testing.T) {
	t.Helper()
	if os.Getenv("TS_API_ACCESS_TOKEN") == "" {
		t.Skip("TS_API_ACCESS_TOKEN not set; skipping real-tailnet e2e")
	}
	pairOnce.Do(func() {
		api = tailnet.New(os.Getenv("TS_API_BASE"), tailnet.StaticToken(os.Getenv("TS_API_ACCESS_TOKEN")))
		roles := []struct{ env, role string }{{"SRC", "src"}, {"DST", "dst"}, {"DST2", "dst2"}}
		if os.Getenv("E2E_SRC_ID") != "" {
			for i, r := range roles {
				pair[i], pairErr = fromEnv(r.env, r.role)
				if pairErr != nil {
					return
				}
			}
			return
		}
		for i, r := range roles {
			pair[i], pairErr = createLocal(r.role)
			if pairErr != nil {
				return
			}
		}
	})
	if pairErr != nil {
		t.Fatalf("test tailnets: %v", pairErr)
	}
}

// tailnets returns the shared src and dst tailnets, or skips the test.
func tailnets(t *testing.T) (src, dst *side) {
	t.Helper()
	ensureTailnets(t)
	return pair[0], pair[1]
}

// threeTailnets returns src, dst and dst2, or skips.
func threeTailnets(t *testing.T) (src, dst, dst2 *side) {
	t.Helper()
	ensureTailnets(t)
	if pair[2] == nil {
		t.Fatal("dst2 was not created; the e2e-real workflow needs --roles src,dst,dst2")
	}
	return pair[0], pair[1], pair[2]
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
	linkName   string // bridge rule name; default "echo"
	authz      config.AuthzConfig
	// creds, when set, supplies the oauth block for a side instead of
	// creating an OAuth client in that tailnet.
	creds func(t *testing.T, s *side) config.OAuthCreds
}

// startLink joins a backend in src and a client in dst, gives tailnetlink a
// fresh least-privilege OAuth client in each tailnet, and starts the manager.
func startLink(t *testing.T, ctx context.Context, o linkOpts) *link {
	t.Helper()
	src, dst := tailnets(t)
	return startBorder(t, ctx, src, dst, o)
}

// startBorder is startLink for an explicit pair of sides. Two borders that
// share a source use the same src side with different destinations.
func startBorder(t *testing.T, ctx context.Context, src, dst *side, o linkOpts) *link {
	t.Helper()
	l := &link{sfx: suffix(t), src: src, dst: dst, echoPort: 7000, peers: make(chan string, 16), logOutput: &strings.Builder{}}
	if o.shortName == "" {
		o.shortName = "e2e-echo-" + l.sfx
	}
	if o.linkName == "" {
		o.linkName = "echo"
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

	// tailnetlink gets secrets and JWTs only through 0600 files.
	creds := map[string]config.OAuthCreds{}
	if o.creds != nil {
		for _, s := range []*side{src, dst} {
			creds[s.role] = o.creds(t, s)
		}
	} else {
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
	}
	name := "e2e-" + l.sfx
	stateDir := t.TempDir()
	poll, dial := config.Duration{Duration: 5 * time.Second}, config.Duration{Duration: 10 * time.Second}
	bd := &config.File{
		Name:      name,
		StateDir:  stateDir,
		Ephemeral: !o.persistent,
		Tailnets: map[string]config.TailnetSpec{
			"src": {Auth: creds[src.role], Tags: []string{linkTag}, Tailnet: src.id, Node: config.NodeSpec{Hostname: "tailnetlink-e2e-" + l.sfx + "-src"}},
			"dst": {Auth: creds[dst.role], Tags: []string{linkTag}, Tailnet: dst.id, Node: config.NodeSpec{Hostname: "tailnetlink-e2e-" + l.sfx + "-dst"}},
		},
		Targets: map[string]config.TargetSpec{
			o.linkName: {In: "src", Device: l.backend.fqdn, Ports: config.LocalPortList(l.echoPort)},
		},
		Exports: []config.ExportSpec{{
			Target: o.linkName, To: []string{"dst"}, Name: o.shortName, Authz: o.authz,
		}},
		PollInterval: &poll,
		DialTimeout:  &dial,
	}
	if o.webUI {
		pl, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		l.webAddr = pl.Addr().String()
		pl.Close()
		bd.UI.ListenAddr = l.webAddr
		l.cfgPath = filepath.Join(t.TempDir(), "tailnetlink.json")
		data, _ := json.Marshal(bd)
		if err := os.WriteFile(l.cfgPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := bd.Compile()
	if err != nil {
		t.Fatal(err)
	}
	l.cfg = cfg

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
					if strings.HasPrefix(d.Hostname, "tailnetlink-e2e-"+l.sfx+"-"+s.role) {
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
	var ui http.Handler
	if webUI {
		cs, err := config.NewStore(l.cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		srv := server.New(l.webAddr, store, cs.Get, logger)
		ui = srv.Handler()
		go srv.Run(mctx) //nolint:errcheck // stops with the manager
	}
	mgr := bridge.New(store, logger, ui)
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

// TestRealWorkloadIdentity runs one border with client_id and id_token_file
// on both sides. The federated identity is the one the workflow already
// created in each tailnet. This test only writes a GitHub Actions OIDC token
// (audience from that identity) to a file and checks that tailnetlink can
// mint node auth keys and serve traffic through the API token it exchanges.
func TestRealWorkloadIdentity(t *testing.T) {
	oidc, ok := tailnet.GitHubOIDCFromEnv(os.Getenv)
	if !ok || os.Getenv("E2E_SRC_FED_CLIENT_ID") == "" || os.Getenv("E2E_DST_FED_CLIENT_ID") == "" {
		t.Skip("needs GitHub Actions OIDC and the workflow's per-tailnet federated identity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	src, dst := tailnets(t)
	dir := t.TempDir()
	write := func(ctx context.Context, s *side) error {
		id := os.Getenv("E2E_" + strings.ToUpper(s.role) + "_FED_CLIENT_ID")
		aud := os.Getenv("E2E_" + strings.ToUpper(s.role) + "_FED_AUDIENCE")
		if aud == "" {
			aud = tailnet.AudienceFor(id)
		}
		jwt, err := oidc.JWT(ctx, aud)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, s.role+"-id-token"), []byte(jwt), 0o600)
	}
	l := startBorder(t, ctx, src, dst, linkOpts{
		creds: func(t *testing.T, s *side) config.OAuthCreds {
			t.Helper()
			if err := write(ctx, s); err != nil {
				t.Fatal(err)
			}
			return config.OAuthCreds{
				ClientID:    os.Getenv("E2E_" + strings.ToUpper(s.role) + "_FED_CLIENT_ID"),
				IDTokenFile: filepath.Join(dir, s.role+"-id-token"),
			}
		},
	})
	// GitHub's OIDC tokens are short. Refresh the files before prune, which
	// exchanges again from the same paths. Registered last so it runs first.
	t.Cleanup(func() {
		rctx, rcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer rcancel()
		for _, s := range []*side{src, dst} {
			if err := write(rctx, s); err != nil {
				t.Logf("refresh id token for %s: %v", s.role, err)
			}
		}
	})
	vip := l.waitService(t, ctx, l.svc)
	echo(t, l.dialVIP(t, ctx, vip, l.echoPort), "wif "+l.sfx)
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
			if strings.HasPrefix(d.Hostname, "tailnetlink-e2e-"+l.sfx+"-src") {
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
// Two borders sharing one source across three real throwaway tailnets.
// Each only owns its destination; killing one leaves the other working.
func TestRealTwoBorders(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	src, dst, dst2 := threeTailnets(t)
	ab := startBorder(t, ctx, src, dst, linkOpts{shortName: "echo-ab-" + suffix(t)})
	ac := startBorder(t, ctx, src, dst2, linkOpts{shortName: "echo-ac-" + suffix(t)})
	vipB := ab.waitService(t, ctx, ab.svc)
	vipC := ac.waitService(t, ctx, ac.svc)
	echo(t, ab.dialVIP(t, ctx, vipB, ab.echoPort), "to B")
	echo(t, ac.dialVIP(t, ctx, vipC, ac.echoPort), "to C")

	if got := ab.service(ctx, ab.svc).Annotations["tailnetlink/owner"]; got != ab.cfg.InstanceID {
		t.Errorf("B owner = %q", got)
	}
	if got := ac.service(ctx, ac.svc).Annotations["tailnetlink/owner"]; got != ac.cfg.InstanceID {
		t.Errorf("C owner = %q", got)
	}
	ab.stop(t)
	echo(t, ac.dialVIP(t, ctx, vipC, ac.echoPort), "C after B stopped")
	if after := ab.service(ctx, ab.svc); after == nil {
		t.Error("stopping A-to-B deleted its service")
	}
}

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
				if strings.HasPrefix(d.Hostname, "tailnetlink-e2e-"+l.sfx+"-"+s.role) {
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

// TestRealReadOnlyUI (problems 4 and 5, fixed by PRs 7 and 9): the
// read-only UI is reachable locally and through svc:tailnetlink from a
// client in each tailnet. Every read route works, the old config and write
// routes are gone, every write is refused, and nothing served carries an
// OAuth client secret, a client ID or a secret file path, in any route,
// the SSE stream or a header.
func TestRealReadOnlyUI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	l := startLink(t, ctx, linkOpts{webUI: true})
	srcClient := join(t, ctx, l.src, "e2e-srcclient-"+l.sfx, "tag:e2e-client")
	acceptRoutes(t, ctx, srcClient)

	via := func(n node, vip netip.Addr) *http.Client {
		return &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return n.srv.Dial(ctx, "tcp", netip.AddrPortFrom(vip, 80).String())
			}},
		}
	}
	dstVIP := l.waitService(t, ctx, "svc:tailnetlink")
	srcVIP := waitServiceIn(t, ctx, l.src, "svc:tailnetlink")

	private := append([]string{}, l.secrets...)
	for _, tc := range l.cfg.Tailnets {
		private = append(private, tc.OAuth.ClientID, tc.OAuth.ClientSecretFile)
	}
	read := []string{"/", "/api/status", "/api/bridges", "/api/connections", "/api/logs"}
	removed := []string{"/api/config", "/api/settings", "/api/tailnets", "/api/tailnets/detect",
		"/api/tailnets/e2e-" + l.sfx + "-src/devices", "/api/bridge-rules", "/api/bridge-rules/e2e-" + l.sfx}

	for where, c := range map[string]struct {
		hc   *http.Client
		base string
	}{
		"local":   {&http.Client{Timeout: 30 * time.Second}, "http://" + l.webAddr},
		"dst vip": {via(l.client, dstVIP), "http://tailnetlink"},
		"src vip": {via(srcClient, srcVIP), "http://tailnetlink"},
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
		get := func(p string, want int) {
			resp, err := c.hc.Get(c.base + p)
			if err != nil {
				t.Errorf("%s GET %s: %v", where, p, err)
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			_ = resp.Header.Write(&all)
			all.Write(body)
			if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "" {
				t.Errorf("%s GET %s: Access-Control-Allow-Origin = %q", where, p, v)
			}
			if resp.StatusCode != want {
				t.Errorf("%s GET %s = %d, want %d", where, p, resp.StatusCode, want)
			}
		}
		for _, p := range read {
			get(p, http.StatusOK)
		}
		for _, p := range removed {
			get(p, http.StatusNotFound)
		}
		for _, p := range append(append([]string{"/api/events"}, read...), removed...) {
			for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
				req, _ := http.NewRequestWithContext(ctx, m, c.base+p, strings.NewReader(`{"name":"x"}`))
				req.Header.Set("Content-Type", "application/json")
				resp, err := c.hc.Do(req)
				if err != nil {
					t.Errorf("%s %s %s: %v", where, m, p, err)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotFound {
					t.Errorf("%s %s %s = %d, want 405 or 404", where, m, p, resp.StatusCode)
				}
			}
		}
		sctx, scancel := context.WithTimeout(ctx, 3*time.Second)
		req, _ := http.NewRequestWithContext(sctx, http.MethodGet, c.base+"/api/events", nil)
		if resp, err := c.hc.Do(req); err == nil {
			sse, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			all.Write(sse)
		}
		scancel()
		for _, sec := range private {
			if sec == "" {
				continue
			}
			for _, form := range []string{sec, base64.StdEncoding.EncodeToString([]byte(sec)), base64.URLEncoding.EncodeToString([]byte(sec))} {
				if strings.Contains(all.String(), form) {
					t.Errorf("%s: a secret, client ID or secret path leaked over HTTP", where)
				}
			}
		}
		if !strings.Contains(all.String(), "event: init") {
			t.Errorf("%s: no SSE init event", where)
		}
	}
	if svc := l.service(ctx, l.svc); svc == nil || len(svc.Ports) != 1 {
		t.Errorf("bridged service changed: %+v", svc)
	}
}

// waitServiceIn waits for a VIP service with an address in s.
func waitServiceIn(t *testing.T, ctx context.Context, s *side, name string) netip.Addr {
	t.Helper()
	var vip netip.Addr
	waitFor(t, 3*time.Minute, name+" in "+s.role, func() bool {
		svc, err := s.client().VIPServices().Get(ctx, name)
		if err != nil {
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

// TestRealAuthz: destination policy grants the app capability for export
// name echo-ok only. require_cap allows that export and denies another name.
func TestRealAuthz(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	src, dst := tailnets(t)

	ok := startBorder(t, ctx, src, dst, linkOpts{
		shortName: "echo-ok",
		linkName:  "echo-ok",
		authz:     config.AuthzConfig{Mode: config.AuthzRequireCap},
	})
	vip := ok.waitService(t, ctx, ok.svc)
	echo(t, ok.dialVIP(t, ctx, vip, ok.echoPort), "cap-ok")
	select {
	case <-ok.peers:
	case <-time.After(5 * time.Second):
		t.Fatal("backend never saw the allowed connection")
	}

	deny := startBorder(t, ctx, src, dst, linkOpts{
		shortName: "echo-no",
		linkName:  "echo-no",
		authz:     config.AuthzConfig{Mode: config.AuthzRequireCap},
	})
	dvip := deny.waitService(t, ctx, deny.svc)
	dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
	defer dcancel()
	conn, err := deny.client.srv.Dial(dctx, "tcp", netip.AddrPortFrom(dvip, uint16(deny.echoPort)).String())
	if err == nil {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.WriteString(conn, "cap-no\n")
		_, rerr := bufio.NewReader(conn).ReadString('\n')
		conn.Close()
		if rerr == nil {
			t.Fatal("echo succeeded without a grant for echo-no")
		}
	}
	select {
	case p := <-deny.peers:
		t.Fatalf("backend saw a denied connection from %s", p)
	case <-time.After(500 * time.Millisecond):
	}
}
