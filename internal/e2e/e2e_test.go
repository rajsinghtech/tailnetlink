// Package e2e runs tailnetlink code against real tsnet nodes on in-process
// control servers (tailscale.com/tstest/integration/testcontrol). Each
// testcontrol instance is its own tailnet, so two of them give us a real
// border to forward across. No Tailscale account or secrets are needed.
package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/bridge"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
)

type tailnet struct {
	control *testcontrol.Server
	url     string
}

func newTailnet(t *testing.T, domain string) *tailnet {
	t.Helper()
	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	c := &testcontrol.Server{
		DERPMap:        derpMap,
		DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
		MagicDNSDomain: domain,
		Logf:           logger.Discard,
	}
	c.HTTPTestServer = httptest.NewUnstartedServer(c)
	c.HTTPTestServer.Start()
	t.Cleanup(c.HTTPTestServer.Close)
	return &tailnet{control: c, url: c.HTTPTestServer.URL}
}

type node struct {
	srv *tsnet.Server
	ip  netip.Addr
	key key.NodePublic
}

func (tn *tailnet) node(t *testing.T, ctx context.Context, hostname string) node {
	t.Helper()
	s := &tsnet.Server{
		Dir:        t.TempDir(),
		ControlURL: tn.url,
		Hostname:   hostname,
		Store:      new(mem.Store),
		Ephemeral:  true,
		Logf:       logger.Discard,
	}
	t.Cleanup(func() { s.Close() })
	st, err := s.Up(ctx)
	if err != nil {
		t.Fatalf("%s up: %v", hostname, err)
	}
	return node{srv: s, ip: st.TailscaleIPs[0], key: st.Self.PublicKey}
}

// makeServiceHost does on testcontrol what the real control plane does when
// a tagged node advertises a VIP service the admin API knows about: give
// the node the service-host capability, let it route the VIP, and tag it.
func (tn *tailnet) makeServiceHost(t *testing.T, ctx context.Context, n node, svc tailcfg.ServiceName, vip netip.Addr, tag string) {
	t.Helper()
	caps := map[tailcfg.ServiceName]views.Slice[netip.Addr]{svc: views.SliceOf([]netip.Addr{vip})}
	j, err := json.Marshal(caps)
	if err != nil {
		t.Fatal(err)
	}
	cur := tn.control.Node(n.key)
	cm := maps.Clone(cur.CapMap)
	if cm == nil {
		cm = tailcfg.NodeCapMap{}
	}
	cm[tailcfg.NodeAttrServiceHost] = []tailcfg.RawMessage{tailcfg.RawMessage(j)}
	tn.control.SetNodeCapMap(n.key, cm)
	tn.control.SetSubnetRoutes(n.key, []netip.Prefix{netip.PrefixFrom(vip, 32)})
	cur = tn.control.Node(n.key)
	cur.Tags = append(cur.Tags, tag)
	tn.control.UpdateNode(cur)

	lc, err := n.srv.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, 20*time.Second, "service host netmap", func() bool {
		st, err := lc.Status(ctx)
		if err != nil || st.Self == nil || st.Self.Tags == nil || st.Self.Tags.Len() == 0 {
			return false
		}
		_, ok := st.Self.CapMap[tailcfg.NodeAttrServiceHost]
		return ok
	})
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
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// serveEcho answers each line with "echo: <line>" and reports the remote
// address of every connection it accepts.
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

func TestTrafficCrossesBorder(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: starts real tsnet nodes")
	}
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	src := newTailnet(t, "src.ts.net")
	dest := newTailnet(t, "dest.ts.net")

	backend := src.node(t, ctx, "backend")
	linkSrc := src.node(t, ctx, "tailnetlink-src")
	linkDest := dest.node(t, ctx, "tailnetlink-dest")
	client := dest.node(t, ctx, "client")

	// The backend only exists in the source tailnet.
	ln, err := backend.srv.Listen("tcp", ":8080")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	peers := make(chan string, 8)
	go serveEcho(ln, peers)

	const svcName = "svc:tnl-src-backend"
	vip := netip.MustParseAddr("100.11.22.33")
	dest.makeServiceHost(t, ctx, linkDest, svcName, vip, "tag:tailnetlink")
	acceptRoutes(t, ctx, client)

	// Before the bridge exists, the client cannot reach the backend: they
	// are on different control planes.
	dctx, dcancel := context.WithTimeout(ctx, 2*time.Second)
	if c, err := client.srv.Dial(dctx, "tcp", netip.AddrPortFrom(backend.ip, 8080).String()); err == nil {
		c.Close()
		t.Fatal("client reached the source backend directly; tailnets are not isolated")
	}
	dcancel()

	store := state.New()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	fwd := bridge.NewForwarder(linkDest.srv, linkSrc.srv, &bridge.VIPService{
		ServiceName: svcName,
		SourceFQDN:  "backend.src.ts.net",
		SourceIP:    backend.ip,
		VIP:         vip,
		Ports:       []int{8080},
	}, "e2e/dest/backend", 5*time.Second, store, logger)
	if err := fwd.Start(ctx); err != nil {
		t.Fatalf("forwarder start: %v", err)
	}
	defer fwd.Stop()

	var conn net.Conn
	waitFor(t, 30*time.Second, "dial VIP from dest client", func() bool {
		c, err := client.srv.Dial(ctx, "tcp", netip.AddrPortFrom(vip, 8080).String())
		if err != nil {
			return false
		}
		conn = c
		return true
	})
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	r := bufio.NewReader(conn)
	for _, msg := range []string{"hello", "across the border"} {
		if _, err := io.WriteString(conn, msg+"\n"); err != nil {
			t.Fatal(err)
		}
		got, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read reply: %v", err)
		}
		if want := "echo: " + msg + "\n"; got != want {
			t.Fatalf("reply = %q, want %q", got, want)
		}
	}

	// The backend saw the connection come from the source-side tailnetlink
	// node, not from the client.
	select {
	case p := <-peers:
		if !strings.HasPrefix(p, linkSrc.ip.String()+":") {
			t.Errorf("backend saw peer %s, want the source tailnetlink node %s", p, linkSrc.ip)
		}
	case <-time.After(5 * time.Second):
		t.Error("backend never saw a connection")
	}

	// The forwarder resolved the real client through the PROXY header and
	// WhoIs on the destination side.
	waitFor(t, 5*time.Second, "connection recorded", func() bool {
		for _, c := range store.GetConns() {
			if c.NodeName == "client" && strings.HasPrefix(c.ClientAddr, client.ip.String()+":") {
				return true
			}
		}
		return false
	})
}
