package bridge

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rajsinghtech/tailnetlink/internal/config"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

func TestMinimalCoverPicksOnlyTheMatchingPrefix(t *testing.T) {
	peer := key.NewNode().Public()
	other := key.NewNode().Public()
	routes := []advertised{
		{peer, netip.MustParsePrefix("10.20.0.0/24")},
		{peer, netip.MustParsePrefix("10.99.0.0/24")},
		{other, netip.MustParsePrefix("10.0.0.0/8")},
	}
	p, owner, ok := minimalCover(routes, netip.MustParseAddr("10.20.0.10"))
	if !ok || p != netip.MustParsePrefix("10.20.0.0/24") || owner != peer {
		t.Fatalf("cover = %s %s %v", p, owner, ok)
	}
	if _, _, ok := minimalCover(routes, netip.MustParseAddr("100.64.0.1")); ok {
		t.Fatal("a tailscale IP must not take a subnet route")
	}
	if _, _, ok := minimalCover(routes, netip.MustParseAddr("192.0.2.1")); ok {
		t.Fatal("uncovered address matched a route")
	}
	if tailscaleRoute(netip.MustParsePrefix("10.20.0.0/24")) {
		t.Fatal("subnet prefix classified as a tailscale route")
	}
	if !tailscaleRoute(netip.MustParsePrefix("100.64.0.1/32")) || tailscaleRoute(netip.Prefix{}) {
		t.Fatal("tailscale single IP classification")
	}
}

func TestSplitDNSAndMagicLookup(t *testing.T) {
	nm := &netmap.NetworkMap{DNS: tailcfg.DNSConfig{Routes: map[string][]*dnstype.Resolver{
		"internal.example.com": {{Addr: "100.64.0.8:53"}, {Addr: ""}},
		"example.com":          {{Addr: "10.20.0.53"}},
	}}}
	got := splitResolverIPs(nm, "app.internal.example.com.")
	if len(got) != 1 || got[0] != netip.MustParseAddr("100.64.0.8") {
		t.Fatalf("resolvers = %v", got)
	}
	if splitResolverIPs(nil, "x") != nil || splitResolverIPs(nm, "other.test") != nil {
		t.Fatal("unmatched name returned resolvers")
	}
	peer := (&tailcfg.Node{
		Name:      "app.src.ts.net.",
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.5/32")},
	}).View()
	nm.Peers = []tailcfg.NodeView{peer}
	ip, ok := magicDNSAddr(nm, "APP.SRC.TS.NET")
	if !ok || ip != netip.MustParseAddr("100.64.0.5") {
		t.Fatalf("magic = %s %v", ip, ok)
	}
	if _, ok := magicDNSAddr(nm, "missing.ts.net"); ok {
		t.Fatal("unknown name matched magic DNS")
	}
}

func TestResolveUsesTailnetDNSNotThePod(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var nbuf [2]byte
		if _, err := io.ReadFull(c, nbuf[:]); err != nil {
			return
		}
		raw := make([]byte, int(binary.BigEndian.Uint16(nbuf[:])))
		if _, err := io.ReadFull(c, raw); err != nil {
			return
		}
		var req dns.Msg
		if err := req.Unpack(raw); err != nil {
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(&req)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5},
			A:   net.ParseIP("100.64.0.9"),
		})
		out, _ := resp.Pack()
		var lenb [2]byte
		binary.BigEndian.PutUint16(lenb[:], uint16(len(out)))
		_, _ = c.Write(append(lenb[:], out...))
	}()

	orig := tailnetDial
	t.Cleanup(func() { tailnetDial = orig })
	tailnetDial = func(ctx context.Context, srv *tsnet.Server, network, addr string) (net.Conn, error) {
		if !strings.HasSuffix(addr, ":53") {
			return nil, errors.New("unexpected dial " + addr)
		}
		return net.Dial(network, ln.Addr().String())
	}
	nm := &netmap.NetworkMap{DNS: tailcfg.DNSConfig{Routes: map[string][]*dnstype.Resolver{
		"internal.example.com": {{Addr: "100.64.0.8"}},
	}}}
	m := &Manager{scopes: map[string]*nodeScope{"src": {nm: nm}}}
	ip, err := m.resolveTailnetHost(context.Background(), "src", nil, "app.internal.example.com")
	if err != nil || ip != netip.MustParseAddr("100.64.0.9") {
		t.Fatalf("resolve = %s %v", ip, err)
	}
	if _, err := m.resolveTailnetHost(context.Background(), "src", nil, "10.1.2.3"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.resolveTailnetHost(context.Background(), "src", nil, "missing.example"); err == nil {
		t.Fatal("unknown name resolved")
	}
	if err := m.scopes["src"].cover(context.Background(), netip.MustParseAddr("10.20.0.10")); err == nil {
		t.Fatal("subnet address with no advertisement was accepted")
	}
	if _, err := queryA(context.Background(), nil, netip.MustParseAddr("100.64.0.8"), "no.question"); err == nil {
		// The stub still answers an A record for any question. Force a failure
		// by closing the listener and dialing again.
	}
	ln.Close()
	if _, err := queryA(context.Background(), nil, netip.MustParseAddr("100.64.0.8"), "app.internal.example.com"); err == nil {
		t.Fatal("query against a closed nameserver worked")
	}
}

func TestScopedAllowedIPsAndRouter(t *testing.T) {
	peer := key.NewNode().Public()
	other := key.NewNode().Public()
	cfg := &wgcfg.Config{Peers: []wgcfg.Peer{
		{PublicKey: peer, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32"), netip.MustParsePrefix("10.99.0.0/24")}},
		{PublicKey: other, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")}},
	}}
	want := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	owners := map[netip.Prefix]key.NodePublic{want[0]: peer}
	got := scopeAllowedIPs(cfg, want, owners)
	if p := subnetPrefixes(got); len(p) != 1 || p[0] != want[0] {
		t.Fatalf("installed = %v", p)
	}
	for _, aip := range got.Peers[0].AllowedIPs {
		if aip == netip.MustParsePrefix("10.99.0.0/24") {
			t.Fatal("unrelated prefix kept")
		}
	}
	rc := scopeRouter(nil, got, want)
	if !prefixContains(rc.Routes, netip.MustParseAddr("10.20.0.5")) {
		t.Fatalf("router routes = %v", rc.Routes)
	}
	if scopeAllowedIPs(nil, nil, nil) == nil || subnetPrefixes(nil) != nil {
		t.Fatal("nil config")
	}
	again := scopeRouter(&router.Config{Routes: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32"), netip.MustParsePrefix("10.99.0.0/24")}}, got, nil)
	if prefixContains(again.Routes, netip.MustParseAddr("10.99.0.1")) {
		t.Fatal("withdraw left 10.99 installed")
	}
}

func TestDialSourceRefusesUnacceptedPrefix(t *testing.T) {
	m := &Manager{}
	if _, err := m.DialSource(context.Background(), "src", "10.20.0.1:80"); err == nil {
		t.Fatal("missing node dialed")
	}
	if _, err := m.DialSource(context.Background(), "src", "not-an-addr"); err == nil {
		t.Fatal("bad address dialed")
	}
	m.servers = map[string]*tsnet.Server{"src": {}}
	m.scopes = map[string]*nodeScope{"src": {applied: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}}}
	if _, err := m.DialSource(context.Background(), "src", "10.99.0.9:8080"); err == nil || !errors.Is(err, errNoSubnetRoute) {
		t.Fatalf("unaccepted prefix err = %v", err)
	}
	orig := tailnetDial
	t.Cleanup(func() { tailnetDial = orig })
	tailnetDial = func(context.Context, *tsnet.Server, string, string) (net.Conn, error) {
		c, _ := net.Pipe()
		return c, nil
	}
	c, err := m.DialSource(context.Background(), "src", "100.64.0.5:80")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if m.AcceptedRoutes("missing") != nil {
		t.Fatal("unknown tailnet has routes")
	}
	if userspaceValue(nil).IsValid() {
		t.Fatal("nil engine looked like userspace")
	}
	if installSubnetRoutes(nil, nil, nil) == nil {
		t.Fatal("nil server installed routes")
	}
	_ = time.Second
}

func TestCoverAndSyncEdgeCases(t *testing.T) {
	if _, err := tailnetDial(context.Background(), nil, "tcp", "10.20.0.10:80"); err == nil {
		t.Fatal("nil node dialed")
	}
	p20 := netip.MustParsePrefix("10.20.0.0/24")
	p99 := netip.MustParsePrefix("10.99.0.0/24")
	routerKey := key.NewNode().Public()
	routerPeer := (&tailcfg.Node{
		Name:          "router.src.ts.net.",
		Key:           routerKey,
		PrimaryRoutes: []netip.Prefix{p20, p99},
		Addresses:     []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
	}).View()
	magic := (&tailcfg.Node{
		Name:      "app.src.ts.net.",
		Key:       key.NewNode().Public(),
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.5/32")},
	}).View()
	nm := &netmap.NetworkMap{
		Peers: []tailcfg.NodeView{routerPeer, magic},
		DNS: tailcfg.DNSConfig{Routes: map[string][]*dnstype.Resolver{
			"internal.example.com": {{Addr: "10.20.0.53"}},
			"example.com":          {{Addr: "10.99.0.53"}},
		}},
	}
	// Map iteration order is random; repeat so the shorter suffix is seen
	// after the longer one at least once.
	for range 32 {
		got := splitResolverIPs(nm, "app.internal.example.com")
		if len(got) != 1 || got[0] != netip.MustParseAddr("10.20.0.53") {
			t.Fatalf("resolvers = %v", got)
		}
	}
	if advertisedRoutes(nil) != nil {
		t.Fatal("nil netmap advertised routes")
	}

	sc := &nodeScope{nm: nm, applied: []netip.Prefix{p20, netip.MustParsePrefix("192.0.2.0/24")}}
	if err := sc.cover(context.Background(), netip.MustParseAddr("100.64.0.2")); err != nil {
		t.Fatal(err)
	}
	if err := sc.cover(context.Background(), netip.MustParseAddr("10.20.0.10")); err != nil {
		t.Fatal(err)
	}
	// A new prefix has to be installed. The node is not running, and the
	// prefix already applied still needs its owner filled in.
	sc.applied = []netip.Prefix{p99}
	if err := sc.cover(context.Background(), netip.MustParseAddr("10.20.0.10")); err == nil {
		t.Fatal("cover installed routes on a stopped node")
	}
	bare := &nodeScope{}
	if err := bare.cover(context.Background(), netip.MustParseAddr("10.20.0.10")); err == nil {
		t.Fatal("cover without a netmap")
	}
	if err := bare.apply(context.Background()); err != nil {
		t.Fatalf("untouched apply: %v", err)
	}
	bare.touched = true
	if err := bare.apply(context.Background()); err == nil {
		t.Fatal("withdraw on a stopped node")
	}
	bare.nm = nm
	bare.want = []string{"10.20.0.10", "192.0.2.9", "app.internal.example.com"}
	if err := bare.apply(context.Background()); err == nil {
		t.Fatal("apply on a stopped node")
	}
	want, owners := prefixesFor(advertisedRoutes(nm), bare.want, nm)
	if len(want) != 1 || want[0] != p20 || owners[p20] != routerKey {
		t.Fatalf("prefixes = %v owners = %v", want, owners)
	}

	m := &Manager{
		logger:  discardLogger(),
		cfg:     &config.Config{},
		servers: map[string]*tsnet.Server{"src": {}},
	}
	m.syncTailnetDial(context.Background(), "src")
	m.syncTailnetDial(context.Background(), "missing")
	if _, err := m.DialSource(context.Background(), "src", "not-an-addr"); err == nil {
		t.Fatal("bad address dialed")
	}
	if _, err := m.DialSource(context.Background(), "src", "app.example.com:80"); err == nil {
		t.Fatal("hostname dialed")
	}
	if _, err := m.resolveTailnetHost(context.Background(), "src", nil, "app.internal.example.com"); err == nil {
		t.Fatal("resolve before a netmap")
	}
	m.servers = nil
	m.cfg = &config.Config{Bridges: []config.BridgeRule{{
		Name:          "db",
		SourceTailnet: "src",
		LocalSources: []config.LocalSourceSpec{
			{Addr: "10.0.0.1:8080"},
			{Addr: "app.internal.example.com:443", Via: config.ViaTailnet, Ports: config.LocalPortList(443)},
			{Addr: "app.internal.example.com", Via: config.ViaTailnet, Ports: config.LocalPortList(443)},
		},
	}}}
	m.syncTailnetDial(context.Background(), "src")

	m.scopes = map[string]*nodeScope{"src": {nm: nm}}
	ip, err := m.resolveTailnetHost(context.Background(), "src", nil, "app.src.ts.net")
	if err != nil || ip != netip.MustParseAddr("100.64.0.5") {
		t.Fatalf("magic = %s %v", ip, err)
	}
	nowhere := &netmap.NetworkMap{DNS: tailcfg.DNSConfig{Routes: map[string][]*dnstype.Resolver{
		"internal.example.com": {{Addr: "192.0.2.53"}},
	}}}
	m.scopes["src"].nm = nowhere
	if _, err := m.resolveTailnetHost(context.Background(), "src", nil, "app.internal.example.com"); err == nil {
		t.Fatal("resolver without a route resolved")
	}

	orig := tailnetDial
	t.Cleanup(func() { tailnetDial = orig })
	tailnetDial = func(context.Context, *tsnet.Server, string, string) (net.Conn, error) {
		return nil, errors.New("dns down")
	}
	m.scopes["src"].nm = &netmap.NetworkMap{DNS: tailcfg.DNSConfig{Routes: map[string][]*dnstype.Resolver{
		"internal.example.com": {{Addr: "100.64.0.8"}},
	}}}
	if _, err := m.resolveTailnetHost(context.Background(), "src", nil, "app.internal.example.com"); err == nil {
		t.Fatal("failed query resolved")
	}
	tailnetDial = func(context.Context, *tsnet.Server, string, string) (net.Conn, error) {
		c, s := net.Pipe()
		go func() {
			defer s.Close()
			var nbuf [2]byte
			if _, err := io.ReadFull(s, nbuf[:]); err != nil {
				return
			}
			raw := make([]byte, int(binary.BigEndian.Uint16(nbuf[:])))
			if _, err := io.ReadFull(s, raw); err != nil {
				return
			}
			resp := new(dns.Msg)
			resp.SetReply(&dns.Msg{Question: []dns.Question{{Name: "app.internal.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}})
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: "app.internal.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5},
				A:   net.ParseIP("192.0.2.10"),
			})
			out, _ := resp.Pack()
			var lenb [2]byte
			binary.BigEndian.PutUint16(lenb[:], uint16(len(out)))
			_, _ = s.Write(append(lenb[:], out...))
		}()
		return c, nil
	}
	if _, err := m.resolveTailnetHost(context.Background(), "src", nil, "app.internal.example.com"); err == nil {
		t.Fatal("answer outside advertised routes was accepted")
	}

	if exportField(reflect.Value{}).IsValid() {
		t.Fatal("invalid field exported")
	}
	type plain struct{ N int }
	f := reflect.ValueOf(&plain{N: 7}).Elem().FieldByName("N")
	if got := exportField(f); !got.CanInterface() || got.Int() != 7 {
		t.Fatalf("export = %v", got)
	}
}

func TestQueryARejectsBadReplies(t *testing.T) {
	orig := tailnetDial
	t.Cleanup(func() { tailnetDial = orig })
	ns := netip.MustParseAddr("100.64.0.8")
	dial := func(conn net.Conn) {
		t.Helper()
		tailnetDial = func(context.Context, *tsnet.Server, string, string) (net.Conn, error) {
			return conn, nil
		}
	}
	pipe := func(reply []byte) net.Conn {
		c, s := net.Pipe()
		go func() {
			defer s.Close()
			var nbuf [2]byte
			if _, err := io.ReadFull(s, nbuf[:]); err != nil {
				return
			}
			raw := make([]byte, int(binary.BigEndian.Uint16(nbuf[:])))
			_, _ = io.ReadFull(s, raw)
			if reply != nil {
				_, _ = s.Write(reply)
			}
		}()
		return c
	}
	dial(&failWriteConn{})
	if _, err := queryA(context.Background(), nil, ns, "app.internal.example.com"); err == nil {
		t.Fatal("write failure queried")
	}
	dial(pipe([]byte{0, 0}))
	if _, err := queryA(context.Background(), nil, ns, "app.internal.example.com"); err == nil {
		t.Fatal("zero length accepted")
	}
	dial(pipe([]byte{0, 4, 1}))
	if _, err := queryA(context.Background(), nil, ns, "app.internal.example.com"); err == nil {
		t.Fatal("short body accepted")
	}
	dial(pipe([]byte{0, 4, 1, 2, 3, 4}))
	if _, err := queryA(context.Background(), nil, ns, "app.internal.example.com"); err == nil {
		t.Fatal("garbage accepted")
	}
	resp := new(dns.Msg)
	resp.SetReply(&dns.Msg{Question: []dns.Question{{Name: "app.internal.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}})
	out, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var lenb [2]byte
	binary.BigEndian.PutUint16(lenb[:], uint16(len(out)))
	dial(pipe(append(lenb[:], out...)))
	if _, err := queryA(context.Background(), nil, ns, "app.internal.example.com"); err == nil {
		t.Fatal("empty answer accepted")
	}
}

type failWriteConn struct{ net.Conn }

func (failWriteConn) Write([]byte) (int, error) { return 0, errors.New("write failed") }
func (failWriteConn) Close() error              { return nil }
func (failWriteConn) SetDeadline(time.Time) error {
	return nil
}

func TestViaTailnetDialRefusesBeforeSending(t *testing.T) {
	f := &Forwarder{viaTailnet: true, localTargets: map[int]string{80: "not a host"}}
	if _, _, err := f.dialBackend(context.Background(), 80); err == nil {
		t.Fatal("bad target dialed")
	}
	f.localTargets = map[int]string{80: "app.example.com:80"}
	if _, _, err := f.dialBackend(context.Background(), 80); err == nil {
		t.Fatal("unconfigured prepare dialed")
	}
	f.prepareTailnet = func(context.Context, string) (netip.Addr, error) {
		return netip.Addr{}, errNoSubnetRoute
	}
	if _, _, err := f.dialBackend(context.Background(), 80); err == nil {
		t.Fatal("prepare error dialed")
	}
	f.localTargets = nil
	f.localAddr = "10.0.0.1:8080"
	if addr, ok := f.localDial(9); !ok || addr != "10.0.0.1:8080" {
		t.Fatalf("localDial = %q %v", addr, ok)
	}
}

func TestRoutedDialErrors(t *testing.T) {
	cases := []struct {
		err    error
		reason string
	}{
		{nil, ""},
		{errNoSubnetRoute, "no_route"},
		{errors.New("connection denied by filter"), "denied"},
		{context.DeadlineExceeded, "denied"},
		{errors.New("i/o timeout"), "denied"},
		{errors.New("connection reset"), "error"},
	}
	for _, c := range cases {
		if got := routedFailureReason(c.err); got != c.reason {
			t.Errorf("reason(%v) = %q, want %q", c.err, got, c.reason)
		}
	}
	for _, reason := range []string{"no_route", "denied", "error"} {
		if !strings.Contains(routedDialMessage("svc:app", "10.20.0.10:8080", reason, errNoSubnetRoute), "10.20.0.10:8080") {
			t.Errorf("message for %s dropped the target", reason)
		}
	}
}
