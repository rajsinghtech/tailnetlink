package e2e

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rajsinghtech/tailnetlink/internal/config"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

// TestViaTailnetReachesBackendThroughSubnetRouter proves a via:tailnet
// local entry is dialed through the source node's userspace netstack to an
// address that exists only behind a subnet router. The source node installs
// the one advertised prefix that covers the target and not the router's
// other prefix. Removing the entry withdraws that prefix, and shutting the
// process down leaves the same empty set. Other nodes, their routes, and
// both tailnets' DNS config are unchanged, and no tun device is opened.
func TestViaTailnetReachesBackendThroughSubnetRouter(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	b.src.control.DNSConfig.Routes = map[string][]*dnstype.Resolver{
		"internal.example.com": {{Addr: "10.20.0.53"}},
	}

	router := b.src.node(t, ctx, "router")
	lc, err := router.srv.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.20.0.0/24"),
		netip.MustParsePrefix("10.99.0.0/24"),
	}
	if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		AdvertiseRoutesSet: true,
		Prefs:              ipn.Prefs{AdvertiseRoutes: prefixes},
	}); err != nil {
		t.Fatal(err)
	}
	b.src.control.SetSubnetRoutes(router.key, prefixes)

	var saw99 atomic.Bool
	router.srv.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (func(net.Conn), bool) {
		switch dst.String() {
		case "10.20.0.53:53":
			return serveDNSA("app.internal.example.com.", net.ParseIP("10.20.0.10")), true
		case "10.20.0.10:8080":
			return serveEchoConn, true
		case "10.99.0.9:8080":
			return func(c net.Conn) {
				saw99.Store(true)
				c.Close()
			}, true
		default:
			return nil, false
		}
	})
	bystander := b.src.node(t, ctx, "bystander")
	_ = bystander

	beforeSrc := controlSnap(t, b.src)
	beforeDst := controlSnap(t, b.dst)
	rule := config.BridgeRule{
		Name: "app", SourceTailnet: b.srcName, DestTailnets: []string{b.dstName},
		LocalSources: []config.LocalSourceSpec{{
			Addr: "app.internal.example.com", Via: config.ViaTailnet,
			DNSName: "app.example.com", ShortName: "app",
			Ports: config.LocalPortList(8080),
		}},
	}
	r := startManager(t, b.config(rule), "")
	waitFor(t, 45*time.Second, "bridge active", func() bool {
		status, _ := r.bridgeStatus("app/local/" + b.dstName + "/app.internal.example.com/app")
		return status == "active"
	})
	waitFor(t, 30*time.Second, "only 10.20.0.0/24 accepted", func() bool {
		return onlyPrefix(r.m.AcceptedRoutes(b.srcName), "10.20.0.0/24")
	})
	on, err := r.m.RouteAll(ctx, b.srcName)
	if err != nil || on {
		t.Fatalf("RouteAll = %v, %v; want false", on, err)
	}

	cli := client(t, ctx, b.dst, "client")
	vip := waitVIP(t, b.dstAPI, "svc:app")
	echoVia(t, ctx, cli, netip.AddrPortFrom(vip, 8080), "via-tailnet")

	if _, err := r.m.DialSource(ctx, b.srcName, "10.99.0.9:8080"); err == nil || !strings.Contains(err.Error(), "no subnet route") {
		t.Fatalf("dial of unconfigured prefix = %v", err)
	}
	if saw99.Load() {
		t.Fatal("traffic reached 10.99.0.9; that prefix was accepted")
	}
	if !sameSnap(beforeSrc, controlSnap(t, b.src)) || !sameSnap(beforeDst, controlSnap(t, b.dst)) {
		t.Fatalf("tailnet changed\nsrc before %s\nsrc after  %s\ndst before %s\ndst after  %s", beforeSrc, controlSnap(t, b.src), beforeDst, controlSnap(t, b.dst))
	}
	assertLinkHasNoApprovedRoutes(t, b.src, "tailnetlink-"+b.srcName, true)
	assertLinkHasNoApprovedRoutes(t, b.dst, "tailnetlink-"+b.dstName, true)
	assertNoDNSOrRouteWrites(t, b.srcAPI)
	if got := r.m.AcceptedRoutes(b.dstName); len(got) != 0 {
		t.Fatalf("dest tailnet accepted routes with no via:tailnet entry: %v", got)
	}
	if on, err := r.m.RouteAll(ctx, b.dstName); err != nil || on {
		t.Fatalf("dest RouteAll = %v, %v", on, err)
	}
	assertNoTun(t)

	r.reconcile(b.config())
	waitFor(t, 20*time.Second, "route acceptance withdrawn", func() bool {
		return len(r.m.AcceptedRoutes(b.srcName)) == 0
	})
	on, err = r.m.RouteAll(ctx, b.srcName)
	if err != nil || on {
		t.Fatalf("RouteAll after removal = %v, %v", on, err)
	}
	if got := r.m.AcceptedRoutes(b.dstName); len(got) != 0 {
		t.Fatalf("dest routes after removal: %v", got)
	}
	if !sameSnap(beforeSrc, controlSnap(t, b.src)) || !sameSnap(beforeDst, controlSnap(t, b.dst)) {
		t.Fatalf("tailnet residue after reload\nsrc %s\ndst %s", controlSnap(t, b.src), controlSnap(t, b.dst))
	}
	assertLinkHasNoApprovedRoutes(t, b.src, "tailnetlink-"+b.srcName, true)
	assertLinkHasNoApprovedRoutes(t, b.dst, "tailnetlink-"+b.dstName, true)
	assertNoDNSOrRouteWrites(t, b.srcAPI)

	r.stop(t)
	if got := r.m.AcceptedRoutes(b.srcName); len(got) != 0 {
		t.Fatalf("accepted routes after shutdown: %v", got)
	}
	if got := r.m.AcceptedRoutes(b.dstName); len(got) != 0 {
		t.Fatalf("dest routes after shutdown: %v", got)
	}
	if !sameSnap(beforeSrc, controlSnap(t, b.src)) || !sameSnap(beforeDst, controlSnap(t, b.dst)) {
		t.Fatalf("tailnet residue after shutdown\nsrc %s\ndst %s", controlSnap(t, b.src), controlSnap(t, b.dst))
	}
	assertLinkHasNoApprovedRoutes(t, b.src, "tailnetlink-"+b.srcName, false)
	assertLinkHasNoApprovedRoutes(t, b.dst, "tailnetlink-"+b.dstName, false)
	assertNoDNSOrRouteWrites(t, b.srcAPI)
}

func onlyPrefix(got []netip.Prefix, cidr string) bool {
	want := netip.MustParsePrefix(cidr)
	return len(got) == 1 && got[0] == want
}

func serveEchoConn(c net.Conn) {
	defer c.Close()
	in := make([]byte, 64)
	n, err := c.Read(in)
	if err != nil && n == 0 {
		return
	}
	line := string(in[:n])
	if !strings.HasSuffix(line, "\n") {
		line += "\n"
	}
	_, _ = io.WriteString(c, "echo: "+line)
}

func serveDNSA(name string, ip net.IP) func(net.Conn) {
	return func(c net.Conn) {
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		var nbuf [2]byte
		if _, err := io.ReadFull(c, nbuf[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(nbuf[:]))
		raw := make([]byte, n)
		if _, err := io.ReadFull(c, raw); err != nil {
			return
		}
		var req dns.Msg
		if err := req.Unpack(raw); err != nil || len(req.Question) == 0 {
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(&req)
		if req.Question[0].Name == name && req.Question[0].Qtype == dns.TypeA {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
				A:   ip,
			})
		}
		out, err := resp.Pack()
		if err != nil {
			return
		}
		var lenb [2]byte
		binary.BigEndian.PutUint16(lenb[:], uint16(len(out)))
		_, _ = c.Write(append(lenb[:], out...))
	}
}

type tailnetSnap struct {
	dns   string
	peers string
}

// controlSnap is the tailnet DNS config plus every peer this process did
// not create. The tailnetlink nodes and the dialing test client are left
// out so the comparison is the other devices' names, tags, addresses, and
// approved routes.
func controlSnap(t *testing.T, tn *tailnet) tailnetSnap {
	t.Helper()
	raw, err := json.Marshal(tn.control.DNSConfig)
	if err != nil {
		t.Fatal(err)
	}
	var peers []string
	for _, n := range tn.control.AllNodes() {
		host := ""
		if n.Hostinfo.Valid() {
			host = n.Hostinfo.Hostname()
		}
		if strings.HasPrefix(host, "tailnetlink-") || host == "client" {
			continue
		}
		peers = append(peers, nodeSig(n))
	}
	slices.Sort(peers)
	return tailnetSnap{dns: string(raw), peers: strings.Join(peers, "\n")}
}

func sameSnap(a, b tailnetSnap) bool {
	return a == b
}

func (s tailnetSnap) String() string {
	return fmt.Sprintf("dns=%s peers=%s", s.dns, s.peers)
}

// assertLinkHasNoApprovedRoutes checks the tailnetlink node did not
// advertise or receive subnet routes in the control plane. A missing node
// after shutdown is fine: there is nothing left behind.
func assertLinkHasNoApprovedRoutes(t *testing.T, tn *tailnet, host string, mustExist bool) {
	t.Helper()
	n := findNode(tn, host)
	if n == nil {
		if mustExist {
			t.Fatalf("node %s missing from control", host)
		}
		return
	}
	if len(n.PrimaryRoutes) != 0 {
		t.Fatalf("%s primary routes = %v", host, n.PrimaryRoutes)
	}
	if n.Hostinfo.Valid() && n.Hostinfo.RoutableIPs().Len() != 0 {
		t.Fatalf("%s routable IPs = %v", host, n.Hostinfo.RoutableIPs())
	}
}

func assertNoDNSOrRouteWrites(t *testing.T, api *ctlBridge) {
	t.Helper()
	for _, call := range api.Writes() {
		low := strings.ToLower(call)
		if strings.Contains(low, "dns") || strings.Contains(low, "route") || strings.Contains(low, "acl") || strings.Contains(low, "policy") {
			t.Errorf("source tailnet control write %q", call)
		}
	}
}

func findNode(tn *tailnet, host string) *tailcfg.Node {
	for _, n := range tn.control.AllNodes() {
		if n.Hostinfo.Valid() && n.Hostinfo.Hostname() == host {
			return n
		}
	}
	return nil
}

func nodeSig(n *tailcfg.Node) string {
	if n == nil {
		return ""
	}
	routable := ""
	if n.Hostinfo.Valid() {
		routable = fmt.Sprint(n.Hostinfo.RoutableIPs())
	}
	return fmt.Sprintf("name=%s tags=%v addr=%v routes=%v routable=%s", n.Name, n.Tags, n.Addresses, n.PrimaryRoutes, routable)
}

func assertNoTun(t *testing.T) {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err != nil {
			continue
		}
		if strings.Contains(target, "tun") || strings.Contains(target, "/dev/net/") {
			t.Errorf("tun device open: fd %s -> %s", e.Name(), target)
		}
	}
	if _, err := os.Stat("/sys/class/net/tailscale0"); err == nil {
		t.Error("kernel interface tailscale0 exists")
	}
}

// TestUserspaceNodeDoesNotOpenTun starts a node the way tailnetlink does,
// with no TUN device configured, and checks the process did not open one.
func TestUserspaceNodeDoesNotOpenTun(t *testing.T) {
	ctx := e2eSetup(t)
	tn := newTailnet(t, "src.ts.net")
	_ = tn.node(t, ctx, "tailnetlink-src")
	assertNoTun(t)
}
