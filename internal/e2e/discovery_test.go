package e2e

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rajsinghtech/tailnetlink/internal/config"
)

// tagRule bridges every device and service with tag in src to dst.
func (b *border) tagRule(name, tag string, ports ...int) config.BridgeRule {
	return config.BridgeRule{Name: name, SourceTailnet: b.srcName, DestTailnets: []string{b.dstName}, SourceTag: tag, Ports: ports}
}

// Twenty backends that appear at once all get a service in dst, and every
// one of them carries traffic.
func TestManagerManyBackendsAtOnce(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	b.srcAPI.setHostTags("web-", "tag:web")
	const n = 20
	for i := range n {
		echoBackend(t, ctx, b.src, fmt.Sprintf("web-%02d", i), 8080)
	}
	cl := client(t, ctx, b.dst, "client")
	startManager(t, b.config(b.tagRule("web", "tag:web", 8080)), "")

	for i := range n {
		host := fmt.Sprintf("web-%02d", i)
		vip := waitVIP(t, b.dstAPI, b.serviceName(host, ""))
		echoVia(t, ctx, cl, netip.AddrPortFrom(vip, 8080), host)
	}
}

// Two instances bridging A to B and B to A with the same tag don't pick up
// each other's services or nodes, so the service count stays put.
func TestManagerNoLoopBothWays(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	for _, api := range []*ctlBridge{b.srcAPI, b.dstAPI} {
		api.setHostTags("tailnetlink-", "tag:web")
		api.setHostTags("web-", "tag:web")
	}
	echoBackend(t, ctx, b.src, "web-a", 8080)
	echoBackend(t, ctx, b.dst, "web-b", 8080)

	cfgA := b.config(b.tagRule("ab", "tag:web", 8080))
	for name, tc := range cfgA.Tailnets {
		tc.Tags = []string{"tag:web"}
		cfgA.Tailnets[name] = tc
	}
	// The second instance runs the other way with its own names.
	cfgB := cfgA.Clone()
	cfgB.InstanceID = "e2e-rev-" + b.sfx
	cfgB.StateDir = t.TempDir()
	revSrc, revDst := "revsrc"+b.sfx, "revdst"+b.sfx
	cfgB.Tailnets = map[string]config.TailnetConfig{revSrc: cfgA.Tailnets[b.dstName], revDst: cfgA.Tailnets[b.srcName]}
	cfgB.Bridges = []config.BridgeRule{{Name: "ba", SourceTailnet: revSrc, DestTailnets: []string{revDst}, SourceTag: "tag:web", Ports: []int{8080}}}

	startManager(t, cfgA, "")
	startManager(t, cfgB, "")
	waitVIP(t, b.dstAPI, b.serviceName("web-a", ""))
	waitVIP(t, b.srcAPI, "svc:tnl-"+revSrc+"-web-b")

	want := map[string][]string{
		"src": {"svc:tnl-" + revSrc + "-web-b", "svc:tnl-dns-dst-ts-net-dns"},
		"dst": {b.serviceName("web-a", ""), "svc:tnl-dns-src-ts-net-dns"},
	}
	apis := map[string]*ctlBridge{"src": b.srcAPI, "dst": b.dstAPI}
	for side := range want {
		slices.Sort(want[side])
		waitFor(t, 30*time.Second, "services settled in "+side, func() bool {
			return slices.Equal(apis[side].ServiceNames(), want[side])
		})
	}
	// Three poll intervals later nothing has been added.
	time.Sleep(3 * cfgA.PollInterval.Duration)
	for side, api := range apis {
		if got := api.ServiceNames(); !slices.Equal(got, want[side]) {
			t.Errorf("%s services = %v, want %v", side, got, want[side])
		}
	}
}

// A local rule publishes a host:port on the test machine as a service in
// dst, and a client there gets echo replies through it.
func TestManagerLocalRule(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	peers := make(chan string, 16)
	go serveEcho(ln, peers)
	cl := client(t, ctx, b.dst, "client")

	short := "local-echo-" + b.sfx
	rule := config.BridgeRule{Name: "local", DestTailnets: []string{b.dstName}, LocalSources: []config.LocalSourceSpec{
		{Addr: ln.Addr().String(), DNSName: "echo.local.test", ShortName: short, ExposePort: 9000},
	}}
	startManager(t, b.config(rule), "")
	vip := waitVIP(t, b.dstAPI, "svc:"+short)
	if s, _ := b.dstAPI.Service("svc:" + short); !slices.Equal(s.Ports, []string{"tcp:9000"}) {
		t.Errorf("ports = %v", s.Ports)
	}
	echoVia(t, ctx, cl, netip.AddrPortFrom(vip, 9000), "local hello")
	select {
	case p := <-peers:
		if !strings.HasPrefix(p, "127.0.0.1:") {
			t.Errorf("local backend saw %s", p)
		}
	case <-time.After(5 * time.Second):
		t.Error("local backend never saw a connection")
	}
}

// A bridged name resolves through the DNS service in dst. That service
// answers over TCP; see DNSServer for why there is no UDP on a VIP.
func TestManagerDNSResolvesBridgedName(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	echoBackend(t, ctx, b.src, "backend", 8080)
	cl := client(t, ctx, b.dst, "client")
	startManager(t, b.config(b.deviceRule("web", "backend", "", 8080)), "")
	vip := waitVIP(t, b.dstAPI, b.serviceName("backend", ""))
	dnsVIP := waitVIP(t, b.dstAPI, "svc:tnl-dns-src-ts-net-dns")
	waitFor(t, 30*time.Second, "split-DNS for src.ts.net", func() bool {
		return slices.Contains(b.dstAPI.SplitDNS("src.ts.net"), dnsVIP.String())
	})

	q := new(dns.Msg)
	q.SetQuestion("backend.src.ts.net.", dns.TypeA)
	var answer string
	waitFor(t, 30*time.Second, "A record over TCP", func() bool {
		c, err := cl.srv.Dial(ctx, "tcp", netip.AddrPortFrom(dnsVIP, 53).String())
		if err != nil {
			return false
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		dc := &dns.Conn{Conn: c}
		if err := dc.WriteMsg(q); err != nil {
			return false
		}
		r, err := dc.ReadMsg()
		if err != nil || len(r.Answer) == 0 {
			return false
		}
		answer = r.Answer[0].(*dns.A).A.String()
		return true
	})
	if answer != vip.String() {
		t.Errorf("backend.src.ts.net = %s, want %s", answer, vip)
	}
}
