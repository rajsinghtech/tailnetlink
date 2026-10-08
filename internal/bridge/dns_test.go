package bridge

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"tailscale.com/tailcfg"
)

// serveDNS runs d's handler on a loopback TCP listener, the way the VIP
// listener is served, and returns a query function.
func serveDNS(t *testing.T, d *DNSServer) func(name string, qtype uint16) *dns.Msg {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: ln, Handler: d.mux}
	go srv.ActivateAndServe() //nolint:errcheck
	t.Cleanup(func() { _ = srv.Shutdown() })
	c := &dns.Client{Net: "tcp"}
	return func(name string, qtype uint16) *dns.Msg {
		t.Helper()
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qtype)
		r, _, err := c.Exchange(m, ln.Addr().String())
		if err != nil {
			t.Fatalf("query %s: %v", name, err)
		}
		return r
	}
}

func TestDNSServerAnswersExactZoneApex(t *testing.T) {
	const zone = "app.corp.example.com"
	d := NewDNSServer(nil, nil, nil, testOwner, zone, discardLogger())
	d.AddRecord("@", netip.MustParseAddr("100.100.1.9"))
	q := serveDNS(t, d)
	if r := q(zone, dns.TypeA); len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "100.100.1.9" || !r.Authoritative {
		t.Errorf("apex A = %+v", r)
	}
	if r := q(zone, dns.TypeAAAA); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Errorf("apex AAAA with only an A = %+v", r)
	}
	d.AddRecord("@", netip.MustParseAddr("fd7a:115c:a1e0::9"))
	if r := q(zone, dns.TypeAAAA); len(r.Answer) != 1 || r.Answer[0].(*dns.AAAA).AAAA.String() != "fd7a:115c:a1e0::9" {
		t.Errorf("apex AAAA = %+v", r)
	}
	if r := q("other.corp.example.com", dns.TypeA); len(r.Answer) != 0 {
		t.Errorf("sibling name answered: %+v", r)
	}
}

func TestDNSServerAnswers(t *testing.T) {
	d := NewDNSServer(nil, nil, nil, testOwner, "src.example", discardLogger())
	d.AddRecord("web", netip.MustParseAddr("100.100.1.1"))
	d.AddRecord("v6", netip.MustParseAddr("fd7a:115c:a1e0::1"))
	d.AddRecord("src.example", netip.MustParseAddr("100.100.1.2"))
	d.AddRecord("mapped", netip.MustParseAddr("::ffff:100.100.1.3"))
	q := serveDNS(t, d)

	if r := q("web.src.example", dns.TypeA); len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "100.100.1.1" || !r.Authoritative {
		t.Errorf("A web = %v", r)
	}
	if r := q("v6.src.example", dns.TypeAAAA); len(r.Answer) != 1 || r.Answer[0].(*dns.AAAA).AAAA.String() != "fd7a:115c:a1e0::1" {
		t.Errorf("AAAA v6 = %v", r)
	}
	if r := q("src.example", dns.TypeA); len(r.Answer) != 1 {
		t.Errorf("apex = %v", r)
	}
	if r := q("mapped.src.example", dns.TypeA); len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "100.100.1.3" {
		t.Errorf("4in6 = %v", r)
	}
	// The name exists but has no record of this family: NOERROR, empty.
	if r := q("web.src.example", dns.TypeAAAA); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Errorf("AAAA web = %v", r)
	}
	if r := q("nope.src.example", dns.TypeA); r.Rcode != dns.RcodeNameError {
		t.Errorf("missing name rcode = %d", r.Rcode)
	}
	if r := q("web.src.example", dns.TypeTXT); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Errorf("TXT = %v", r)
	}
	d.RemoveRecord("web")
	if r := q("web.src.example", dns.TypeA); r.Rcode != dns.RcodeNameError {
		t.Errorf("removed name rcode = %d", r.Rcode)
	}
}

// The DNS service is named after its zone, never after a rule, and stays a
// valid service name for long zones.
func TestDNSServiceName(t *testing.T) {
	if got := DNSServiceName("src.example."); got != "svc:tnl-dns-src-example-dns" {
		t.Errorf("name = %q", got)
	}
	if d := NewDNSServer(nil, nil, nil, testOwner, "src.example", discardLogger()); d.svcName != "svc:tnl-dns-src-example-dns" {
		t.Errorf("server name = %q", d.svcName)
	}
	long := DNSServiceName(strings.Repeat("a", 40) + "." + strings.Repeat("b", 40) + ".ts.net")
	if err := tailcfg.ServiceName(long).Validate(); err != nil {
		t.Errorf("%q: %v", long, err)
	}
	if DNSServiceName(strings.Repeat("a", 80)+"x") == DNSServiceName(strings.Repeat("a", 80)+"y") {
		t.Error("long zones collided")
	}
}

// Start creates the DNS service with a zone annotation and no rule
// annotation, since it is shared by every rule using the zone.
func TestDNSServiceAnnotations(t *testing.T) {
	tm := newTestManager(t)
	d := NewDNSServer(nil, tm.m.apiClients["dest"], []string{"tag:bridge"}, testOwner, "src.example", discardLogger())
	// No VIP addresses in this fake, so Start stops before listening.
	if _, err := d.Start(t.Context()); err == nil || !strings.Contains(err.Error(), "no assigned IP") {
		t.Fatalf("Start err = %v", err)
	}
	svc, ok := tm.dest.Service("svc:tnl-dns-src-example-dns")
	if !ok {
		t.Fatal("DNS service not created")
	}
	if svc.Annotations["tailnetlink/zone"] != "src.example" || svc.Annotations["tailnetlink/rule"] != "" {
		t.Errorf("annotations = %v", svc.Annotations)
	}
	if err := d.DeleteService(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, ok := tm.dest.Service("svc:tnl-dns-src-example-dns"); ok {
		t.Error("DNS service not deleted")
	}
}
