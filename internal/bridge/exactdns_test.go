package bridge

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/miekg/dns"
	"tailscale.com/tsnet"
)

func stubDNSListen(t *testing.T) {
	t.Helper()
	orig := listenDNS
	listenDNS = func(*tsnet.Server, string, tsnet.ServiceMode) (net.Listener, error) {
		return net.Listen("tcp", "127.0.0.1:0")
	}
	t.Cleanup(func() { listenDNS = orig })
}

// An exact dns_zone registers split-DNS for that name only, answers the
// apex, and cleanup drops only our resolver.
func TestExactDNSZoneRegistersApex(t *testing.T) {
	tm := newTestManager(t)
	tm.dest.AssignAddrs = true
	stubDNSListen(t)

	const (
		name = "app.corp.example.com"
		zone = "app.corp.example.com"
	)
	dest := destCtx{
		name: "dest", srv: tm.m.servers["dest"], client: tm.m.apiClients["dest"],
		tags: []string{"tag:bridge"},
	}
	vip := netip.MustParseAddr("100.64.0.8")
	tm.m.startDeviceDNS(context.Background(), "b1", "app", "", "svc:app", "", name, zone, vip, dest)

	if tm.dest.HasZone("corp.example.com") {
		t.Fatal("parent zone was registered")
	}
	resolvers := tm.dest.SplitDNS(zone)
	if len(resolvers) != 1 {
		t.Fatalf("resolvers for %s = %v", zone, resolvers)
	}

	entry := tm.m.sharedDNS["dest/"+zone]
	if entry == nil {
		t.Fatal("exact zone was not published")
	}
	q := serveDNS(t, entry.server)
	r := q(name, dns.TypeA)
	if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != vip.String() {
		t.Fatalf("apex answer = %+v", r)
	}

	tm.dest.SetSplitDNS(zone, []string{resolvers[0], "192.0.2.53"})
	cleanup := tm.m.dnsCleanups["b1"]
	if cleanup == nil {
		t.Fatal("no DNS cleanup")
	}
	cleanup(true)
	if got := tm.dest.SplitDNS(zone); !slices.Equal(got, []string{"192.0.2.53"}) {
		t.Errorf("resolvers after cleanup = %v, want the other resolver kept", got)
	}
	if tm.dest.HasZone("corp.example.com") {
		t.Error("cleanup created the parent zone")
	}
}

func TestDefaultDNSZoneIsParent(t *testing.T) {
	tm := newTestManager(t)
	tm.dest.AssignAddrs = true
	stubDNSListen(t)
	dest := destCtx{
		name: "dest", srv: tm.m.servers["dest"], client: tm.m.apiClients["dest"],
		tags: []string{"tag:bridge"},
	}
	tm.m.startDeviceDNS(context.Background(), "b1", "app", "", "svc:app", "", "app.corp.example.com", "", netip.MustParseAddr("100.64.0.8"), dest)
	t.Cleanup(func() {
		if c := tm.m.dnsCleanups["b1"]; c != nil {
			c(true)
		}
	})
	if !tm.dest.HasZone("corp.example.com") {
		t.Fatalf("parent zone missing, zones registered via split-DNS writes: %v", tm.dest.Writes())
	}
	if tm.dest.HasZone("app.corp.example.com") {
		t.Fatal("exact name was registered without dns_zone")
	}
}
