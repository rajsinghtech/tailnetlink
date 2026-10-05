package bridge

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	"github.com/rajsinghtech/tailnetlink/internal/testutil/fakeapi"
	tsclient "tailscale.com/client/tailscale/v2"
	"tailscale.com/tsnet"
)

// stubForwarders replaces the forwarder start with a no-op for the test, so
// rules can run without a real tsnet node. The tsnet.Server values put in
// the manager below are never started.
func stubForwarders(t *testing.T) {
	t.Helper()
	orig := startForwarder
	startForwarder = func(*Forwarder, context.Context) error { return nil }
	t.Cleanup(func() { startForwarder = orig })
}

type testManager struct {
	m    *Manager
	src  *fakeapi.Server
	dest *fakeapi.Server
}

func newTestManager(t *testing.T) *testManager {
	t.Helper()
	stubForwarders(t)
	src := fakeapi.New(t)
	src.Tailnet = "src.example"
	dest := fakeapi.New(t)
	dest.Tailnet = "dest.example"
	// Leave bridged VIPs without an address so per-device DNS setup, which
	// needs a running tsnet node, is skipped.
	dest.AssignAddrs = false

	m := New(state.New(), discardLogger(), "")
	m.servers["src"] = &tsnet.Server{}
	m.servers["dest"] = &tsnet.Server{}
	m.apiClients["src"] = src.Client()
	m.apiClients["dest"] = dest.Client()
	m.cfg = &config.Config{Tailnets: map[string]config.TailnetConfig{
		"src":  {Tailnet: "src.example"},
		"dest": {Tailnet: "dest.example", Tags: []string{"tag:bridge"}},
	}}
	return &testManager{m: m, src: src, dest: dest}
}

func (tm *testManager) bridgeActive(id string) bool {
	for _, b := range tm.m.store.GetBridges() {
		if b.ID == id && b.Status == state.BridgeStatusActive {
			return true
		}
	}
	return false
}

// KNOWN-BAD: when a rule's context is cancelled (process shutdown, or the
// rule or its tailnet being reconfigured) every VIP service it created is
// deleted from the destination tailnet. Flip in roadmap PR 6 (no delete on
// shutdown): cancelling should make zero writes.
func TestKnownBad_RuleShutdownDeletesServices(t *testing.T) {
	tm := newTestManager(t)
	tm.src.SetDevices([]tsclient.Device{{
		NodeID: "n1", Name: "web-1.src.example", Hostname: "web-1",
		Tags: []string{"tag:web"}, Addresses: []string{"100.64.0.1"},
	}})
	rule := config.BridgeRule{
		Name: "web", SourceTailnet: "src", DestTailnets: []string{"dest"},
		SourceTag: "tag:web", Ports: []int{80},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		tm.m.runRule(ctx, rule, time.Hour, time.Second)
		close(done)
	}()

	waitFor(t, 5*time.Second, "bridge active", func() bool {
		return tm.bridgeActive("web/dest/web-1.src.example")
	})
	if _, ok := tm.dest.Service("svc:tnl-src-web-1"); !ok {
		t.Fatal("service not created")
	}

	tm.dest.ResetCalls()
	cancel()
	<-done

	if got := callStrings(tm.dest.Writes()); !slices.Equal(got, []string{"DELETE /vip-services/svc:tnl-src-web-1"}) {
		t.Errorf("writes on shutdown = %v", got)
	}
	if _, ok := tm.dest.Service("svc:tnl-src-web-1"); ok {
		t.Error("expected the service to be deleted on shutdown today")
	}
}

// KNOWN-BAD: the worst case of the two problems above together. A local rule
// whose derived short name ("app") matches an existing hand made service
// takes it over, then deletes it on shutdown. Flip in roadmap PR 4 (no
// takeover) and PR 6 (no delete on shutdown).
func TestKnownBad_LocalRuleTakesOverAndDeletesForeignService(t *testing.T) {
	tm := newTestManager(t)
	tm.dest.PutService(tsclient.VIPService{
		Name: "svc:app", Addrs: []string{"100.100.5.5"}, Comment: "hand made", Ports: []string{"tcp:3000"},
	})
	rule := config.BridgeRule{
		Name: "loc", DestTailnets: []string{"dest"},
		LocalSources: []config.LocalSourceSpec{{Addr: "localhost:8080", DNSName: "app.example.net"}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		tm.m.runLocalRule(ctx, rule, time.Second)
		close(done)
	}()

	// The takeover keeps the foreign service's address, so per-device DNS
	// setup does run here. It stops early because the fake gives the DNS VIP
	// no address, before anything touches the unstarted tsnet node.
	waitFor(t, 5*time.Second, "local bridge active", func() bool {
		return tm.bridgeActive("loc/local/dest/localhost:8080")
	})
	svc, _ := tm.dest.Service("svc:app")
	if svc.Comment == "hand made" {
		t.Errorf("expected the foreign service to be overwritten today, got %+v", svc)
	}

	cancel()
	<-done

	if _, ok := tm.dest.Service("svc:app"); ok {
		t.Error("expected the (formerly foreign) service to be deleted on shutdown today")
	}
}

// KNOWN-BAD: releasing the last reference to a shared DNS zone, which is what
// rule shutdown does through dnsCleanups, deletes the DNS VIP service and
// removes the split-DNS entry. Flip in roadmap PR 6 for the shutdown case.
func TestKnownBad_ReleaseSharedDNSDeletesOnLastRef(t *testing.T) {
	tm := newTestManager(t)
	const zone = "src.example"
	const resolver = "100.100.0.53"
	tm.dest.PutService(tsclient.VIPService{Name: "svc:tnl-dns-src-example-dns", Addrs: []string{resolver}})
	tm.dest.SetSplitDNS(zone, []string{resolver})

	client := tm.m.apiClients["dest"]
	ds := NewDNSServer(nil, client, "dns-src-example", nil, zone, discardLogger())
	ds.svcName = "svc:tnl-dns-src-example-dns"
	ds.AddRecord("web-1", mustAddr("100.100.0.1"))
	tm.m.sharedDNS["dest/"+zone] = &sharedDNSEntry{
		server: ds,
		sdns:   NewSplitDNSConfigurator(client, zone, resolver, discardLogger()),
		refs:   2,
	}

	// First release only drops a reference.
	tm.m.releaseSharedDNS("dest", zone, "web-1")
	if w := tm.dest.Writes(); len(w) != 0 {
		t.Fatalf("writes with refs remaining: %v", callStrings(w))
	}

	tm.m.releaseSharedDNS("dest", zone, "web-2")
	got := callStrings(tm.dest.Writes())
	want := []string{"DELETE /vip-services/svc:tnl-dns-src-example-dns", "PATCH /dns/split-dns"}
	if !slices.Equal(got, want) {
		t.Errorf("writes = %v, want %v", got, want)
	}
	if tm.dest.HasZone(zone) {
		t.Error("expected split-DNS zone to be removed today")
	}
}
