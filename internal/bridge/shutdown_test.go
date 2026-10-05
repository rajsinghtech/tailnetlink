package bridge

import (
	"context"
	"reflect"
	"slices"
	"strings"
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
	origClose := closeServer
	closeServer = func(*tsnet.Server) error { return nil }
	t.Cleanup(func() { startForwarder, closeServer = orig, origClose })
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

	m := New(state.New(), discardLogger(), nil)
	m.owner = testOwner
	m.uiService = config.DefaultUIServiceName
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

// runWebRule starts the tag:web rule from src to dest the way Reconcile
// does, waits for its bridge to be active and returns the rule.
func (tm *testManager) runWebRule(t *testing.T) config.BridgeRule {
	t.Helper()
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
	tm.m.mu.Lock()
	tm.m.rules[rule.Name] = cancel
	tm.m.ruleDone[rule.Name] = done
	tm.m.mu.Unlock()
	go func() {
		defer close(done)
		tm.m.runRule(ctx, rule, time.Hour, time.Second)
	}()
	t.Cleanup(cancel)
	waitFor(t, 5*time.Second, "bridge active", func() bool {
		return tm.bridgeActive("web/dest/web-1.src.example")
	})
	if _, ok := tm.dest.Service("svc:tnl-src-web-1"); !ok {
		t.Fatal("service not created")
	}
	return rule
}

// Stopping a rule for a shutdown or restart makes no writes: the service
// stays where it is for the next start to pick up.
func TestRuleStopMakesNoWrites(t *testing.T) {
	tm := newTestManager(t)
	tm.runWebRule(t)
	tm.dest.ResetCalls()
	tm.m.stopRule("web", false)

	if w := tm.dest.Writes(); len(w) != 0 {
		t.Errorf("writes on stop = %v, want none", callStrings(w))
	}
	if _, ok := tm.dest.Service("svc:tnl-src-web-1"); !ok {
		t.Error("service deleted on stop")
	}
	if len(tm.m.store.GetBridges()) != 0 {
		t.Error("bridge entries left in the state store")
	}
}

// Removing a rule deletes the services it owns, and nothing else.
func TestRuleRemoveDeletesOwnServices(t *testing.T) {
	tm := newTestManager(t)
	tm.dest.PutService(tsclient.VIPService{Name: "svc:other", Addrs: []string{"100.100.9.1"}})
	tm.runWebRule(t)
	tm.dest.ResetCalls()
	tm.m.stopRule("web", true)

	if got := callStrings(tm.dest.Writes()); !slices.Equal(got, []string{"DELETE /vip-services/svc:tnl-src-web-1"}) {
		t.Errorf("writes on remove = %v", got)
	}
	if _, ok := tm.dest.Service("svc:other"); !ok {
		t.Error("unrelated service deleted")
	}
}

// Reconcile restarts a changed rule without deleting anything, and only a
// rule that left the config gets its services deleted.
func TestReconcileChangedVersusRemovedRule(t *testing.T) {
	tm := newTestManager(t)
	tm.src.SetDevices([]tsclient.Device{{
		NodeID: "n1", Name: "web-1.src.example", Hostname: "web-1",
		Tags: []string{"tag:web"}, Addresses: []string{"100.64.0.1"},
	}})
	base := *tm.m.cfg
	base.InstanceID = testOwner
	base.PollInterval = config.Duration{Duration: time.Hour}
	base.DialTimeout = config.Duration{Duration: time.Second}
	rule := config.BridgeRule{Name: "web", SourceTailnet: "src", DestTailnets: []string{"dest"}, SourceTag: "tag:web", Ports: []int{80}}
	withRule := func(r ...config.BridgeRule) *config.Config {
		c := base
		c.Bridges = r
		return &c
	}
	ctx := context.Background()

	tm.m.Reconcile(ctx, withRule(rule))
	waitFor(t, 5*time.Second, "bridge active", func() bool { return tm.bridgeActive("web/dest/web-1.src.example") })

	tm.dest.ResetCalls()
	changed := rule
	changed.Ports = []int{80, 443}
	tm.m.Reconcile(ctx, withRule(changed))
	waitFor(t, 5*time.Second, "bridge active again", func() bool { return tm.bridgeActive("web/dest/web-1.src.example") })
	for _, w := range callStrings(tm.dest.Writes()) {
		if strings.HasPrefix(w, "DELETE") {
			t.Errorf("changed rule deleted something: %s", w)
		}
	}
	if svc, _ := tm.dest.Service("svc:tnl-src-web-1"); !slices.Equal(svc.Ports, []string{"tcp:80", "tcp:443"}) {
		t.Errorf("ports after change = %v", svc.Ports)
	}

	tm.dest.ResetCalls()
	tm.m.Reconcile(ctx, withRule())
	if got := callStrings(tm.dest.Writes()); !slices.Equal(got, []string{"DELETE /vip-services/svc:tnl-src-web-1"}) {
		t.Errorf("writes on removal = %v", got)
	}
}

// A local rule's own services also survive a stop and go on remove.
func TestLocalRuleStopVersusRemove(t *testing.T) {
	for _, remove := range []bool{false, true} {
		tm := newTestManager(t)
		rule := config.BridgeRule{
			Name: "loc", DestTailnets: []string{"dest"},
			LocalSources: []config.LocalSourceSpec{{Addr: "localhost:8080", DNSName: "app.example.net"}},
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		tm.m.rules["loc"] = cancel
		tm.m.ruleDone["loc"] = done
		go func() {
			defer close(done)
			tm.m.runLocalRule(ctx, rule, time.Second)
		}()
		waitFor(t, 5*time.Second, "local bridge active", func() bool {
			return tm.bridgeActive("loc/local/dest/localhost:8080")
		})
		tm.dest.ResetCalls()
		tm.m.stopRule("loc", remove)
		_, exists := tm.dest.Service("svc:app")
		if exists == remove {
			t.Errorf("remove=%v: service exists=%v, writes %v", remove, exists, callStrings(tm.dest.Writes()))
		}
	}
}

// A local rule whose derived short name ("app") matches a hand made service
// reports a conflict and never touches it, neither while running nor on
// shutdown.
func TestLocalRuleLeavesForeignServiceAlone(t *testing.T) {
	tm := newTestManager(t)
	foreign := tsclient.VIPService{
		Name: "svc:app", Addrs: []string{"100.100.5.5"}, Comment: "hand made", Ports: []string{"tcp:3000"},
	}
	tm.dest.PutService(foreign)
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

	waitFor(t, 5*time.Second, "local bridge error", func() bool {
		for _, b := range tm.m.store.GetBridges() {
			if b.ID == "loc/local/dest/localhost:8080" && b.Status == state.BridgeStatusError {
				return strings.HasPrefix(b.Error, "name conflict")
			}
		}
		return false
	})
	cancel()
	<-done

	if w := tm.dest.Writes(); len(w) != 0 {
		t.Errorf("writes = %v, want none", callStrings(w))
	}
	if svc, _ := tm.dest.Service("svc:app"); !reflect.DeepEqual(svc, foreign) {
		t.Errorf("foreign service changed: %+v", svc)
	}
}

// On a stop, releasing the last reference to a shared DNS zone only stops
// the listener: the DNS VIP and split-DNS stay.
func TestReleaseSharedDNSStopKeepsService(t *testing.T) {
	tm := newTestManager(t)
	sharedDNSFixture(tm, 2, map[string]string{"tailnetlink/owner": testOwner}, "100.100.0.53")
	tm.m.releaseSharedDNS("dest", "src.example", "web-1", false)
	tm.m.releaseSharedDNS("dest", "src.example", "web-2", false)
	if w := tm.dest.Writes(); len(w) != 0 {
		t.Errorf("writes = %v, want none", callStrings(w))
	}
	if _, ok := tm.m.sharedDNS["dest/src.example"]; ok {
		t.Error("zone still held after the last release")
	}
	if !tm.dest.HasZone("src.example") {
		t.Error("split-DNS zone removed on stop")
	}
}

// On a remove, the last release deletes the DNS VIP and the split-DNS entry.
func TestReleaseSharedDNSRemoveDeletesOnLastRef(t *testing.T) {
	tm := newTestManager(t)
	sharedDNSFixture(tm, 2, map[string]string{"tailnetlink/owner": testOwner}, "100.100.0.53")

	tm.m.releaseSharedDNS("dest", "src.example", "web-1", true)
	if w := tm.dest.Writes(); len(w) != 0 {
		t.Fatalf("writes with refs remaining: %v", callStrings(w))
	}
	tm.m.releaseSharedDNS("dest", "src.example", "web-2", true)
	got := callStrings(tm.dest.Writes())
	want := []string{"DELETE /vip-services/svc:tnl-dns-src-example-dns", "PATCH /dns/split-dns"}
	if !slices.Equal(got, want) {
		t.Errorf("writes = %v, want %v", got, want)
	}
	if tm.dest.HasZone("src.example") {
		t.Error("split-DNS zone still there")
	}
}

// sharedDNSFixture puts one shared DNS zone with refs references into the
// manager, backed by a DNS VIP with the given annotations.
func sharedDNSFixture(tm *testManager, refs int, annotations map[string]string, resolvers ...string) {
	const zone = "src.example"
	tm.dest.PutService(tsclient.VIPService{Name: "svc:tnl-dns-src-example-dns", Addrs: []string{resolvers[0]}, Annotations: annotations})
	tm.dest.SetSplitDNS(zone, resolvers)
	client := tm.m.apiClients["dest"]
	ds := NewDNSServer(nil, client, "dns-src-example", nil, testOwner, zone, discardLogger())
	ds.svcName = "svc:tnl-dns-src-example-dns"
	tm.m.sharedDNS["dest/"+zone] = &sharedDNSEntry{
		server: ds,
		sdns:   NewSplitDNSConfigurator(client, zone, resolvers[0], discardLogger()),
		refs:   refs,
	}
}

// Removing our resolver leaves a resolver someone else added to the same
// zone in place.
func TestReleaseSharedDNSKeepsForeignResolver(t *testing.T) {
	tm := newTestManager(t)
	sharedDNSFixture(tm, 1, map[string]string{"tailnetlink/owner": testOwner}, "100.100.0.53", "100.99.0.1")
	tm.m.releaseSharedDNS("dest", "src.example", "web-1", true)
	if got := tm.dest.SplitDNS("src.example"); !slices.Equal(got, []string{"100.99.0.1"}) {
		t.Errorf("resolvers = %v, want only the foreign one", got)
	}
}

// If the DNS VIP is no longer ours, neither it nor its split-DNS entry is
// touched.
func TestReleaseSharedDNSLeavesForeignDNSService(t *testing.T) {
	tm := newTestManager(t)
	sharedDNSFixture(tm, 1, map[string]string{"tailnetlink/owner": "someone-else"}, "100.100.0.53")
	tm.m.releaseSharedDNS("dest", "src.example", "web-1", true)
	if w := tm.dest.Writes(); len(w) != 0 {
		t.Errorf("writes = %v, want none", callStrings(w))
	}
	if !tm.dest.HasZone("src.example") {
		t.Error("split-DNS zone was removed")
	}
}

// A foreign service with the UI's name keeps the UI from being published in
// that tailnet, and is left alone.
func TestWebUIRefusesForeignService(t *testing.T) {
	tm := newTestManager(t)
	foreign := tsclient.VIPService{Name: "svc:tailnetlink", Addrs: []string{"100.100.8.8"}, Comment: "someone else's"}
	tm.dest.PutService(foreign)
	tm.m.serveWebUI(context.Background(), "dest", nil, tm.m.apiClients["dest"], []string{"tag:bridge"})
	if w := tm.dest.Writes(); len(w) != 0 {
		t.Errorf("writes = %v, want none", callStrings(w))
	}
	if svc, _ := tm.dest.Service("svc:tailnetlink"); !reflect.DeepEqual(svc, foreign) {
		t.Errorf("foreign service changed: %+v", svc)
	}
	found := false
	for _, l := range tm.m.store.GetLogs(10) {
		found = found || (l.Level == "error" && strings.Contains(l.Message, "web UI not published") && strings.Contains(l.Message, "name conflict"))
	}
	if !found {
		t.Error("conflict not reported")
	}
}

// Any other failure creating the UI service is a warning, not a conflict.
func TestWebUICreateError(t *testing.T) {
	tm := newTestManager(t)
	tm.dest.Fail("GET", "/vip-services/svc:tailnetlink", 500)
	tm.m.serveWebUI(context.Background(), "dest", nil, tm.m.apiClients["dest"], nil)
	if w := tm.dest.Writes(); len(w) != 0 {
		t.Errorf("writes = %v, want none", callStrings(w))
	}
}
