package bridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/metrics"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	"github.com/rajsinghtech/tailnetlink/internal/testutil/fakeapi"
	tsclient "tailscale.com/client/tailscale/v2"
	"tailscale.com/tsnet"
)

func sideJSON(tailnet, id, base string, extra string) string {
	s := fmt.Sprintf(`"tailnet": %q, "oauth": {"client_id": %q, "client_secret_env": "TNL_MULTI_SECRET"}, "tags": ["tag:tailnetlink"]`, tailnet, id)
	if base != "" {
		s += fmt.Sprintf(`, "api_base_url": %q`, base)
	}
	if extra != "" {
		s += ", " + extra
	}
	return "{" + s + "}"
}

func parseMulti(t *testing.T, dests string) *config.Config {
	t.Helper()
	body := `{
		"name": "edge",
		"source": ` + sideJSON("keiretsu.ts.net", "src", "", "") + `,
		"dests": [` + dests + `],
		"links": [{"name": "web", "tag": "tag:web", "ports": [80], "authz": {"mode": "off"}}]
	}`
	cfg, err := config.Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	cfg.PollInterval = config.Duration{Duration: time.Hour}
	cfg.DialTimeout = config.Duration{Duration: time.Second}
	return cfg
}

func destKeyFor(tailnet string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(tailnet)))
	return "edge-dst-" + hex.EncodeToString(sum[:2])
}

func seedTailnet(m *Manager, key string, api *fakeapi.Server) {
	m.servers[key] = &tsnet.Server{}
	m.apiClients[key] = api.Client()
}

func adopt(m *Manager, cfg *config.Config) {
	m.owner = cfg.InstanceID
	m.uiService = cfg.UIServiceName()
}

func devicePolls(api *fakeapi.Server) int {
	n := 0
	for _, c := range api.Calls() {
		if c.Method == "GET" && c.Path == "/devices" {
			n++
		}
	}
	return n
}

func TestDestStateDirsDoNotCollide(t *testing.T) {
	m := New(state.New(), discardLogger(), nil)
	root := t.TempDir()
	single, err := m.nodeDir("edge-dst", config.TailnetConfig{}, root)
	if err != nil {
		t.Fatal(err)
	}
	hashed, err := m.nodeDir(destKeyFor("example.ts.net"), config.TailnetConfig{}, root)
	if err != nil {
		t.Fatal(err)
	}
	other, err := m.nodeDir(destKeyFor("partner.example.com"), config.TailnetConfig{}, root)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(single) != "edge-dst" {
		t.Errorf("single dest dir = %s", single)
	}
	if single == hashed || hashed == other || filepath.Base(hashed) == "edge-dst" {
		t.Fatalf("dirs collided: %s %s %s", single, hashed, other)
	}
	for _, key := range []string{"edge-dst", destKeyFor("example.ts.net"), destKeyFor("partner.example.com")} {
		host := "tailnetlink-" + key
		if len(host) > 63 {
			t.Errorf("hostname %q is %d bytes", host, len(host))
		}
	}
	if destKeyFor("example.ts.net") == destKeyFor("partner.example.com") {
		t.Fatal("distinct tailnets hashed to one key")
	}
}

func TestOneDestFailureStillServes(t *testing.T) {
	stubForwarders(t)
	t.Setenv("TNL_MULTI_SECRET", "secret")
	good := fakeapi.New(t)
	good.Tailnet = "example.ts.net"
	good.AssignAddrs = false
	bad := fakeapi.New(t)
	bad.Tailnet = "partner.example.com"
	bad.Fail("POST", "/keys", 401)
	src := fakeapi.New(t)
	src.Tailnet = "keiretsu.ts.net"
	src.SetDevices([]tsclient.Device{{
		NodeID: "n1", Name: "web-1.keiretsu.ts.net", Hostname: "web-1",
		Tags: []string{"tag:web"}, Addresses: []string{"100.64.0.1"},
	}})

	cfg := parseMulti(t, sideJSON("example.ts.net", "ex", good.URL(), `"authz": {"mode": "allow_logins", "allow_logins": ["alice@example.com"]}`)+","+
		sideJSON("partner.example.com", "pa", bad.URL(), ""))
	goodKey, badKey := destKeyFor("example.ts.net"), destKeyFor("partner.example.com")

	m := New(state.New(), discardLogger(), nil)
	adopt(m, cfg)
	seedTailnet(m, "edge-src", src)
	seedTailnet(m, goodKey, good)
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	m.Reconcile(context.Background(), cfg)
	id := "web/" + goodKey + "/web-1.keiretsu.ts.net"
	waitFor(t, 5*time.Second, "good dest bridge", func() bool {
		for _, b := range m.store.GetBridges() {
			if b.ID == id && b.Status == state.BridgeStatusActive {
				return true
			}
		}
		return false
	})

	if _, ok := good.Service("svc:tnl-edge-src-web-1"); !ok {
		t.Fatal("healthy dest has no VIP")
	}
	if names := bad.ServiceNames(); len(names) != 0 {
		t.Errorf("failed dest has services %v", names)
	}
	if devicePolls(src) != 1 {
		t.Errorf("source device polls = %d, want 1", devicePolls(src))
	}
	m.mu.Lock()
	_, badUp := m.servers[badKey]
	err := m.tailnetErr[badKey]
	m.mu.Unlock()
	if badUp || err == nil {
		t.Fatalf("bad dest up=%v err=%v", badUp, err)
	}
	var labeled bool
	for _, b := range m.store.GetBridges() {
		if b.ID == id {
			labeled = b.DestTailnet == "example.ts.net"
			if b.DestTailnet != "example.ts.net" {
				t.Errorf("bridge label = %q", b.DestTailnet)
			}
		}
		if strings.Contains(b.ID, badKey) {
			t.Errorf("failed dest has a bridge %s", b.ID)
		}
	}
	if !labeled {
		t.Fatal("bridge not labeled with the dest tailnet")
	}
	m.mu.Lock()
	az := m.forwarders[id].authz
	m.mu.Unlock()
	if az.Mode != config.AuthzAllowLogins || len(az.AllowLogins) != 1 {
		t.Errorf("per-dest authz = %+v", az)
	}
	if err := m.Ready(); err != nil {
		t.Fatalf("ready with one healthy dest: %v", err)
	}
	for _, tn := range m.store.GetStatus().Tailnets {
		if tn.ID != badKey {
			continue
		}
		if tn.Name != "partner.example.com" || tn.Role != "dest" || tn.Connected {
			t.Errorf("failed dest status = %+v", tn)
		}
	}
}

func TestOneDestAPIFailureStillServes(t *testing.T) {
	stubForwarders(t)
	good := fakeapi.New(t)
	good.Tailnet = "example.ts.net"
	good.AssignAddrs = false
	bad := fakeapi.New(t)
	bad.Tailnet = "partner.example.com"
	bad.AssignAddrs = false
	bad.Fail("PUT", "/vip-services/svc:tnl-edge-src-web-1", 500)
	src := fakeapi.New(t)
	src.Tailnet = "keiretsu.ts.net"
	src.SetDevices([]tsclient.Device{{
		NodeID: "n1", Name: "web-1.keiretsu.ts.net", Hostname: "web-1",
		Tags: []string{"tag:web"}, Addresses: []string{"100.64.0.1"},
	}})

	cfg := parseMulti(t, sideJSON("example.ts.net", "ex", "", "")+","+sideJSON("partner.example.com", "pa", "", ""))
	goodKey, badKey := destKeyFor("example.ts.net"), destKeyFor("partner.example.com")
	m := New(state.New(), discardLogger(), nil)
	adopt(m, cfg)
	seedTailnet(m, "edge-src", src)
	seedTailnet(m, goodKey, good)
	seedTailnet(m, badKey, bad)
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	m.Reconcile(context.Background(), cfg)
	goodID := "web/" + goodKey + "/web-1.keiretsu.ts.net"
	badID := "web/" + badKey + "/web-1.keiretsu.ts.net"
	waitFor(t, 5*time.Second, "good dest active", func() bool {
		for _, b := range m.store.GetBridges() {
			if b.ID == goodID && b.Status == state.BridgeStatusActive {
				return true
			}
		}
		return false
	})
	waitFor(t, 5*time.Second, "bad dest error", func() bool {
		for _, b := range m.store.GetBridges() {
			if b.ID == badID && b.Status == state.BridgeStatusError {
				return true
			}
		}
		return false
	})
	if _, ok := good.Service("svc:tnl-edge-src-web-1"); !ok {
		t.Fatal("healthy dest lost its VIP")
	}
	if _, ok := bad.Service("svc:tnl-edge-src-web-1"); ok {
		t.Fatal("failed dest kept a VIP")
	}
	if devicePolls(src) != 1 {
		t.Errorf("source device polls = %d, want 1", devicePolls(src))
	}
}

func TestHotReloadAddAndRemoveDest(t *testing.T) {
	stubForwarders(t)
	src := fakeapi.New(t)
	src.Tailnet = "keiretsu.ts.net"
	src.SetDevices([]tsclient.Device{{
		NodeID: "n1", Name: "web-1.keiretsu.ts.net", Hostname: "web-1",
		Tags: []string{"tag:web"}, Addresses: []string{"100.64.0.1"},
	}})
	first := fakeapi.New(t)
	first.Tailnet = "example.ts.net"
	first.AssignAddrs = false
	second := fakeapi.New(t)
	second.Tailnet = "partner.example.com"
	second.AssignAddrs = false

	one := parseMulti(t, sideJSON("example.ts.net", "ex", "", ""))
	two := parseMulti(t, sideJSON("example.ts.net", "ex", "", "")+","+sideJSON("partner.example.com", "pa", "", ""))
	firstKey, secondKey := destKeyFor("example.ts.net"), destKeyFor("partner.example.com")
	if one.Tailnets[firstKey].Tailnet != "example.ts.net" || two.Tailnets[firstKey].Tailnet != "example.ts.net" {
		t.Fatalf("adding a dest changed the first key: %+v %+v", one.Tailnets, two.Tailnets)
	}

	m := New(state.New(), discardLogger(), nil)
	adopt(m, one)
	seedTailnet(m, "edge-src", src)
	seedTailnet(m, firstKey, first)
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	ctx := context.Background()
	m.Reconcile(ctx, one)
	firstID := "web/" + firstKey + "/web-1.keiretsu.ts.net"
	waitFor(t, 5*time.Second, "first dest", func() bool {
		for _, b := range m.store.GetBridges() {
			if b.ID == firstID && b.Status == state.BridgeStatusActive {
				return true
			}
		}
		return false
	})

	seedTailnet(m, secondKey, second)
	m.Reconcile(ctx, two)
	secondID := "web/" + secondKey + "/web-1.keiretsu.ts.net"
	waitFor(t, 5*time.Second, "second dest", func() bool {
		for _, b := range m.store.GetBridges() {
			if b.ID == secondID && b.Status == state.BridgeStatusActive {
				return true
			}
		}
		return false
	})
	if _, ok := first.Service("svc:tnl-edge-src-web-1"); !ok {
		t.Fatal("first dest lost its VIP when a dest was added")
	}
	if _, ok := second.Service("svc:tnl-edge-src-web-1"); !ok {
		t.Fatal("added dest has no VIP")
	}

	second.ResetCalls()
	m.Reconcile(ctx, one)
	waitFor(t, 5*time.Second, "first dest still active", func() bool {
		for _, b := range m.store.GetBridges() {
			if b.ID == firstID && b.Status == state.BridgeStatusActive {
				return true
			}
		}
		return false
	})
	if _, ok := second.Service("svc:tnl-edge-src-web-1"); ok {
		t.Fatal("removed dest kept its VIP")
	}
	if _, ok := first.Service("svc:tnl-edge-src-web-1"); !ok {
		t.Fatal("remaining dest lost its VIP")
	}
	for _, b := range m.store.GetBridges() {
		if strings.Contains(b.ID, secondKey) {
			t.Errorf("removed dest still has bridge %s", b.ID)
		}
	}
	deleted := false
	for _, w := range second.Writes() {
		if w.Method == "DELETE" && strings.Contains(w.Path, "svc:tnl-edge-src-web-1") {
			deleted = true
		}
	}
	if !deleted {
		t.Fatalf("removed dest writes = %v", callStrings(second.Writes()))
	}
}

func TestLocalRuleSkipsDownDest(t *testing.T) {
	stubForwarders(t)
	good := fakeapi.New(t)
	good.Tailnet = "example.ts.net"
	good.AssignAddrs = false
	m := New(state.New(), discardLogger(), nil)
	m.owner = testOwner
	goodKey, badKey := destKeyFor("example.ts.net"), destKeyFor("partner.example.com")
	m.servers[goodKey] = &tsnet.Server{}
	m.apiClients[goodKey] = good.Client()
	m.cfg = &config.Config{Tailnets: map[string]config.TailnetConfig{
		goodKey: {Tailnet: "example.ts.net", Tags: []string{"tag:bridge"}, Role: "dest"},
		badKey:  {Tailnet: "partner.example.com", Tags: []string{"tag:bridge"}, Role: "dest"},
	}}
	rule := config.BridgeRule{
		Name: "loc", DestTailnets: []string{badKey, goodKey},
		LocalSources: []config.LocalSourceSpec{{Addr: "127.0.0.1:3000", DNSName: "app.example.com"}},
		Authz:        config.AuthzConfig{Mode: config.AuthzOff},
	}
	m.cfg.Tailnets[goodKey] = config.TailnetConfig{
		Tailnet: "example.ts.net", Tags: []string{"tag:bridge"}, Role: "dest",
		Authz: config.AuthzConfig{Mode: config.AuthzAllowTags, AllowTags: []string{"tag:eng"}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.runLocalRule(ctx, rule, time.Second)
	}()
	id := "loc/local/" + goodKey + "/127.0.0.1:3000"
	waitFor(t, 5*time.Second, "local bridge", func() bool {
		for _, b := range m.store.GetBridges() {
			if b.ID == id && b.Status == state.BridgeStatusActive && b.DestTailnet == "example.ts.net" {
				return true
			}
		}
		return false
	})
	names := good.ServiceNames()
	if len(names) != 1 {
		t.Fatalf("services = %v", names)
	}
	svc, ok := good.Service(names[0])
	if !ok || svc.Annotations[annotationBridge] != rule.BridgeRef(goodKey) {
		t.Fatalf("bridge annotation = %v, want %s", svc.Annotations, rule.BridgeRef(goodKey))
	}
	for _, b := range m.store.GetBridges() {
		if strings.Contains(b.ID, badKey) {
			t.Errorf("down dest has bridge %s", b.ID)
		}
	}
	m.mu.Lock()
	az := m.forwarders[id].authz
	m.mu.Unlock()
	if az.Mode != config.AuthzAllowTags {
		t.Errorf("local authz = %+v", az)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("local rule did not stop")
	}
}

func TestReadyFailedDestDoesNotBlock(t *testing.T) {
	m := New(state.New(), discardLogger(), nil)
	m.mu.Lock()
	m.applied = true
	m.cfg = &config.Config{
		PollInterval: config.Duration{Duration: time.Second},
		Tailnets: map[string]config.TailnetConfig{
			"src": {Role: "source", Tailnet: "keiretsu.ts.net"},
			"ok":  {Role: "dest", Tailnet: "example.ts.net"},
			"bad": {Role: "dest", Tailnet: "partner.example.com"},
		},
		Bridges: []config.BridgeRule{{Name: "web", SourceTailnet: "src", DestTailnets: []string{"ok", "bad"}}},
	}
	m.servers["src"] = &tsnet.Server{}
	m.servers["ok"] = &tsnet.Server{}
	m.tailnetErr["bad"] = errors.New("auth failed")
	m.lastPoll["web"] = time.Now()
	m.mu.Unlock()
	if err := m.Ready(); err != nil {
		t.Fatalf("one failed dest: %v", err)
	}

	m.mu.Lock()
	delete(m.tailnetErr, "bad")
	m.mu.Unlock()
	if err := m.Ready(); err == nil || !strings.Contains(err.Error(), `"bad"`) {
		t.Fatalf("dest still starting: %v", err)
	}

	m.mu.Lock()
	delete(m.servers, "ok")
	m.tailnetErr["ok"] = errors.New("down")
	m.tailnetErr["bad"] = errors.New("down")
	m.mu.Unlock()
	if err := m.Ready(); err == nil || !strings.Contains(err.Error(), "no destination") {
		t.Fatalf("every dest failed: %v", err)
	}

	m.mu.Lock()
	m.servers["ok"] = &tsnet.Server{}
	delete(m.tailnetErr, "ok")
	delete(m.servers, "src")
	m.mu.Unlock()
	if err := m.Ready(); err == nil || !strings.Contains(err.Error(), `"src"`) {
		t.Fatalf("source down: %v", err)
	}
}

func TestConflictMetricUsesTailnetName(t *testing.T) {
	m := New(state.New(), discardLogger(), nil)
	mt := metrics.New()
	m.SetMetrics(mt)
	m.cfg.Tailnets["edge-dst-ab12"] = config.TailnetConfig{Tailnet: "example.ts.net"}
	m.conflict("edge-dst-ab12", &ConflictError{Service: "svc:x"})

	mfs, err := mt.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	var got string
	for _, mf := range mfs {
		if mf.GetName() != "tailnetlink_ownership_conflicts_total" {
			continue
		}
		for _, series := range mf.GetMetric() {
			if series.GetCounter().GetValue() == 0 {
				continue
			}
			for _, l := range series.GetLabel() {
				if l.GetName() == "tailnet" {
					got = l.GetValue()
				}
			}
		}
	}
	if got != "example.ts.net" {
		t.Fatalf("conflict label = %q", got)
	}
}

func TestSweepIdleDropsWhileRuleIsDown(t *testing.T) {
	stubForwarders(t)
	api := fakeapi.New(t)
	api.Tailnet = "example.ts.net"
	own := map[string]string{"tailnetlink/owner": testOwner}
	api.PutService(tsclient.VIPService{Name: "svc:app", Annotations: own})
	api.PutService(tsclient.VIPService{Name: "svc:theirs", Annotations: map[string]string{"tailnetlink/owner": "other"}})
	m := New(state.New(), discardLogger(), nil)
	m.owner = testOwner
	key := destKeyFor("example.ts.net")
	m.apiClients[key] = api.Client()
	m.store.UpsertBridge(state.BridgeEntry{
		ID: "web/" + key + "/host.example.com", RuleName: "web", ServiceName: "svc:app",
	})
	m.store.UpsertBridge(state.BridgeEntry{
		ID: "web/local/" + key + "/127.0.0.1:1", RuleName: "web", ServiceName: "svc:app",
	})
	m.store.UpsertBridge(state.BridgeEntry{
		ID: "other/" + key + "/host.example.com", RuleName: "other", ServiceName: "svc:theirs",
	})
	m.markDropDest("web", key)
	if _, ok := api.Service("svc:app"); ok {
		t.Fatal("owned service kept after the dest left")
	}
	if _, ok := api.Service("svc:theirs"); !ok {
		t.Fatal("another owner's service was deleted")
	}
	for _, b := range m.store.GetBridges() {
		if b.RuleName == "web" {
			t.Errorf("bridge left behind: %+v", b)
		}
	}
	m.mu.Lock()
	if len(m.dropDest["web"]) != 0 {
		t.Errorf("drops left = %v", m.dropDest["web"])
	}
	m.rules["web"] = func() {}
	m.dropDest["web"] = map[string]bool{key: true}
	m.mu.Unlock()
	m.sweepIdleDrops("web")
	m.mu.Lock()
	if !m.dropDest["web"][key] {
		t.Fatal("sweep cleared drops for a running rule")
	}
	m.mu.Unlock()

	if tailnetLabel(config.TailnetConfig{}, "k") != "k" || tailnetRole(config.TailnetConfig{}, "k") != "k" {
		t.Fatal("empty role or tailnet should fall back to the key")
	}
	bare := New(state.New(), discardLogger(), nil)
	bare.cfg = nil
	if bare.tailnetLabel("k") != "k" {
		t.Fatal("nil config label")
	}
	if got := bare.authzFor(config.BridgeRule{Authz: config.AuthzConfig{Mode: config.AuthzOff}}, "k"); got.Mode != config.AuthzOff {
		t.Fatalf("nil config authz = %+v", got)
	}
	bare.cfg = &config.Config{Tailnets: map[string]config.TailnetConfig{
		"k": {Authz: config.AuthzConfig{}},
	}}
	if got := bare.authzFor(config.BridgeRule{Authz: config.AuthzConfig{Mode: config.AuthzRequireCap}}, "k"); got.Mode != config.AuthzRequireCap {
		t.Fatalf("link authz = %+v", got)
	}
	if drop := bare.takeDrops("missing"); len(drop) != 0 {
		t.Fatalf("takeDrops = %v", drop)
	}

	st := state.New()
	st.SetTailnet("edge-src", state.TailnetStatus{Connected: true})
	var stamped *state.TailnetStatus
	for _, tn := range st.GetStatus().Tailnets {
		if tn.Connected {
			stamped = tn
		}
	}
	if stamped == nil || stamped.ID != "edge-src" || stamped.Name != "edge-src" {
		t.Fatalf("status = %+v", stamped)
	}
}

func TestPerDestDNSOff(t *testing.T) {
	m := New(state.New(), discardLogger(), nil)
	m.cfg = &config.Config{Tailnets: map[string]config.TailnetConfig{
		"edge-dst-ab12": {Tailnet: "example.ts.net", DNSDisabled: true},
	}}
	m.startDeviceDNS(context.Background(), "web/edge-dst-ab12/host.example.com", "web", "keiretsu.ts.net", "host.keiretsu.ts.net", "", "", "", netip.MustParseAddr("100.100.0.1"), destCtx{name: "edge-dst-ab12"})
	if len(m.dnsCleanups) != 0 {
		t.Fatal("dest with dns off still registered DNS")
	}
}
