package bridge

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/metrics"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	"github.com/rajsinghtech/tailnetlink/internal/testutil/fakeapi"
	tsclient "tailscale.com/client/tailscale/v2"
	"tailscale.com/tsnet"
)

func meshTailnetJSON(name, id string) string {
	return `"` + name + `": {
		"tailnet": "` + id + `",
		"auth": {"client_id": "` + name + `", "client_secret_file": "/run/` + name + `"},
		"tags": ["tag:tailnetlink"]
	}`
}

func parseMesh(t *testing.T, targets, exports string) *config.Config {
	t.Helper()
	body := `{
		"name": "mesh",
		"dns": false,
		"tailnets": {
			` + meshTailnetJSON("home", "keiretsu.ts.net") + `,
			` + meshTailnetJSON("work", "example.ts.net") + `,
			` + meshTailnetJSON("partner", "partner.example.com") + `
		},
		"targets": {` + targets + `},
		"exports": [` + exports + `]
	}`
	cfg, err := config.Parse([]byte(body))
	if err != nil {
		t.Fatalf("parse mesh: %v\n%s", err, body)
	}
	cfg.PollInterval = config.Duration{Duration: time.Hour}
	cfg.DialTimeout = config.Duration{Duration: time.Second}
	return cfg
}

func foreignService(name, addr string) tsclient.VIPService {
	return tsclient.VIPService{
		Name:    name,
		Addrs:   []string{addr},
		Comment: "not tailnetlink",
		Ports:   []string{"tcp:9"},
		Tags:    []string{"tag:user"},
	}
}

func TestSharedNodesLeaveForeignResources(t *testing.T) {
	stubForwarders(t)
	homeAPI := fakeapi.New(t)
	homeAPI.Tailnet = "keiretsu.ts.net"
	homeAPI.AssignAddrs = false
	workAPI := fakeapi.New(t)
	workAPI.Tailnet = "example.ts.net"
	workAPI.AssignAddrs = false
	partnerAPI := fakeapi.New(t)
	partnerAPI.Tailnet = "partner.example.com"
	partnerAPI.AssignAddrs = false

	homeDevs := []tsclient.Device{
		dev("colleague", []string{"tag:user"}, "100.64.0.9"),
		dev("api", []string{"tag:api-server"}, "100.64.0.1"),
		dev("other", nil, "100.64.0.2"),
	}
	workDevs := []tsclient.Device{
		dev("colleague", []string{"tag:user"}, "100.64.1.9"),
		dev("build", []string{"tag:build-runner"}, "100.64.1.1"),
	}
	partnerDevs := []tsclient.Device{
		dev("colleague", []string{"tag:user"}, "100.64.2.9"),
		dev("billing", nil, "100.64.2.1"),
	}
	homeAPI.SetDevices(homeDevs)
	workAPI.SetDevices(workDevs)
	partnerAPI.SetDevices(partnerDevs)

	homeForeign := foreignService("svc:unrelated", "100.80.0.1")
	workForeign := foreignService("svc:unrelated", "100.80.0.2")
	taken := foreignService("svc:taken", "100.80.0.3")
	partnerForeign := foreignService("svc:unrelated", "100.80.0.4")
	real := tsclient.VIPService{Name: "svc:real", Addrs: []string{"100.90.0.1"}, Tags: []string{"tag:tailnetlink"}, Comment: "a real service"}
	homeAPI.PutService(homeForeign)
	workAPI.PutService(workForeign)
	workAPI.PutService(taken)
	workAPI.PutService(real)
	partnerAPI.PutService(partnerForeign)
	for _, api := range []*fakeapi.Server{homeAPI, workAPI, partnerAPI} {
		api.SetSplitDNS("other.example.com", []string{"9.9.9.9"})
	}
	workAPI.SetSplitDNS("app.example.com", []string{"192.0.2.1"})

	homeSrv, workSrv, partnerSrv := &tsnet.Server{}, &tsnet.Server{}, &tsnet.Server{}
	m := New(state.New(), discardLogger(), nil)
	m.servers["home"] = homeSrv
	m.servers["work"] = workSrv
	m.servers["partner"] = partnerSrv
	m.apiClients["home"] = homeAPI.Client()
	m.apiClients["work"] = workAPI.Client()
	m.apiClients["partner"] = partnerAPI.Client()

	t.Cleanup(func() { _ = m.Close(context.Background()) })

	initial := parseMesh(t, `
			"api": {"in": "home", "device": "api.src.example", "ports": [8080]},
			"db": {"in": "pod", "addr": "10.1.0.5", "ports": [5432]},
			"taken": {"in": "home", "device": "other.src.example", "ports": [9]},
			"billing": {"in": "partner", "device": "billing.src.example", "ports": [8443]}
		`, `
		{"target": "api", "to": ["work", "partner"]},
		{"target": "db", "to": ["work"], "dns_name": "db.example.com"},
		{"target": "taken", "to": ["work"], "name": "taken"},
		{"target": "billing", "to": ["work"]}
	`)
	adopt(m, initial)
	m.cfg = initial.Clone()
	m.Reconcile(context.Background(), initial)

	waitFor(t, 5*time.Second, "api bridge on work", func() bool {
		st, _ := bridgeState(m, "api/api/work/api.src.example")
		return st == state.BridgeStatusActive
	})
	waitFor(t, 5*time.Second, "api bridge on partner", func() bool {
		st, _ := bridgeState(m, "api/api/partner/api.src.example")
		return st == state.BridgeStatusActive
	})
	waitFor(t, 5*time.Second, "name conflict", func() bool {
		_, errText := bridgeState(m, "taken/taken/work/other.src.example")
		return strings.Contains(errText, "conflict")
	})
	waitFor(t, 5*time.Second, "partner billing bridge", func() bool {
		st, _ := bridgeState(m, "billing/billing/work/billing.src.example")
		return st == state.BridgeStatusActive
	})

	if m.servers["home"] != homeSrv || m.servers["work"] != workSrv || m.servers["partner"] != partnerSrv {
		t.Fatal("startup replaced a shared node")
	}
	if _, ok := workAPI.Service("svc:api"); !ok {
		t.Fatal("work did not get the bridged service")
	}
	if _, ok := partnerAPI.Service("svc:api"); !ok {
		t.Fatal("partner did not get the bridged service")
	}
	if devicePolls(homeAPI) != 1 {
		t.Errorf("home polls = %d, want 1 shared poll for every bridge leaving home", devicePolls(homeAPI))
	}
	assertForeign(t, homeAPI, homeDevs, map[string]tsclient.VIPService{"svc:unrelated": homeForeign}, map[string][]string{"other.example.com": {"9.9.9.9"}})
	assertForeign(t, workAPI, workDevs, map[string]tsclient.VIPService{
		"svc:unrelated": workForeign,
		"svc:taken":     taken,
		"svc:real":      real,
	}, map[string][]string{"other.example.com": {"9.9.9.9"}, "app.example.com": {"192.0.2.1"}})
	assertForeign(t, partnerAPI, partnerDevs, map[string]tsclient.VIPService{"svc:unrelated": partnerForeign}, map[string][]string{"other.example.com": {"9.9.9.9"}})
	assertNoForeignWrites(t, homeAPI)
	assertNoForeignWrites(t, workAPI)
	assertNoForeignWrites(t, partnerAPI)

	if got := m.AcceptedRoutes("home"); len(got) != 0 {
		t.Fatalf("pod local entries installed subnet routes: %v", got)
	}

	// Adding a bridge reuses the nodes and recomputes route acceptance.
	withReturn := parseMesh(t, `
			"api": {"in": "home", "device": "api.src.example", "ports": [8080]},
			"db": {"in": "pod", "addr": "10.1.0.5", "ports": [5432]},
			"cache": {"in": "pod", "addr": "10.9.9.9", "ports": [80]},
			"taken": {"in": "home", "device": "other.src.example", "ports": [9]},
			"builds": {"in": "work", "device": "build.src.example", "ports": [8022]},
			"loop": {"in": "work", "tag": "tag:tailnetlink", "ports": [443]},
			"billing": {"in": "partner", "device": "billing.src.example", "ports": [8443]}
		`, `
		{"target": "api", "to": ["work", "partner"]},
		{"target": "db", "to": ["work"], "dns_name": "db.example.com"},
		{"target": "cache", "to": ["work"], "dns_name": "cache.example.com"},
		{"target": "taken", "to": ["work"], "name": "taken"},
		{"target": "builds", "to": ["home"]},
		{"target": "loop", "to": ["home"]},
		{"target": "billing", "to": ["work"]}
	`)
	m.Reconcile(context.Background(), withReturn)
	waitFor(t, 5*time.Second, "return bridge", func() bool {
		st, _ := bridgeState(m, "builds/builds/home/build.src.example")
		return st == state.BridgeStatusActive
	})
	waitFor(t, 5*time.Second, "real service exported once", func() bool {
		_, ok := homeAPI.Service("svc:loop-real")
		return ok
	})
	if _, ok := homeAPI.Service("svc:loop-api"); ok {
		t.Fatal("managed VIP was re-exported back to its source tailnet")
	}
	if _, ok := homeAPI.Service("svc:loop-unrelated"); ok {
		t.Fatal("foreign service was re-exported")
	}
	if m.servers["home"] != homeSrv || m.servers["work"] != workSrv || m.servers["partner"] != partnerSrv {
		t.Fatal("adding a bridge restarted a node")
	}
	if got := m.AcceptedRoutes("home"); len(got) != 0 {
		t.Fatalf("pod local entries installed subnet routes after reload: %v", got)
	}
	assertForeign(t, homeAPI, homeDevs, map[string]tsclient.VIPService{"svc:unrelated": homeForeign}, map[string][]string{"other.example.com": {"9.9.9.9"}})
	assertForeign(t, workAPI, workDevs, map[string]tsclient.VIPService{
		"svc:unrelated": workForeign,
		"svc:taken":     taken,
		"svc:real":      real,
	}, map[string][]string{"other.example.com": {"9.9.9.9"}, "app.example.com": {"192.0.2.1"}})

	// Removing the partner tailnet drops only the bridges that used it.
	withoutPartner := parseMesh(t, `
			"api": {"in": "home", "device": "api.src.example", "ports": [8080]},
			"db": {"in": "pod", "addr": "10.1.0.5", "ports": [5432]},
			"builds": {"in": "work", "device": "build.src.example", "ports": [8022]}
		`, `
		{"target": "api", "to": ["work"]},
		{"target": "db", "to": ["work"], "dns_name": "db.example.com"},
		{"target": "builds", "to": ["home"]}
	`)
	// Nothing references partner, so compile omits it. Drop it again in case
	// a future compile keeps unused tailnets.
	delete(withoutPartner.Tailnets, "partner")
	m.Reconcile(context.Background(), withoutPartner)
	waitFor(t, 5*time.Second, "partner node stopped", func() bool {
		m.mu.Lock()
		_, up := m.servers["partner"]
		m.mu.Unlock()
		return !up
	})
	if m.servers["home"] != homeSrv || m.servers["work"] != workSrv {
		t.Fatal("removing partner restarted another node")
	}
	if _, ok := partnerAPI.Service("svc:api"); ok {
		t.Fatal("partner still has a VIP this process published")
	}
	if _, ok := workAPI.Service("svc:billing"); ok {
		t.Fatal("work still has the partner bridge VIP")
	}
	if _, ok := workAPI.Service("svc:api"); !ok {
		t.Fatal("removing partner deleted the work VIP")
	}
	assertForeign(t, partnerAPI, partnerDevs, map[string]tsclient.VIPService{"svc:unrelated": partnerForeign}, map[string][]string{"other.example.com": {"9.9.9.9"}})
	assertForeign(t, workAPI, workDevs, map[string]tsclient.VIPService{
		"svc:unrelated": workForeign,
		"svc:taken":     taken,
		"svc:real":      real,
	}, map[string][]string{"other.example.com": {"9.9.9.9"}, "app.example.com": {"192.0.2.1"}})

	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertForeign(t, homeAPI, homeDevs, map[string]tsclient.VIPService{"svc:unrelated": homeForeign}, map[string][]string{"other.example.com": {"9.9.9.9"}})
	assertForeign(t, workAPI, workDevs, map[string]tsclient.VIPService{
		"svc:unrelated": workForeign,
		"svc:taken":     taken,
		"svc:real":      real,
	}, map[string][]string{"other.example.com": {"9.9.9.9"}, "app.example.com": {"192.0.2.1"}})
	assertForeign(t, partnerAPI, partnerDevs, map[string]tsclient.VIPService{"svc:unrelated": partnerForeign}, map[string][]string{"other.example.com": {"9.9.9.9"}})
	if _, ok := workAPI.Service("svc:api"); !ok {
		t.Fatal("shutdown deleted an owned VIP; shutdown leaves owned services in place")
	}
}

func bridgeState(m *Manager, id string) (string, string) {
	for _, b := range m.store.GetBridges() {
		if b.ID == id {
			return b.Status, b.Error
		}
	}
	return "", ""
}

func assertForeign(t *testing.T, api *fakeapi.Server, devs []tsclient.Device, svcs map[string]tsclient.VIPService, dns map[string][]string) {
	t.Helper()
	if got := api.Devices(); !reflect.DeepEqual(got, devs) {
		t.Errorf("devices changed:\n got %#v\nwant %#v", got, devs)
	}
	for name, want := range svcs {
		got, ok := api.Service(name)
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("service %s = %#v, want %#v (ok=%v)", name, got, want, ok)
		}
	}
	for zone, want := range dns {
		got := api.SplitDNS(zone)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("split-DNS %s = %v, want %v", zone, got, want)
		}
	}
}

func assertNoForeignWrites(t *testing.T, api *fakeapi.Server) {
	t.Helper()
	for _, c := range api.Writes() {
		p := c.String()
		if strings.Contains(p, "/vip-services/svc:unrelated") || strings.Contains(p, "/vip-services/svc:taken") || strings.Contains(p, "/vip-services/svc:real") ||
			strings.Contains(p, "/devices") || strings.Contains(p, "/acl") || strings.Contains(p, "/policy") || strings.Contains(p, "/routes") {
			got, _ := api.Service("svc:taken")
			t.Errorf("write touched something this process does not own: %s (taken now %+v)", p, got)
		}
	}
}

func TestReadySharedNodes(t *testing.T) {
	m := New(state.New(), discardLogger(), nil)
	m.applied = true
	m.cfg = &config.Config{
		SharedNodes:  true,
		PollInterval: config.Duration{Duration: time.Second},
		Tailnets: map[string]config.TailnetConfig{
			"home": {}, "work": {}, "partner": {},
		},
		Bridges: []config.BridgeRule{
			{Name: "home/api", SourceTailnet: "home", From: "home", DestTailnets: []string{"work", "partner"}},
			{Name: "work/only", SourceTailnet: "work", From: "work", DestTailnets: []string{"partner"}},
		},
	}
	if err := m.Ready(); err == nil || !strings.Contains(err.Error(), `tailnet "home"`) {
		t.Fatalf("nothing up: %v", err)
	}
	m.servers["home"] = &tsnet.Server{}
	m.servers["work"] = &tsnet.Server{}
	m.pollDone("home/api", time.Millisecond, nil)
	// partner is still starting. home/api has work up, so the process is ready.
	if err := m.Ready(); err != nil {
		t.Fatalf("one bridge up: %v", err)
	}
	delete(m.servers, "work")
	m.tailnetErr["work"] = errString("auth")
	m.tailnetErr["partner"] = errString("auth")
	if err := m.Ready(); err == nil || !strings.Contains(err.Error(), "no destination") {
		t.Fatalf("every dest failed: %v", err)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestNodeUpMetric(t *testing.T) {
	m := New(state.New(), discardLogger(), nil)
	mt := metrics.New()
	m.store.SetTailnet("home", state.TailnetStatus{ID: "home", Name: "keiretsu.ts.net", Connected: true})
	m.store.SetTailnet("work", state.TailnetStatus{ID: "work", Name: "example.ts.net", Connected: false})
	m.SetMetrics(mt)
	if err := testutil.GatherAndCompare(mt.Registry(), strings.NewReader(`
# HELP tailnetlink_node_up 1 when this process's node in the tailnet is connected.
# TYPE tailnetlink_node_up gauge
tailnetlink_node_up{tailnet="example.ts.net"} 0
tailnetlink_node_up{tailnet="keiretsu.ts.net"} 1
`), "tailnetlink_node_up"); err != nil {
		t.Error(err)
	}
}
