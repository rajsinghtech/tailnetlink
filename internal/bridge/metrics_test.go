package bridge

import (
	"context"
	"errors"
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

func TestReady(t *testing.T) {
	m := New(state.New(), discardLogger(), nil)
	if err := m.Ready(); err == nil || !strings.Contains(err.Error(), "not applied") {
		t.Fatalf("before Reconcile: %v", err)
	}

	m.mu.Lock()
	m.applied = true
	m.cfg = &config.Config{
		Tailnets:     map[string]config.TailnetConfig{"a": {}, "b": {}},
		PollInterval: config.Duration{Duration: time.Second},
		Bridges: []config.BridgeRule{
			{Name: "web", SourceTailnet: "a", DestTailnets: []string{"b"}},
			{Name: "local", DestTailnets: []string{"b"}, LocalSources: []config.LocalSourceSpec{{Addr: "127.0.0.1:1"}}},
		},
	}
	m.servers["a"] = &tsnet.Server{}
	m.mu.Unlock()
	if err := m.Ready(); err == nil || !strings.Contains(err.Error(), `tailnet "b"`) {
		t.Fatalf("one tailnet down: %v", err)
	}

	m.mu.Lock()
	m.servers["b"] = &tsnet.Server{}
	m.mu.Unlock()
	if err := m.Ready(); err == nil || !strings.Contains(err.Error(), "not polled") {
		t.Fatalf("no poll yet: %v", err)
	}

	// A failed poll doesn't count; a good one does. The local rule never
	// polls and doesn't hold readiness back.
	m.pollDone("web", time.Millisecond, errors.New("api down"))
	if err := m.Ready(); err == nil {
		t.Fatal("ready after a failed poll")
	}
	m.pollDone("web", time.Millisecond, nil)
	if err := m.Ready(); err != nil {
		t.Fatalf("after poll: %v", err)
	}

	m.mu.Lock()
	m.lastPoll["web"] = time.Now().Add(-10 * time.Second)
	m.mu.Unlock()
	if err := m.Ready(); err == nil || !strings.Contains(err.Error(), "last polled") {
		t.Fatalf("stale poll: %v", err)
	}
}

func TestReadyEmptyConfig(t *testing.T) {
	m := New(state.New(), discardLogger(), nil)
	m.Reconcile(context.Background(), &config.Config{Tailnets: map[string]config.TailnetConfig{}})
	if err := m.Ready(); err != nil {
		t.Fatal(err)
	}
}

func TestDiscovererReportsPolls(t *testing.T) {
	api := fakeapi.New(t)
	api.SetDevices([]tsclient.Device{dev("web-1", []string{"tag:web"}, "100.64.0.1")})
	var errs []error
	d := NewDiscoverer(api.Client(), "tag:web", nil, nil, 0, discardLogger())
	d.onPoll = func(_ time.Duration, err error) { errs = append(errs, err) }
	d.poll1(context.Background())
	api.Fail("GET", "/devices", 500)
	d.poll1(context.Background())

	svc := NewDiscoverer(api.Client(), "", nil, []string{"svc:x"}, 0, discardLogger())
	svc.onPoll = d.onPoll
	api.Fail("GET", "/vip-services", 500)
	svc.poll1(context.Background())

	// A cancelled poll isn't reported at all.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.poll1(ctx)

	if len(errs) != 3 || errs[0] != nil || errs[1] == nil || errs[2] == nil {
		t.Fatalf("poll results = %v", errs)
	}
}

func TestManagerRecordsConflictsAndAPIErrors(t *testing.T) {
	m := New(state.New(), discardLogger(), nil)
	mt := metrics.New()
	m.SetMetrics(mt)
	m.conflict("dst", &ConflictError{Service: "svc:x"})
	m.conflict("dst", errors.New("something else"))
	m.conflict("dst", nil)
	if n := sumMetric(t, mt, "tailnetlink_ownership_conflicts_total"); n != 1 {
		t.Errorf("conflicts = %v, want 1", n)
	}

	api := fakeapi.New(t)
	api.Fail("GET", "/devices", 500)
	c := m.newAPIClient(config.TailnetConfig{Tailnet: api.Tailnet, APIBaseURL: api.URL(), OAuth: config.OAuthCreds{ClientID: "id", ClientSecretEnv: "TNL_METRICS_TEST"}})
	t.Setenv("TNL_METRICS_TEST", "s")
	_, _ = c.Devices().List(context.Background())
	if n := sumMetric(t, mt, "tailnetlink_api_errors_total"); n < 1 {
		t.Errorf("api errors = %v, want at least 1", n)
	}

	m.store.UpsertBridge(state.BridgeEntry{ID: "r/d/x", Status: state.BridgeStatusActive})
	if err := testutil.GatherAndCompare(mt.Registry(), strings.NewReader(`
# HELP tailnetlink_bridges Bridges by status.
# TYPE tailnetlink_bridges gauge
tailnetlink_bridges{status="active"} 1
tailnetlink_bridges{status="error"} 0
tailnetlink_bridges{status="pending"} 0
`), "tailnetlink_bridges"); err != nil {
		t.Error(err)
	}
}

// sumMetric adds up every series of a counter or gauge called name.
func sumMetric(t *testing.T, mt *metrics.Metrics, name string) float64 {
	t.Helper()
	mfs, err := mt.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	var sum float64
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			sum += m.GetCounter().GetValue() + m.GetGauge().GetValue()
		}
	}
	return sum
}
