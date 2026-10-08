package bridge

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	tsclient "tailscale.com/client/tailscale/v2"
)

func TestMain(m *testing.M) {
	// Unit tests must not wait out the production start offset.
	startJitter = func(time.Duration) time.Duration { return 0 }
	os.Exit(m.Run())
}

func TestPollJitterStaysInRange(t *testing.T) {
	for range 30 {
		d := defaultStartJitter(30 * time.Second)
		if d < 0 || d > 5*time.Second {
			t.Fatalf("start offset %s", d)
		}
		next := defaultNextInterval(10 * time.Second)
		if next < 8*time.Second || next > 12*time.Second {
			t.Fatalf("next interval %s", next)
		}
	}
	if defaultStartJitter(0) != 0 || defaultNextInterval(0) != 0 {
		t.Fatal("zero interval")
	}
	if defaultStartJitter(time.Nanosecond) != 0 {
		t.Fatal("tiny interval should not wait")
	}
	if defaultNextInterval(3*time.Nanosecond) != 3*time.Nanosecond {
		t.Fatal("tiny interval jitter")
	}
}

func listCalls(t *testing.T, tm *testManager, path string) int {
	t.Helper()
	n := 0
	for _, c := range tm.src.Calls() {
		if c.Method == http.MethodGet && c.Path == path {
			n++
		}
	}
	return n
}

func TestSharedDiscoveryOneListPerTailnet(t *testing.T) {
	tm := newTestManager(t)
	var devs []tsclient.Device
	for i := range 4 {
		d := devNamed(i, "tag:web")
		devs = append(devs, d)
	}
	tm.src.SetDevices(devs)
	tm.src.PutService(tsclient.VIPService{Name: "svc:extra", Addrs: []string{"100.100.1.1"}, Tags: []string{"tag:web"}})
	for i := range 3 {
		rule := webRule()
		rule.Name = "l" + string(rune('a'+i))
		rule.Ports = []int{443 + i}
		tm.startRule(t, rule, time.Hour)
	}
	// The three links discover the same names, so they want the same VIP
	// services. The first bridge to claim a name owns it. The others stop
	// with a conflict instead of overwriting it. Every link still consumes
	// the one shared poll.
	waitFor(t, 5*time.Second, "every link settled", func() bool {
		a, e, p := bridgeCounts(tm.m.store)
		return p == 0 && a+e == 3*5
	})
	active, errs, _ := bridgeCounts(tm.m.store)
	if active < 5 || errs == 0 {
		t.Fatalf("active=%d errors=%d, want the first bridge to own each name and the others to conflict", active, errs)
	}
	for _, b := range tm.m.store.GetBridges() {
		if b.Status == state.BridgeStatusError && !strings.Contains(b.Error, "conflict") {
			t.Errorf("bridge %s error = %s, want a name conflict", b.ID, b.Error)
		}
	}
	if got := listCalls(t, tm, "/devices"); got != 1 {
		t.Fatalf("device lists = %d, want 1 for 3 links", got)
	}
	if got := listCalls(t, tm, "/vip-services"); got != 1 {
		t.Fatalf("service lists = %d, want 1 for 3 links", got)
	}
	q := strings.Join(tm.src.DeviceListQueries(), " ")
	if !strings.Contains(q, "tags=") {
		t.Fatalf("device list query %q, want a tags filter", q)
	}
}

func TestDeviceModeSkipsTagFilter(t *testing.T) {
	tm := newTestManager(t)
	tm.src.SetDevices([]tsclient.Device{
		devNamed(0, "tag:web"),
		{NodeID: "n-box", Name: "box.src.example", Hostname: "box", Addresses: []string{"100.64.0.9"}},
	})
	tag := webRule()
	tag.Name = "tagged"
	dev := config.BridgeRule{
		Name: "named", SourceTailnet: "src", DestTailnets: []string{"dest"},
		SourceDevices: []config.DeviceSpec{{FQDN: "box.src.example"}},
		Ports:         []int{80},
	}
	tm.startRule(t, tag, time.Hour)
	tm.startRule(t, dev, time.Hour)
	waitFor(t, 5*time.Second, "both links active", func() bool {
		a, _, _ := bridgeCounts(tm.m.store)
		return a >= 2
	})
	qs := tm.src.DeviceListQueries()
	if len(qs) == 0 || strings.Contains(qs[len(qs)-1], "tags=") {
		t.Fatalf("device list queries = %q, want the last one unfiltered", qs)
	}
}

func TestPollerStopsWhenTheLastLinkLeaves(t *testing.T) {
	tm := newTestManager(t)
	tm.src.SetDevices([]tsclient.Device{devNamed(0, "tag:web")})
	rule := webRule()
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
	waitFor(t, 5*time.Second, "active", func() bool {
		a, _, _ := bridgeCounts(tm.m.store)
		return a == 1
	})
	tm.m.stopRule(rule.Name, false)
	if len(tm.m.pollers) != 0 {
		t.Fatalf("pollers left: %d", len(tm.m.pollers))
	}
	p := tm.m.sharedPoller("src", tm.m.apiClients["src"], 0)
	if p.base != 30*time.Second {
		t.Fatalf("zero interval became %s", p.base)
	}
}

func TestServiceModeSkipsTheDeviceList(t *testing.T) {
	tm := newTestManager(t)
	tm.src.PutService(tsclient.VIPService{Name: "svc:only", Addrs: []string{"100.100.1.8"}, Tags: []string{"tag:web"}})
	rule := config.BridgeRule{
		Name: "svc", SourceTailnet: "src", DestTailnets: []string{"dest"},
		SourceServices: []config.ServiceSpec{{Name: "svc:only"}},
		Ports:          []int{80},
	}
	tm.startRule(t, rule, time.Hour)
	waitFor(t, 5*time.Second, "service bridge active", func() bool {
		a, _, _ := bridgeCounts(tm.m.store)
		return a == 1
	})
	if got := listCalls(t, tm, "/devices"); got != 0 {
		t.Fatalf("device lists = %d, want 0 in service mode", got)
	}
	if got := listCalls(t, tm, "/vip-services"); got != 1 {
		t.Fatalf("service lists = %d, want 1", got)
	}
}

// A device-mode link does not list services. A tag link added later on the
// same tailnet has to fetch them instead of reusing that device-only poll
// for the rest of the interval.
func TestTagLinkAfterDeviceLinkListsServices(t *testing.T) {
	tm := newTestManager(t)
	tm.src.SetDevices([]tsclient.Device{devNamed(0, "tag:other")})
	tm.src.PutService(tsclient.VIPService{Name: "svc:extra", Addrs: []string{"100.100.1.1"}, Tags: []string{"tag:web"}})
	tm.startRule(t, config.BridgeRule{
		Name: "dev", SourceTailnet: "src", DestTailnets: []string{"dest"},
		SourceDevices: []config.DeviceSpec{{FQDN: "h0.src.example"}},
		Ports:         []int{80},
	}, time.Hour)
	waitFor(t, 5*time.Second, "device bridge", func() bool {
		a, _, _ := bridgeCounts(tm.m.store)
		return a == 1
	})
	if got := listCalls(t, tm, "/vip-services"); got != 0 {
		t.Fatalf("device-only link listed services %d times", got)
	}
	tag := webRule()
	tag.Name = "tagged"
	tm.startRule(t, tag, time.Hour)
	waitFor(t, 5*time.Second, "tagged service exported", func() bool {
		_, ok := tm.dest.Service("svc:tnl-src-extra")
		return ok
	})
}

func devNamed(i int, tag string) tsclient.Device {
	host := "h" + string(rune('0'+i))
	return tsclient.Device{
		NodeID: "n-" + host, Name: host + ".src.example", Hostname: host,
		Tags: []string{tag}, Addresses: []string{"100.64.0." + string(rune('1'+i))},
	}
}
