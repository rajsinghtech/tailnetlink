package bridge

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	"github.com/rajsinghtech/tailnetlink/internal/testutil/fakeapi"
	tsclient "tailscale.com/client/tailscale/v2"
)

func useFastRetry(t *testing.T) {
	t.Helper()
	old := retryDelay
	retryDelay = func(int) time.Duration { return time.Millisecond }
	t.Cleanup(func() { retryDelay = old })
}

func webRule() config.BridgeRule {
	return config.BridgeRule{
		Name: "web", SourceTailnet: "src", DestTailnets: []string{"dest"},
		SourceTag: "tag:web", Ports: []int{443},
	}
}

func (tm *testManager) startRule(t *testing.T, rule config.BridgeRule, poll time.Duration) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	tm.m.mu.Lock()
	tm.m.rules[rule.Name] = cancel
	tm.m.ruleDone[rule.Name] = done
	tm.m.mu.Unlock()
	go func() {
		defer close(done)
		tm.m.runRule(ctx, rule, poll, time.Second)
	}()
	t.Cleanup(func() { tm.m.stopRule(rule.Name, false) })
}

func bridgeCounts(st *state.Store) (active, errs, pending int) {
	for _, b := range st.GetBridges() {
		switch b.Status {
		case state.BridgeStatusActive:
			active++
		case state.BridgeStatusError:
			errs++
		default:
			pending++
		}
	}
	return
}

func manyDevices(n int) []tsclient.Device {
	out := make([]tsclient.Device, n)
	for i := range n {
		host := fmt.Sprintf("h%05d", i)
		out[i] = tsclient.Device{
			NodeID:    fmt.Sprintf("n%d", i),
			Name:      host + ".src.example",
			Hostname:  host,
			Tags:      []string{"tag:web"},
			Addresses: []string{fmt.Sprintf("100.64.%d.%d", i/256, i%256)},
		}
	}
	return out
}

func destMethods(t *testing.T, tm *testManager) (get, put, del int) {
	t.Helper()
	for _, c := range tm.dest.Calls() {
		switch c.Method {
		case http.MethodGet:
			get++
		case http.MethodPut:
			put++
		case http.MethodDelete:
			del++
		}
	}
	return get, put, del
}

func TestQueueOneKeyDoesNotOverlap(t *testing.T) {
	useFastRetry(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	inflight := map[string]int{}
	maxIn := map[string]int{}
	var done atomic.Int32
	const n = 20
	q := newReconcileQueue(4, func(_ context.Context, item qItem) error {
		mu.Lock()
		inflight[item.bridgeID]++
		if inflight[item.bridgeID] > maxIn[item.bridgeID] {
			maxIn[item.bridgeID] = inflight[item.bridgeID]
		}
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		inflight[item.bridgeID]--
		mu.Unlock()
		done.Add(1)
		return nil
	})
	q.start(ctx)
	want := make(map[string]qItem, n)
	for i := range n {
		id := fmt.Sprintf("b%d", i)
		want[id] = qItem{dev: Device{Name: id, FQDN: id}, bridgeID: id, dest: "dest"}
	}
	q.Replace(want)
	waitFor(t, 5*time.Second, "all keys applied", func() bool { return done.Load() == n })
	cancel()
	q.wg.Wait()
	for id, m := range maxIn {
		if m != 1 {
			t.Errorf("key %s overlapped %d times", id, m)
		}
	}
}

func TestQueueRetriesUntilSuccess(t *testing.T) {
	useFastRetry(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	q := newReconcileQueue(2, func(_ context.Context, item qItem) error {
		if item.bridgeID == "a" && calls.Add(1) < 3 {
			return errors.New("not yet")
		}
		return nil
	})
	q.start(ctx)
	q.Replace(map[string]qItem{
		"a": {dev: Device{Name: "a", FQDN: "a.example"}, bridgeID: "a", dest: "dest"},
	})
	waitFor(t, 5*time.Second, "retries succeeded", func() bool {
		q.mu.Lock()
		defer q.mu.Unlock()
		item := q.desired["a"]
		return item != nil && q.settled["a"] == item.gen && calls.Load() >= 3
	})
	cancel()
	q.wg.Wait()
}

func TestSnapshotIsTheDesiredSet(t *testing.T) {
	api := fakeapi.New(t)
	api.SetDevices([]tsclient.Device{dev("web-1", []string{"tag:web"}, "100.64.0.1")})
	d := NewDiscoverer(api.Client(), "tag:web", nil, nil, time.Hour, discardLogger())
	var snaps []map[string]Device
	d.onSnapshot = func(found map[string]Device) {
		cp := map[string]Device{}
		for k, v := range found {
			cp[k] = v
		}
		snaps = append(snaps, cp)
	}
	d.poll1(context.Background())
	if len(snaps) != 1 || len(snaps[0]) != 1 || snaps[0]["web-1.src.example"].IP.String() != "100.64.0.1" {
		t.Fatalf("first snapshot = %+v", snaps)
	}
	// Same name, new node id. One entry, not a removal plus an add.
	api.SetDevices([]tsclient.Device{{
		NodeID: "n-web-1-new", Name: "web-1.src.example", Hostname: "web-1",
		Tags: []string{"tag:web"}, Addresses: []string{"100.64.0.9"},
	}})
	d.poll1(context.Background())
	if len(snaps) != 2 || len(snaps[1]) != 1 || snaps[1]["web-1.src.example"].IP.String() != "100.64.0.9" {
		t.Fatalf("re-register snapshot = %+v", snaps)
	}
	if added := drain(d.Added()); len(added) != 0 {
		t.Fatalf("snapshot mode still emitted adds: %+v", added)
	}
}

func TestProvisionRetriesOneFailure(t *testing.T) {
	tm := newTestManager(t)
	tm.src.SetDevices(manyDevices(1))
	tm.dest.FailOnce(http.MethodPut, "", http.StatusServiceUnavailable)
	tm.startRule(t, webRule(), time.Hour)
	waitFor(t, 5*time.Second, "bridge active after 503", func() bool {
		a, _, _ := bridgeCounts(tm.m.store)
		return a == 1
	})
	if _, ok := tm.dest.Service("svc:tnl-src-h00000"); !ok {
		t.Fatal("VIP missing after retry")
	}
	a, e, p := bridgeCounts(tm.m.store)
	if a != 1 || e != 0 || p != 0 {
		t.Fatalf("active=%d error=%d pending=%d", a, e, p)
	}
}

func TestProvisionAllActiveUnderRateLimit(t *testing.T) {
	const n = 60
	tm := newTestManager(t)
	tm.src.SetDevices(manyDevices(n))
	tm.dest.SetRateLimit(50, 50)
	tm.startRule(t, webRule(), time.Hour)
	waitFor(t, 30*time.Second, "all VIPs active under 50 req/s", func() bool {
		a, _, _ := bridgeCounts(tm.m.store)
		return a == n
	})
	a, e, p := bridgeCounts(tm.m.store)
	if a != n || e != 0 || p != 0 {
		t.Fatalf("active=%d error=%d pending=%d", a, e, p)
	}
	_, _, del := destMethods(t, tm)
	t.Logf("n=%d active=%d peak=%d services=%d", n, a, tm.dest.PeakInFlight(), len(tm.dest.ServiceNames()))
	if del != 0 {
		t.Fatalf("DELETEs = %d, want 0", del)
	}
	if got := tm.dest.PeakInFlight(); got > int64(reconcileWorkers) {
		t.Fatalf("peak in flight = %d, want <= %d", got, reconcileWorkers)
	}
	if len(tm.dest.ServiceNames()) != n {
		t.Fatalf("services = %d, want %d", len(tm.dest.ServiceNames()), n)
	}
}

func TestProvisionReRegisterKeepsVIP(t *testing.T) {
	tm := newTestManager(t)
	tm.src.SetDevices([]tsclient.Device{{
		NodeID: "n1", Name: "web-1.src.example", Hostname: "web-1",
		Tags: []string{"tag:web"}, Addresses: []string{"100.64.0.1"},
	}})
	tm.startRule(t, webRule(), 20*time.Millisecond)
	waitFor(t, 5*time.Second, "active", func() bool {
		a, _, _ := bridgeCounts(tm.m.store)
		return a == 1
	})
	if _, ok := tm.dest.Service("svc:tnl-src-web-1"); !ok {
		t.Fatal("VIP was not created")
	}
	tm.dest.ResetCalls()
	tm.src.SetDevices([]tsclient.Device{{
		NodeID: "n2", Name: "web-1.src.example", Hostname: "web-1",
		Tags: []string{"tag:web"}, Addresses: []string{"100.64.0.9"},
	}})
	time.Sleep(300 * time.Millisecond)
	if _, ok := tm.dest.Service("svc:tnl-src-web-1"); !ok {
		t.Fatal("re-registered device lost its VIP")
	}
	_, _, del := destMethods(t, tm)
	if del != 0 {
		t.Fatalf("DELETEs after re-register = %d, want 0", del)
	}
	a, e, p := bridgeCounts(tm.m.store)
	if a != 1 || e != 0 || p != 0 {
		t.Fatalf("active=%d error=%d pending=%d", a, e, p)
	}
}

func TestDeviceGoneDeletesVIP(t *testing.T) {
	tm := newTestManager(t)
	tm.src.SetDevices(manyDevices(1))
	tm.startRule(t, webRule(), 20*time.Millisecond)
	waitFor(t, 5*time.Second, "active", func() bool {
		a, _, _ := bridgeCounts(tm.m.store)
		return a == 1
	})
	tm.dest.ResetCalls()
	tm.src.SetDevices(nil)
	waitFor(t, 5*time.Second, "VIP deleted", func() bool {
		_, ok := tm.dest.Service("svc:tnl-src-h00000")
		return !ok
	})
	_, _, del := destMethods(t, tm)
	if del != 1 {
		t.Fatalf("DELETEs = %d, want 1", del)
	}
}

func TestProvisionCallCountAndPeakAtScale(t *testing.T) {
	const n = 5000
	tm := newTestManager(t)
	tm.src.SetDevices(manyDevices(n))
	tm.startRule(t, webRule(), time.Hour)
	waitFor(t, 2*time.Minute, "5000 active", func() bool {
		a, _, _ := bridgeCounts(tm.m.store)
		return a == n
	})
	get, put, del := destMethods(t, tm)
	t.Logf("n=%d get=%d put=%d del=%d peak=%d workers=%d", n, get, put, del, tm.dest.PeakInFlight(), reconcileWorkers)
	if get != 2*n || put != n || del != 0 {
		t.Fatalf("dest API get=%d put=%d del=%d, want get=%d put=%d del=0", get, put, del, 2*n, n)
	}
	if got := tm.dest.PeakInFlight(); got > int64(reconcileWorkers) {
		t.Fatalf("peak in flight = %d, want <= %d", got, reconcileWorkers)
	}
}
