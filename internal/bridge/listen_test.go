package bridge

import (
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rajsinghtech/tailnetlink/internal/metrics"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	"tailscale.com/tsnet"
)

func withNoRetryDelay(t *testing.T) {
	t.Helper()
	old := listenRetryDelay
	listenRetryDelay = 0
	t.Cleanup(func() { listenRetryDelay = old })
}

type countingListener struct {
	net.Listener
	closes *atomic.Int32
}

func (c *countingListener) Close() error {
	c.closes.Add(1)
	return c.Listener.Close()
}

func localListener(t *testing.T, closes *atomic.Int32) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return &countingListener{Listener: ln, closes: closes}
}

func TestListenLockIsPerNode(t *testing.T) {
	a, b := &tsnet.Server{}, &tsnet.Server{}
	la := listenLock(a)
	if listenLock(a) != la {
		t.Fatal("same node returned two locks")
	}
	if la == listenLock(b) {
		t.Fatal("two nodes share a lock")
	}
	listenLocks.Delete(a)
	listenLocks.Delete(b)
}

func TestListenSerializesPerNode(t *testing.T) {
	srv := &tsnet.Server{}
	t.Cleanup(func() { listenLocks.Delete(srv) })
	var cur, max atomic.Int32
	var closes atomic.Int32
	open := func(*tsnet.Server, string, tsnet.ServiceMode) (net.Listener, error) {
		n := cur.Add(1)
		for {
			old := max.Load()
			if n <= old || max.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		cur.Add(-1)
		return localListener(t, &closes), nil
	}
	ok := func(*tsnet.Server, string) (bool, error) { return true, nil }

	const n = 8
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	lns := make([]net.Listener, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ln, err := listenService(srv, "svc:a", tsnet.ServiceModeTCP{Port: 80}, open, ok)
			if err != nil {
				errCh <- err
				return
			}
			lns[i] = ln
		}()
	}
	wg.Wait()
	close(errCh)
	for _, ln := range lns {
		if ln != nil {
			ln.Close()
		}
	}
	for err := range errCh {
		t.Error(err)
	}
	if got := max.Load(); got != 1 {
		t.Fatalf("peak overlapping listens = %d, want 1", got)
	}
}

func TestListenRetriesUntilAdvertised(t *testing.T) {
	withNoRetryDelay(t)
	srv := &tsnet.Server{}
	t.Cleanup(func() { listenLocks.Delete(srv) })
	var calls atomic.Int32
	var closes atomic.Int32
	open := func(*tsnet.Server, string, tsnet.ServiceMode) (net.Listener, error) {
		calls.Add(1)
		return localListener(t, &closes), nil
	}
	inPrefs := func(*tsnet.Server, string) (bool, error) {
		return calls.Load() >= 3, nil
	}
	ln, err := listenService(srv, "svc:a", tsnet.ServiceModeTCP{Port: 80}, open, inPrefs)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatalf("listens = %d, want 3", calls.Load())
	}
	if closes.Load() != 2 {
		t.Fatalf("closed failed listens = %d, want 2", closes.Load())
	}
	ln.Close()
}

func TestListenGivesUpWhenNeverAdvertised(t *testing.T) {
	withNoRetryDelay(t)
	srv := &tsnet.Server{}
	t.Cleanup(func() { listenLocks.Delete(srv) })
	var calls atomic.Int32
	var closes atomic.Int32
	open := func(*tsnet.Server, string, tsnet.ServiceMode) (net.Listener, error) {
		calls.Add(1)
		return localListener(t, &closes), nil
	}
	never := func(*tsnet.Server, string) (bool, error) { return false, nil }
	ln, err := listenService(srv, "svc:missing", tsnet.ServiceModeTCP{Port: 80}, open, never)
	if err == nil {
		ln.Close()
		t.Fatal("expected an error when the service is never advertised")
	}
	if !strings.Contains(err.Error(), "AdvertiseServices") {
		t.Fatalf("error = %v", err)
	}
	if calls.Load() != listenAttempts || closes.Load() != listenAttempts {
		t.Fatalf("calls=%d closes=%d, want %d", calls.Load(), closes.Load(), listenAttempts)
	}
}

func TestListenDoesNotRetryOtherErrors(t *testing.T) {
	withNoRetryDelay(t)
	srv := &tsnet.Server{}
	t.Cleanup(func() { listenLocks.Delete(srv) })
	var calls atomic.Int32
	open := func(*tsnet.Server, string, tsnet.ServiceMode) (net.Listener, error) {
		calls.Add(1)
		return nil, errors.New("boom")
	}
	_, err := listenService(srv, "svc:a", tsnet.ServiceModeTCP{Port: 80}, open, func(*tsnet.Server, string) (bool, error) {
		return true, nil
	})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}
}

func TestListenRetriesEtagMismatch(t *testing.T) {
	withNoRetryDelay(t)
	srv := &tsnet.Server{}
	t.Cleanup(func() { listenLocks.Delete(srv) })
	var calls atomic.Int32
	var closes atomic.Int32
	open := func(*tsnet.Server, string, tsnet.ServiceMode) (net.Listener, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("etag mismatch")
		}
		return localListener(t, &closes), nil
	}
	ln, err := listenService(srv, "svc:a", tsnet.ServiceModeTCP{Port: 80}, open, func(*tsnet.Server, string) (bool, error) {
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2", calls.Load())
	}
}

func TestVIPGaugeDesiredVersusAdvertised(t *testing.T) {
	withNoRetryDelay(t)
	m := New(state.New(), discardLogger(), nil)
	mt := metrics.New()
	m.SetMetrics(mt)
	srv := &tsnet.Server{}
	m.bindNode("dest", srv)
	t.Cleanup(func() {
		m.unbindNode("dest", srv)
		listenLocks.Delete(srv)
	})

	open := func(*tsnet.Server, string, tsnet.ServiceMode) (net.Listener, error) {
		return localListener(t, &atomic.Int32{}), nil
	}
	inPrefs := func(_ *tsnet.Server, name string) (bool, error) {
		return name == "svc:up", nil
	}
	up, err := listenService(srv, "svc:up", tsnet.ServiceModeTCP{Port: 80}, open, inPrefs)
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	if _, err := listenService(srv, "svc:down", tsnet.ServiceModeTCP{Port: 443}, open, inPrefs); err == nil {
		t.Fatal("svc:down was advertised")
	}

	if err := testutil.GatherAndCompare(mt.Registry(), strings.NewReader(`
# HELP tailnetlink_vip_services VIP services this process intends to host (desired) and has verified in AdvertiseServices (advertised).
# TYPE tailnetlink_vip_services gauge
tailnetlink_vip_services{state="advertised",tailnet="dest"} 1
tailnetlink_vip_services{state="desired",tailnet="dest"} 2
`), "tailnetlink_vip_services"); err != nil {
		t.Fatal(err)
	}

	m.dropAdvertised("dest", "svc:up")
	m.forgetVIP("dest", "svc:down")
	if err := testutil.GatherAndCompare(mt.Registry(), strings.NewReader(`
# HELP tailnetlink_vip_services VIP services this process intends to host (desired) and has verified in AdvertiseServices (advertised).
# TYPE tailnetlink_vip_services gauge
tailnetlink_vip_services{state="advertised",tailnet="dest"} 0
tailnetlink_vip_services{state="desired",tailnet="dest"} 1
`), "tailnetlink_vip_services"); err != nil {
		t.Fatal(err)
	}

	m.forgetTailnet("dest")
	fams, err := mt.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, fam := range fams {
		if fam.GetName() == "tailnetlink_vip_services" && len(fam.GetMetric()) != 0 {
			t.Fatalf("series after forget = %d, want 0", len(fam.GetMetric()))
		}
	}
}

func TestVIPBookkeepingEdges(t *testing.T) {
	var none *Manager
	none.bindNode("dest", &tsnet.Server{})
	none.noteVIP("dest", "svc:a", true)
	none.forgetVIP("dest", "svc:a")
	none.dropAdvertised("dest", "svc:a")
	none.forgetTailnet("dest")

	m := New(state.New(), discardLogger(), nil)
	m.bindNode("", &tsnet.Server{})
	m.bindNode("dest", nil)
	m.noteVIP("", "svc:a", true)
	m.noteVIP("dest", "", true)
	m.forgetVIP("dest", "")
	m.dropAdvertised("", "svc:a")
	m.forgetTailnet("")

	m.vipDesired = nil
	m.vipAdvertised = nil
	m.noteVIP("dest", "svc:a", true)
	m.noteVIP("dest", "svc:b", false)
	desired, advertised := m.vipCounts()
	if desired["dest"] != 2 || advertised["dest"] != 1 {
		t.Fatalf("counts = %v %v", desired, advertised)
	}
	m.forgetVIP("dest", "svc:a")
	m.dropAdvertised("dest", "svc:b")
	desired, advertised = m.vipCounts()
	if desired["dest"] != 1 || advertised["dest"] != 0 {
		t.Fatalf("after forget = %v %v", desired, advertised)
	}
	m.unbindNode("dest", nil)
	if _, ok := m.vipDesired["dest"]; ok {
		t.Fatal("unbind left the tailnet")
	}
}
