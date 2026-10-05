package bridge

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	tsclient "tailscale.com/client/tailscale/v2"
)

// Close stops running rules, forgets the tailnets and makes Reconcile a
// no-op.
func TestManagerCloseStopsEverything(t *testing.T) {
	tm := newTestManager(t)
	tm.src.SetDevices([]tsclient.Device{{
		NodeID: "n1", Name: "web-1.src.example", Hostname: "web-1",
		Tags: []string{"tag:web"}, Addresses: []string{"100.64.0.1"},
	}})
	rule := config.BridgeRule{Name: "web", SourceTailnet: "src", DestTailnets: []string{"dest"}, SourceTag: "tag:web", Ports: []int{80}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	tm.m.rules["web"] = cancel
	tm.m.ruleDone["web"] = done
	go func() {
		defer close(done)
		tm.m.runRule(ctx, rule, time.Hour, time.Second)
	}()
	waitFor(t, 5*time.Second, "bridge active", func() bool {
		return tm.bridgeActive("web/dest/web-1.src.example")
	})

	cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer ccancel()
	if err := tm.m.Close(cctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	default:
		t.Error("rule still running after Close")
	}
	if len(tm.m.servers) != 0 || len(tm.m.rules) != 0 {
		t.Errorf("servers=%d rules=%d after Close", len(tm.m.servers), len(tm.m.rules))
	}

	// Reconcile after Close starts nothing.
	tm.m.Reconcile(context.Background(), &config.Config{InstanceID: testOwner, Bridges: []config.BridgeRule{rule}})
	if len(tm.m.rules) != 0 {
		t.Error("Reconcile started a rule after Close")
	}
}

// A rule that never exits makes Close give up when ctx is done.
func TestManagerCloseRespectsTimeout(t *testing.T) {
	m := New(nil, discardLogger(), nil)
	m.rules["stuck"] = func() {}
	m.ruleDone["stuck"] = make(chan struct{}) // never closed
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := m.Close(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want a deadline error", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Close took %v", d)
	}
}
