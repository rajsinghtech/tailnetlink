package e2e

import (
	"context"
	"testing"
	"time"
)

// On SIGTERM the manager closes within the timeout and its tsnet nodes drop
// off both control servers.
func TestManagerCloseDisconnectsNodes(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	echoBackend(t, ctx, b.src, "backend", 8080)
	r := startManager(t, b.config(b.deviceRule("web", "backend", "", 8080)), freeAddr(t))
	waitVIP(t, b.dstAPI, b.serviceName("backend", ""))
	waitVIP(t, b.dstAPI, "svc:tailnetlink")

	r.cancel()
	cctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	if err := r.m.Close(cctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	t.Logf("closed in %v", time.Since(start).Round(time.Millisecond))

	// The echo backend stays on the source control server. The destination
	// has only the tailnetlink node, so its map count goes to zero. A node
	// can hold two map polls for a moment while one replaces the other, so
	// subtracting one from the earlier count reports a disconnect as a node
	// that is still connected.
	waitFor(t, 10*time.Second, "tailnetlink nodes off both control servers", func() bool {
		return b.src.control.InServeMap() == 1 && b.dst.control.InServeMap() == 0
	})
}
