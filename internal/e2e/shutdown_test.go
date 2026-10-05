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

	srcBefore, dstBefore := b.src.control.InServeMap(), b.dst.control.InServeMap()
	r.cancel()
	cctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	if err := r.m.Close(cctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	t.Logf("closed in %v", time.Since(start).Round(time.Millisecond))

	waitFor(t, 10*time.Second, "tailnetlink nodes off both control servers", func() bool {
		return b.src.control.InServeMap() == srcBefore-1 && b.dst.control.InServeMap() == dstBefore-1
	})
}
