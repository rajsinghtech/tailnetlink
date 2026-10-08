package e2e

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/bridge"
	"tailscale.com/tsnet"
)

// Fifty concurrent listens on one node must all show up in
// AdvertiseServices. tsnet updates that list with a read-append-write and
// no lock; without a lock around ListenService some of the names are lost
// and the VIP cannot be routed even though the listen returned nil.
func TestConcurrentListensAreAllAdvertised(t *testing.T) {
	ctx := e2eSetup(t)
	tn := newTailnet(t, "dst.ts.net")
	n := tn.node(t, ctx, "tailnetlink-dst")

	cur := tn.control.Node(n.key)
	cur.Tags = append(cur.Tags, "tag:tailnetlink")
	tn.control.UpdateNode(cur)
	lc, err := n.srv.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, 20*time.Second, "node is tagged", func() bool {
		st, err := lc.Status(ctx)
		return err == nil && st.Self != nil && st.Self.Tags != nil && st.Self.Tags.Len() > 0
	})

	const nListen = 50
	names := make([]string, nListen)
	for i := range names {
		names[i] = fmt.Sprintf("svc:c%02d", i)
	}
	lns := make([]net.Listener, nListen)
	errCh := make(chan error, nListen)
	var wg sync.WaitGroup
	for i := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ln, err := bridge.ListenService(n.srv, names[i], tsnet.ServiceModeTCP{
				Port:                 443,
				PROXYProtocolVersion: 1,
			})
			if err != nil {
				errCh <- fmt.Errorf("%s: %w", names[i], err)
				return
			}
			lns[i] = ln
		}()
	}
	wg.Wait()
	close(errCh)
	t.Cleanup(func() {
		for _, ln := range lns {
			if ln != nil {
				ln.Close()
			}
		}
	})
	var failed int
	for err := range errCh {
		failed++
		if failed == 1 {
			t.Error(err)
		}
	}
	if failed != 0 {
		t.Fatalf("%d/%d listens failed", failed, nListen)
	}

	prefs, err := lc.GetPrefs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]bool, len(prefs.AdvertiseServices))
	for _, name := range prefs.AdvertiseServices {
		got[name] = true
	}
	var missing []string
	for _, name := range names {
		if !got[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 || len(prefs.AdvertiseServices) != nListen {
		t.Fatalf("advertised %d/%d, missing %v", len(prefs.AdvertiseServices), nListen, missing)
	}
}
