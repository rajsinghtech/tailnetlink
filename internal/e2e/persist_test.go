package e2e

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/state"
)

func deletes(calls []string) []string {
	var out []string
	for _, c := range calls {
		if strings.HasPrefix(c, "DELETE ") {
			out = append(out, c)
		}
	}
	return out
}

func keyRequests(calls []string) int {
	n := 0
	for _, c := range calls {
		if strings.HasPrefix(c, "POST ") && strings.HasSuffix(c, "/keys") {
			n++
		}
	}
	return n
}

// Stopping the manager leaves its services and split-DNS in place.
func TestManagerShutdownKeepsServices(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	echoBackend(t, ctx, b.src, "backend", 8080)
	r := startManager(t, b.config(b.deviceRule("web", "backend", "", 8080)), freeAddr(t))
	svc := b.serviceName("backend", "")
	waitVIP(t, b.dstAPI, svc)
	waitVIP(t, b.dstAPI, "svc:tailnetlink")
	waitFor(t, 30*time.Second, "split-DNS for the source zone", func() bool {
		return len(b.dstAPI.SplitDNS(b.src.domain)) > 0
	})
	before, _ := b.dstAPI.Service(svc)
	dnsBefore := b.dstAPI.SplitDNS(b.src.domain)

	b.dstAPI.ResetCalls()
	b.srcAPI.ResetCalls()
	r.stop(t)
	time.Sleep(500 * time.Millisecond)

	if w := append(b.dstAPI.Writes(), b.srcAPI.Writes()...); len(w) != 0 {
		t.Errorf("shutdown made writes: %v", w)
	}
	if after, ok := b.dstAPI.Service(svc); !ok || !reflect.DeepEqual(after, before) {
		t.Errorf("service changed on shutdown: %+v", after)
	}
	for _, api := range []*ctlBridge{b.srcAPI, b.dstAPI} {
		if _, ok := api.Service("svc:tailnetlink"); !ok {
			t.Error("UI service deleted on shutdown")
		}
	}
	if got := b.dstAPI.SplitDNS(b.src.domain); !slices.Equal(got, dnsBefore) {
		t.Errorf("split-DNS = %v, want %v", got, dnsBefore)
	}
}

// A restart with the same state dir comes back as the same nodes, with the
// same VIP, without a new auth key and without deleting anything.
func TestManagerRestartReusesNode(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	echoBackend(t, ctx, b.src, "backend", 8080)
	cl := client(t, ctx, b.dst, "client")
	cfg := b.config(b.deviceRule("web", "backend", "", 8080))
	svc := b.serviceName("backend", "")
	id := "web/" + b.dstName + "/backend." + b.src.domain

	r := startManager(t, cfg, "")
	vip := waitVIP(t, b.dstAPI, svc)
	echoVia(t, ctx, cl, netip.AddrPortFrom(vip, 8080), "first run")
	for _, name := range []string{b.srcName, b.dstName} {
		if _, err := os.Stat(filepath.Join(b.stateDir, name, "tailscaled.state")); err != nil {
			t.Errorf("no saved state for %s: %v", name, err)
		}
	}
	r.stop(t)
	srcNodes, dstNodes := len(b.src.control.AllNodes()), len(b.dst.control.AllNodes())

	b.srcAPI.ResetCalls()
	b.dstAPI.ResetCalls()
	r2 := startManager(t, cfg, "")
	waitFor(t, 60*time.Second, "bridge active after restart", func() bool {
		st, _ := r2.bridgeStatus(id)
		return st == string(state.BridgeStatusActive)
	})
	if got := waitVIP(t, b.dstAPI, svc); got != vip {
		t.Errorf("VIP changed across restart: %v -> %v", vip, got)
	}
	echoVia(t, ctx, cl, netip.AddrPortFrom(vip, 8080), "second run")

	if n := len(b.src.control.AllNodes()); n != srcNodes {
		t.Errorf("src nodes %d -> %d; restart registered a new node", srcNodes, n)
	}
	if n := len(b.dst.control.AllNodes()); n != dstNodes {
		t.Errorf("dst nodes %d -> %d; restart registered a new node", dstNodes, n)
	}
	calls := append(b.srcAPI.Calls(), b.dstAPI.Calls()...)
	if n := keyRequests(calls); n != 0 {
		t.Errorf("restart minted %d auth keys", n)
	}
	if d := deletes(calls); len(d) != 0 {
		t.Errorf("restart deleted: %v", d)
	}
}

// Removing one link from the config deletes that link's services and
// nothing else.
func TestManagerRemoveLinkDeletesOnlyItsServices(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	echoBackend(t, ctx, b.src, "one", 7001)
	echoBackend(t, ctx, b.src, "two", 7002)
	cl := client(t, ctx, b.dst, "client")
	cfg := b.config(b.deviceRule("one", "one", "", 7001), b.deviceRule("two", "two", "", 7002))
	r := startManager(t, cfg, freeAddr(t))
	svc1, svc2 := b.serviceName("one", ""), b.serviceName("two", "")
	vip1 := waitVIP(t, b.dstAPI, svc1)
	waitVIP(t, b.dstAPI, svc2)
	waitVIP(t, b.dstAPI, "svc:tailnetlink")
	waitFor(t, 30*time.Second, "DNS records for both links", func() bool {
		l := r.logs.String()
		return strings.Contains(l, `msg="DNS record added" rule=one`) && strings.Contains(l, `msg="DNS record added" rule=two`)
	})
	before, _ := b.dstAPI.Service(svc1)
	dnsBefore := b.dstAPI.SplitDNS(b.src.domain)

	b.dstAPI.ResetCalls()
	next := *cfg
	next.Bridges = cfg.Bridges[:1]
	r.m.Reconcile(r.ctx, &next)
	waitFor(t, 30*time.Second, "removed link's service deleted", func() bool {
		_, ok := b.dstAPI.Service(svc2)
		return !ok
	})
	time.Sleep(500 * time.Millisecond)

	if d := deletes(b.dstAPI.Calls()); len(d) != 1 || !strings.HasSuffix(d[0], "/"+svc2) {
		t.Errorf("deletes = %v, want only %s", d, svc2)
	}
	if after, ok := b.dstAPI.Service(svc1); !ok || !reflect.DeepEqual(after, before) {
		t.Errorf("kept link's service changed: %+v", after)
	}
	if _, ok := b.dstAPI.Service("svc:tailnetlink"); !ok {
		t.Error("UI service deleted")
	}
	if got := b.dstAPI.SplitDNS(b.src.domain); !slices.Equal(got, dnsBefore) {
		t.Errorf("split-DNS = %v, want %v", got, dnsBefore)
	}
	echoVia(t, ctx, cl, netip.AddrPortFrom(vip1, 7001), "still bridged")
}

// With ephemeral set, nothing is saved under state_dir and every start
// registers a new node.
func TestManagerEphemeralNodes(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	echoBackend(t, ctx, b.src, "backend", 8080)
	cfg := b.config(b.deviceRule("web", "backend", "", 8080))
	for name, tc := range cfg.Tailnets {
		tc.Ephemeral = true
		cfg.Tailnets[name] = tc
	}
	svc := b.serviceName("backend", "")

	r := startManager(t, cfg, "")
	waitVIP(t, b.dstAPI, svc)
	if entries, _ := os.ReadDir(b.stateDir); len(entries) != 0 {
		t.Errorf("ephemeral run wrote to state_dir: %v", entries)
	}
	r.stop(t)
	dstNodes := len(b.dst.control.AllNodes())

	b.dstAPI.ResetCalls()
	r2 := startManager(t, cfg, "")
	id := "web/" + b.dstName + "/backend." + b.src.domain
	waitFor(t, 60*time.Second, "bridge active after restart", func() bool {
		st, _ := r2.bridgeStatus(id)
		return st == string(state.BridgeStatusActive)
	})
	if n := len(b.dst.control.AllNodes()); n != dstNodes+1 {
		t.Errorf("dst nodes %d -> %d, want a new node", dstNodes, n)
	}
	if n := keyRequests(b.dstAPI.Calls()); n != 1 {
		t.Errorf("auth keys minted = %d, want 1", n)
	}
}
