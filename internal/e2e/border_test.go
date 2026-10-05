package e2e

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
)

// sibling is a second border that shares b's source tailnet (and its OAuth
// client) but bridges into a new destination tailnet of its own.
func (b *border) sibling(t *testing.T, domain string) *border {
	t.Helper()
	s := &border{sfx: randSuffix(t), stateDir: t.TempDir(), src: b.src, srcAPI: b.srcAPI}
	s.dst = newTailnet(t, domain)
	s.dstAPI = newCtlBridge(t, s.dst)
	s.srcName = "e2e-" + s.sfx + "-src"
	s.dstName = "e2e-" + s.sfx + "-dst"
	f := filepath.Join(t.TempDir(), "secret-dst")
	if err := os.WriteFile(f, []byte(s.secrets()[1]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.secretFiles = []string{b.secretFiles[0], f}
	s.dstAPI.secret = s.secrets()[1]
	return s
}

// loadBorder writes bd as a config file and loads it the way main does.
func loadBorder(t *testing.T, bd *config.Border) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tailnetlink.json")
	writeBorder(t, path, bd)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Two border processes, A to B and A to C, on three tailnets. Each one only
// touches its own destination and its own services, and stopping one
// leaves the other's traffic flowing.
func TestTwoBordersThreeTailnets(t *testing.T) {
	ctx := e2eSetup(t)
	ab := newBorder(t)
	ac := ab.sibling(t, "dst2.ts.net")
	echoBackend(t, ctx, ab.src, "backend", 8080)
	clientB := client(t, ctx, ab.dst, "client-b")
	clientC := client(t, ctx, ac.dst, "client-c")

	rAB := startManager(t, loadBorder(t, ab.border(ab.deviceLink("web", "backend", "", 8080))), "")
	startManager(t, loadBorder(t, ac.border(ac.deviceLink("web", "backend", "", 8080))), "")

	vipB := waitVIP(t, ab.dstAPI, ab.serviceName("backend", ""))
	vipC := waitVIP(t, ac.dstAPI, ac.serviceName("backend", ""))
	echoVia(t, ctx, clientB, netip.AddrPortFrom(vipB, 8080), "to B")
	echoVia(t, ctx, clientC, netip.AddrPortFrom(vipC, 8080), "to C")

	// Every service in each destination belongs to that destination's
	// border, and nothing created services in the shared source.
	for _, d := range []struct {
		b     *border
		owner string
	}{{ab, "e2e-" + ab.sfx}, {ac, "e2e-" + ac.sfx}} {
		names := d.b.dstAPI.ServiceNames()
		if len(names) == 0 {
			t.Errorf("no services in %s", d.b.dst.domain)
		}
		for _, n := range names {
			if s, _ := d.b.dstAPI.Service(n); s.Annotations["tailnetlink/owner"] != d.owner {
				t.Errorf("%s in %s is owned by %q, want %q", n, d.b.dst.domain, s.Annotations["tailnetlink/owner"], d.owner)
			}
		}
	}
	for _, w := range ab.srcAPI.Writes() {
		if !strings.Contains(w, "/keys") {
			t.Errorf("write to the shared source tailnet: %s", w)
		}
	}

	// Stop A-to-B. A-to-C keeps working, and B's services stay put.
	rAB.stop(t)
	echoVia(t, ctx, clientC, netip.AddrPortFrom(vipC, 8080), "C after B stopped")
	if _, ok := ab.dstAPI.Service(ab.serviceName("backend", "")); !ok {
		t.Error("stopping A-to-B deleted its service")
	}
}

// dns.enabled=false in the file: the link works, but no DNS VIP or
// split-DNS entry is created.
func TestBorderDNSDisabled(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	echoBackend(t, ctx, b.src, "backend", 8080)
	cl := client(t, ctx, b.dst, "client")
	bd := b.border(b.deviceLink("web", "backend", "", 8080))
	off := false
	bd.DNS.Enabled = &off
	startManager(t, loadBorder(t, bd), "")
	vip := waitVIP(t, b.dstAPI, b.serviceName("backend", ""))
	echoVia(t, ctx, cl, netip.AddrPortFrom(vip, 8080), "no dns")
	for _, n := range b.dstAPI.ServiceNames() {
		if strings.HasPrefix(n, "svc:tnl-dns-") {
			t.Errorf("DNS service %s created with dns off", n)
		}
	}
	if got := b.dstAPI.SplitDNS("src.ts.net"); len(got) != 0 {
		t.Errorf("split-DNS = %v with dns off", got)
	}
}

// Turning DNS off in a running border removes the DNS VIP and split-DNS
// entry; the bridged service stays and keeps working.
func TestBorderDNSTurnedOff(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	echoBackend(t, ctx, b.src, "backend", 8080)
	cl := client(t, ctx, b.dst, "client")
	bd := b.border(b.deviceLink("web", "backend", "", 8080))
	r := startManager(t, loadBorder(t, bd), "")
	waitVIP(t, b.dstAPI, "svc:tnl-dns-src-ts-net-dns")

	off := false
	bd.DNS.Enabled = &off
	r.reconcile(loadBorder(t, bd))
	waitFor(t, 30*time.Second, "DNS VIP gone", func() bool {
		_, ok := b.dstAPI.Service("svc:tnl-dns-src-ts-net-dns")
		return !ok && len(b.dstAPI.SplitDNS("src.ts.net")) == 0
	})
	vip := waitVIP(t, b.dstAPI, b.serviceName("backend", ""))
	echoVia(t, ctx, cl, netip.AddrPortFrom(vip, 8080), "still up")
}
