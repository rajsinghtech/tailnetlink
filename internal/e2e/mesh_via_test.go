package e2e

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"tailscale.com/ipn"
	"tailscale.com/types/dnstype"
)

// TestMeshBridgeViaTailnet proves a bridges entry can dial a subnet address
// through the node of the tailnet it leaves. The home node accepts only the
// prefix that covers the name, not the router's other prefix, and work's
// node accepts nothing. No sidecar, no TUN, and the other devices stay put.
func TestMeshBridgeViaTailnet(t *testing.T) {
	ctx := e2eSetup(t)
	g := newMeshRig(t)
	home, work := g.nets["home"], g.nets["work"]
	home.control.DNSConfig.Routes = map[string][]*dnstype.Resolver{
		"internal.example.com": {{Addr: "10.20.0.53"}},
	}

	router := home.node(t, ctx, "router")
	lc, err := router.srv.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.20.0.0/24"),
		netip.MustParsePrefix("10.99.0.0/24"),
	}
	if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		AdvertiseRoutesSet: true,
		Prefs:              ipn.Prefs{AdvertiseRoutes: prefixes},
	}); err != nil {
		t.Fatal(err)
	}
	home.control.SetSubnetRoutes(router.key, prefixes)

	var saw99 atomic.Bool
	router.srv.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (func(net.Conn), bool) {
		switch dst.String() {
		case "10.20.0.53:53":
			return serveDNSA("app.internal.example.com.", net.ParseIP("10.20.0.10")), true
		case "10.20.0.10:8080":
			return serveEchoConn, true
		case "10.99.0.9:8080":
			return func(c net.Conn) {
				saw99.Store(true)
				c.Close()
			}, true
		default:
			return nil, false
		}
	})
	// Start the bystander before the snapshot so its routable IPs are
	// already in the peer record the comparison keeps.
	_ = home.node(t, ctx, "bystander")

	beforeHome := controlSnap(t, home)
	beforeWork := controlSnap(t, work)

	path := filepath.Join(t.TempDir(), "tailnetlink.json")
	bridge := `{"from":"home","to":["work"],"links":[{
		"name":"db",
		"local":[{
			"addr":"app.internal.example.com",
			"via":"tailnet",
			"dns_name":"db.example.com",
			"short_name":"db",
			"ports":[8080]
		}]
	}]}`
	body := g.meshJSON([]string{"home", "work"}, bridge)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var routed bool
	for _, rule := range cfg.Bridges {
		if rule.Name == "home/db" && rule.SourceTailnet == "home" && rule.From == "home" {
			routed = true
		}
	}
	if !routed {
		t.Fatalf("mesh did not set the from key as the dial tailnet: %+v", cfg.Bridges)
	}

	r := startManager(t, cfg, "")
	id := "home/db/local/work/app.internal.example.com/db"
	waitFor(t, 45*time.Second, "routed bridge active", func() bool {
		status, _ := r.bridgeStatus(id)
		return status == "active"
	})
	waitFor(t, 30*time.Second, "only 10.20.0.0/24 accepted on home", func() bool {
		return onlyPrefix(r.m.AcceptedRoutes("home"), "10.20.0.0/24")
	})
	on, err := r.m.RouteAll(ctx, "home")
	if err != nil || on {
		t.Fatalf("RouteAll = %v, %v; want false", on, err)
	}
	if got := r.m.AcceptedRoutes("work"); len(got) != 0 {
		t.Fatalf("work accepted routes: %v", got)
	}

	cli := client(t, ctx, work, "client")
	vip := waitVIP(t, g.apis["work"], "svc:db")
	echoVia(t, ctx, cli, netip.AddrPortFrom(vip, 8080), "mesh-via")

	if _, err := r.m.DialSource(ctx, "home", "10.99.0.9:8080"); err == nil || !strings.Contains(err.Error(), "no subnet route") {
		t.Fatalf("dial of unconfigured prefix = %v", err)
	}
	if saw99.Load() {
		t.Fatal("traffic reached 10.99.0.9; that prefix was accepted")
	}
	if !sameSnap(beforeHome, controlSnap(t, home)) || !sameSnap(beforeWork, controlSnap(t, work)) {
		t.Fatalf("tailnet changed\nhome before %s\nhome after  %s\nwork before %s\nwork after  %s",
			beforeHome, controlSnap(t, home), beforeWork, controlSnap(t, work))
	}
	assertLinkHasNoApprovedRoutes(t, home, "tailnetlink-home", true)
	assertLinkHasNoApprovedRoutes(t, work, "tailnetlink-work", true)
	assertNoTun(t)
}
