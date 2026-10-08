package bridge

import (
	"net/netip"
	"testing"

	"tailscale.com/types/key"
)

func TestMinimalCoverPicksOnlyTheMatchingPrefix(t *testing.T) {
	peer := key.NewNode().Public()
	other := key.NewNode().Public()
	routes := []advertised{
		{peer, netip.MustParsePrefix("10.20.0.0/24")},
		{peer, netip.MustParsePrefix("10.99.0.0/24")},
		{other, netip.MustParsePrefix("10.0.0.0/8")},
	}
	p, owner, ok := minimalCover(routes, netip.MustParseAddr("10.20.0.10"))
	if !ok || p != netip.MustParsePrefix("10.20.0.0/24") || owner != peer {
		t.Fatalf("cover = %s %s %v", p, owner, ok)
	}
	if _, _, ok := minimalCover(routes, netip.MustParseAddr("100.64.0.1")); ok {
		t.Fatal("a tailscale IP must not take a subnet route")
	}
	if _, _, ok := minimalCover(routes, netip.MustParseAddr("192.0.2.1")); ok {
		t.Fatal("uncovered address matched a route")
	}
}
