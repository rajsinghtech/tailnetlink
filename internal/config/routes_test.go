package config_test

import (
	"net/netip"
	"testing"

	"github.com/rajsinghtech/tailnetlink/internal/config"
)

func TestAcceptedRouteAddrsUnionsFromTailnet(t *testing.T) {
	cfg := &config.Config{
		Bridges: []config.BridgeRule{
			{
				Name: "home/db", From: "home", DestTailnets: []string{"work"},
				LocalSources: []config.LocalSourceSpec{
					{Addr: "10.1.0.5:5432"},
					{Addr: "10.0.0.8:80"},
					{Addr: "db.internal:80"},
					{Addr: "10.1.0.5:5433"},
				},
			},
			{
				Name: "home/cache", From: "home", DestTailnets: []string{"partner"},
				LocalSources: []config.LocalSourceSpec{{Addr: "10.2.0.1:6379"}},
			},
			{
				Name: "work/api", From: "work", SourceTailnet: "work", DestTailnets: []string{"home"},
				LocalSources: []config.LocalSourceSpec{{Addr: "10.9.0.1:80"}},
			},
			{
				Name: "border-local", SourceTailnet: "src", DestTailnets: []string{"dst"},
				LocalSources: []config.LocalSourceSpec{{Addr: "192.0.2.10:80"}},
			},
		},
	}
	got := config.AcceptedRouteAddrs(cfg, "home")
	want := []netip.Addr{
		netip.MustParseAddr("10.0.0.8"),
		netip.MustParseAddr("10.1.0.5"),
		netip.MustParseAddr("10.2.0.1"),
	}
	if len(got) != len(want) {
		t.Fatalf("home addrs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("home addrs = %v, want %v", got, want)
		}
	}
	if other := config.AcceptedRouteAddrs(cfg, "work"); len(other) != 1 || other[0] != netip.MustParseAddr("10.9.0.1") {
		t.Fatalf("work addrs = %v", other)
	}
	if border := config.AcceptedRouteAddrs(cfg, "src"); len(border) != 1 || border[0] != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("source addrs = %v", border)
	}
	if config.AcceptedRouteAddrs(nil, "home") != nil || config.AcceptedRouteAddrs(cfg, "") != nil {
		t.Fatal("empty input returned addresses")
	}
}
