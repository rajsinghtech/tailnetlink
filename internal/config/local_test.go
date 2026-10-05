package config_test

import (
	"testing"

	"github.com/rajsinghtech/tailnetlink/internal/config"
)

func TestLocalSourceNaming(t *testing.T) {
	cases := []struct {
		spec      config.LocalSourceSpec
		dnsName   string // "" means an error
		shortName string
		port      int
	}{
		{config.LocalSourceSpec{Addr: "localhost:11434", DNSName: "ollama.dest.ts.net"}, "ollama.dest.ts.net", "ollama", 11434},
		{config.LocalSourceSpec{Addr: "ai.localtailnet.ts.net:8080"}, "ai.localtailnet.ts.net", "ai", 8080},
		{config.LocalSourceSpec{Addr: "local.app.custom.domain:80", ExposePort: 443}, "local.app.custom.domain", "local", 443},
		{config.LocalSourceSpec{Addr: "DB.Lan:5432"}, "DB.Lan", "db", 5432},
		{config.LocalSourceSpec{Addr: "singleword:1"}, "singleword", "singleword", 1},
		{config.LocalSourceSpec{Addr: "localhost:3000", DNSName: "app.dest.ts.net", ShortName: "custom"}, "app.dest.ts.net", "custom", 3000},
		{config.LocalSourceSpec{Addr: "localhost:11434"}, "", "", 11434},
		{config.LocalSourceSpec{Addr: "192.168.1.5:8080"}, "", "", 8080},
		{config.LocalSourceSpec{Addr: "[::1]:8080"}, "", "", 8080},
		{config.LocalSourceSpec{Addr: "0.0.0.0:8080", ShortName: "x"}, "", "x", 8080},
	}
	for _, c := range cases {
		got, err := c.spec.EffectiveDNSName()
		switch {
		case c.dnsName == "" && err == nil:
			t.Errorf("%+v: DNS name %q, want an error", c.spec, got)
		case c.dnsName != "" && (err != nil || got != c.dnsName):
			t.Errorf("%+v: DNS name %q, %v; want %q", c.spec, got, err, c.dnsName)
		}
		if sn := c.spec.EffectiveShortName(); sn != c.shortName {
			t.Errorf("%+v: short name %q, want %q", c.spec, sn, c.shortName)
		}
		if p, err := c.spec.EffectivePort(); err != nil || p != c.port {
			t.Errorf("%+v: port %d, %v; want %d", c.spec, p, err, c.port)
		}
	}
}

func TestLocalSourcePortErrors(t *testing.T) {
	for _, spec := range []config.LocalSourceSpec{
		{Addr: "h:80", ExposePort: -1},
		{Addr: "h:80", ExposePort: 70000},
		{Addr: "nope"},
		{Addr: "h:0"},
		{Addr: "h:x"},
	} {
		if p, err := spec.EffectivePort(); err == nil {
			t.Errorf("%+v: port %d, want an error", spec, p)
		}
	}
	if _, err := (config.LocalSourceSpec{Addr: "nope"}).EffectiveDNSName(); err == nil {
		t.Error("bad addr: want an error")
	}
}

// Two local sources whose names derive to the same short name collide in
// the destination, and validation catches it.
func TestLocalSourceDerivedShortNameConflict(t *testing.T) {
	cfg := config.Config{InstanceID: "x", Tailnets: map[string]config.TailnetConfig{"b": {}},
		Bridges: []config.BridgeRule{{Name: "l", DestTailnets: []string{"b"}, LocalSources: []config.LocalSourceSpec{
			{Addr: "db.one.lan:5432"}, {Addr: "db.two.lan:5432"},
		}}}}
	if err := cfg.Validate(); err == nil {
		t.Error("want a short name conflict")
	}
	cfg.Bridges[0].LocalSources[1].ShortName = "db2"
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	cfg.Bridges[0].LocalSources[1].Addr = ":5432"
	if err := cfg.Validate(); err == nil {
		t.Error("addr with no host: want an error")
	}
}
