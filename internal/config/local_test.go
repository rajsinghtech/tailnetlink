package config_test

import (
	"encoding/json"
	"reflect"
	"strings"
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

func TestLocalForwards(t *testing.T) {
	cases := []struct {
		name string
		spec config.LocalSourceSpec
		host string
		want []config.LocalForward
	}{
		{"host port", config.LocalSourceSpec{Addr: "db.lan:5432"}, "db.lan", []config.LocalForward{{Expose: 5432, Backend: 5432}}},
		{"expose port", config.LocalSourceSpec{Addr: "db.lan:8080", ExposePort: 80}, "db.lan", []config.LocalForward{{Expose: 80, Backend: 8080}}},
		{"ipv6", config.LocalSourceSpec{Addr: "[::1]:8080", DNSName: "app.example.com"}, "::1", []config.LocalForward{{Expose: 8080, Backend: 8080}}},
		{"list keeps order", config.LocalSourceSpec{Addr: "10.0.0.1", DNSName: "app.example.com", Ports: config.LocalPortList(443, 80)}, "10.0.0.1", []config.LocalForward{{Expose: 443, Backend: 443}, {Expose: 80, Backend: 80}}},
		{"map sorts keys", config.LocalSourceSpec{Addr: "[::1]", DNSName: "app.example.com", Ports: config.LocalPortMap(map[int]int{443: 8443, 80: 8080})}, "::1", []config.LocalForward{{Expose: 80, Backend: 8080}, {Expose: 443, Backend: 8443}}},
		{"named host list", config.LocalSourceSpec{Addr: "db.lan", Ports: config.LocalPortList(5432)}, "db.lan", []config.LocalForward{{Expose: 5432, Backend: 5432}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host, got, err := c.spec.Forwards()
			if err != nil {
				t.Fatalf("Forwards: %v", err)
			}
			if host != c.host || !reflect.DeepEqual(got, c.want) {
				t.Fatalf("Forwards = %s, %#v; want %s, %#v", host, got, c.host, c.want)
			}
		})
	}
	spec := config.LocalSourceSpec{Addr: "10.0.0.1", DNSName: "app.example.com", Ports: config.LocalPortList(80, 443)}
	if _, err := spec.EffectivePort(); err == nil {
		t.Fatal("EffectivePort on a multi-port target: want an error")
	}
	if name, err := spec.EffectiveDNSName(); err != nil || name != "app.example.com" {
		t.Fatalf("DNS name = %q, %v", name, err)
	}
	if spec.EffectiveShortName() != "app" {
		t.Fatalf("short name = %q", spec.EffectiveShortName())
	}
}

func TestLocalPortsJSON(t *testing.T) {
	raw := `{
		"name": "app",
		"dest_tailnets": ["b"],
		"local_sources": [{
			"addr": "10.0.0.1",
			"dns_name": "app.example.com",
			"short_name": "app",
			"ports": {"443": 8443, "80": 8080}
		}]
	}`
	var rule config.BridgeRule
	if err := json.Unmarshal([]byte(raw), &rule); err != nil {
		t.Fatal(err)
	}
	host, fw, err := rule.LocalSources[0].Forwards()
	if err != nil {
		t.Fatal(err)
	}
	want := []config.LocalForward{{Expose: 80, Backend: 8080}, {Expose: 443, Backend: 8443}}
	if host != "10.0.0.1" || !reflect.DeepEqual(fw, want) {
		t.Fatalf("Forwards = %s %#v", host, fw)
	}
	out, err := json.Marshal(rule.LocalSources[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"80":8080`) || strings.Contains(string(out), "expose_port") {
		t.Fatalf("marshal = %s", out)
	}

	var list config.LocalSourceSpec
	if err := json.Unmarshal([]byte(`{"addr":"10.0.0.1","ports":[80,443]}`), &list); err != nil {
		t.Fatal(err)
	}
	again, err := json.Marshal(list.Ports)
	if err != nil || string(again) != "[80,443]" {
		t.Fatalf("list marshal = %s, %v", again, err)
	}

	for _, bad := range []string{
		`{"addr":"10.0.0.1","ports":[]}`,
		`{"addr":"10.0.0.1","ports":{}}`,
		`{"addr":"10.0.0.1","ports":{"080":1}}`,
		`{"addr":"10.0.0.1","ports":"80"}`,
		`{"addr":"10.0.0.1","ports":[80,80]}`,
		`{"addr":"10.0.0.1:80","ports":[80]}`,
	} {
		var spec config.LocalSourceSpec
		err := json.Unmarshal([]byte(bad), &spec)
		if err != nil {
			continue
		}
		if _, _, err := spec.Forwards(); err == nil {
			t.Errorf("%s: want an error", bad)
		}
	}
}
