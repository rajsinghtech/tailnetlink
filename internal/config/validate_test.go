package config_test

import (
	"strings"
	"testing"

	"github.com/rajsinghtech/tailnetlink/internal/config"
)

func TestValidateBridges(t *testing.T) {
	tn := map[string]config.TailnetConfig{"a": {}, "b": {}}
	tag := func(name string, mod func(*config.BridgeRule)) config.BridgeRule {
		r := config.BridgeRule{Name: name, SourceTailnet: "a", DestTailnets: []string{"b"}, SourceTag: "tag:web", Ports: []int{80}}
		if mod != nil {
			mod(&r)
		}
		return r
	}
	local := func(name string, srcs ...config.LocalSourceSpec) config.BridgeRule {
		return config.BridgeRule{Name: name, DestTailnets: []string{"b"}, LocalSources: srcs}
	}
	cases := []struct {
		name  string
		rules []config.BridgeRule
		want  string
	}{
		{"tag rule", []config.BridgeRule{tag("r", nil)}, ""},
		{"no name", []config.BridgeRule{tag("", nil)}, "name is required"},
		{"no dest", []config.BridgeRule{tag("r", func(r *config.BridgeRule) { r.DestTailnets = nil })}, "dest_tailnets is required"},
		{"unknown dest", []config.BridgeRule{tag("r", func(r *config.BridgeRule) { r.DestTailnets = []string{"c"} })}, `dest tailnet "c" is not configured`},
		{"unknown source", []config.BridgeRule{tag("r", func(r *config.BridgeRule) { r.SourceTailnet = "c" })}, `source tailnet "c" is not configured`},
		{"no source", []config.BridgeRule{tag("r", func(r *config.BridgeRule) { r.SourceTailnet = "" })}, "source_tailnet is required"},
		{"no ports", []config.BridgeRule{tag("r", func(r *config.BridgeRule) { r.Ports = nil })}, "ports is required"},
		{"port 0", []config.BridgeRule{tag("r", func(r *config.BridgeRule) { r.Ports = []int{0} })}, "out of range"},
		{"port too big", []config.BridgeRule{tag("r", func(r *config.BridgeRule) { r.Ports = []int{65536} })}, "out of range"},
		{"no selector", []config.BridgeRule{tag("r", func(r *config.BridgeRule) { r.SourceTag = "" })}, "must be specified"},
		{"devices", []config.BridgeRule{tag("r", func(r *config.BridgeRule) {
			r.SourceTag = ""
			r.SourceDevices = []config.DeviceSpec{{FQDN: "d.a", ShortName: "d"}}
		})}, ""},
		{"duplicate rule", []config.BridgeRule{tag("r", nil), tag("r", nil)}, "defined more than once"},
		{"short name twice in a rule", []config.BridgeRule{tag("r", func(r *config.BridgeRule) {
			r.SourceTag = ""
			r.SourceDevices = []config.DeviceSpec{{FQDN: "d.a", ShortName: "x"}}
			r.SourceServices = []config.ServiceSpec{{Name: "svc:s", ShortName: "x"}}
		})}, "appears more than once"},
		{"short name across rules", []config.BridgeRule{
			tag("r1", func(r *config.BridgeRule) { r.SourceServices = []config.ServiceSpec{{Name: "svc:s", ShortName: "x"}} }),
			local("r2", config.LocalSourceSpec{Addr: "db.lan:5432", ShortName: "x"}),
		}, `already used by rule "r1"`},
		{"short name too long", []config.BridgeRule{tag("r", func(r *config.BridgeRule) {
			r.SourceServices = []config.ServiceSpec{{Name: "svc:s", ShortName: strings.Repeat("a", 64)}}
		})}, "1 to 63 lowercase"},
		{"short name 63", []config.BridgeRule{tag("r", func(r *config.BridgeRule) {
			r.SourceServices = []config.ServiceSpec{{Name: "svc:s", ShortName: strings.Repeat("a", 63)}}
		})}, ""},
		{"short name upper case", []config.BridgeRule{tag("r", func(r *config.BridgeRule) {
			r.SourceDevices = []config.DeviceSpec{{FQDN: "d.a", ShortName: "Api"}}
		})}, "1 to 63 lowercase"},
		{"short name with dot", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "db.lan:5432", ShortName: "db.lan"})}, "1 to 63 lowercase"},
		{"local", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "127.0.0.1:8080", DNSName: "app.example"})}, ""},
		{"local named host", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "db.lan:5432"})}, ""},
		{"local with ports", []config.BridgeRule{func() config.BridgeRule {
			r := local("l", config.LocalSourceSpec{Addr: "db.lan:5432"})
			r.Ports = []int{1}
			return r
		}()}, "local rules must not set"},
		{"local bad addr", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "nope"})}, "is invalid"},
		{"local bad port", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "h:99999"})}, "invalid port"},
		{"local bad expose", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "h:80", ExposePort: 70000})}, "expose_port"},
		{"local negative expose", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "h:80", ExposePort: -1})}, "expose_port"},
		{"local ip needs dns", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "10.0.0.1:80"})}, "requires dns_name"},
		{"localhost needs dns", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "localhost:80"})}, "requires dns_name"},
		{"local multi port", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "10.0.0.1", DNSName: "app.example.com", ShortName: "app", Ports: config.LocalPortList(80, 443)})}, ""},
		{"local port map", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "db.lan", Ports: config.LocalPortMap(map[int]int{80: 8080})})}, ""},
		{"local empty ports", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "10.0.0.1", DNSName: "app.example.com", Ports: config.LocalPortList()})}, "ports is empty"},
		{"local duplicate port", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "10.0.0.1", DNSName: "app.example.com", Ports: config.LocalPortList(80, 80)})}, "duplicate exposed port"},
		{"local port zero", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "10.0.0.1", DNSName: "app.example.com", Ports: config.LocalPortList(0)})}, "out of range"},
		{"local port too big", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "10.0.0.1", DNSName: "app.example.com", Ports: config.LocalPortList(65536)})}, "out of range"},
		{"local backend port out of range", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "10.0.0.1", DNSName: "app.example.com", Ports: config.LocalPortMap(map[int]int{80: 0})})}, "backend port"},
		{"local addr port with ports", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "10.0.0.1:80", DNSName: "app.example.com", Ports: config.LocalPortList(80)})}, "also sets ports"},
		{"local expose with ports", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "10.0.0.1", DNSName: "app.example.com", ExposePort: 80, Ports: config.LocalPortList(80)})}, "expose_port cannot be combined"},
		{"local host-only needs ports", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "10.0.0.1", DNSName: "app.example.com"})}, "is invalid"},
		{"via tailnet", []config.BridgeRule{{
			Name: "r", SourceTailnet: "a", DestTailnets: []string{"b"},
			LocalSources: []config.LocalSourceSpec{{Addr: "10.20.0.10", DNSName: "db.example.com", ShortName: "db", Via: config.ViaTailnet, Ports: config.LocalPortList(80, 443)}},
		}}, ""},
		{"via tailnet name", []config.BridgeRule{{
			Name: "r", SourceTailnet: "a", DestTailnets: []string{"b"},
			LocalSources: []config.LocalSourceSpec{{Addr: "app.example.com", Via: config.ViaTailnet, Ports: config.LocalPortList(443)}},
		}}, ""},
		{"via pod is default", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "db.lan:5432"})}, ""},
		{"via pod rejects source", []config.BridgeRule{{
			Name: "r", SourceTailnet: "a", DestTailnets: []string{"b"},
			LocalSources: []config.LocalSourceSpec{{Addr: "db.lan:5432"}},
		}}, "must not set source_tailnet"},
		{"via tailnet needs source", []config.BridgeRule{{
			Name: "r", DestTailnets: []string{"b"},
			LocalSources: []config.LocalSourceSpec{{Addr: "10.20.0.10", DNSName: "db.example.com", Via: "tailnet", Ports: config.LocalPortList(443)}},
		}}, "source_tailnet is required"},
		{"via bad", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "db.lan:1", Via: "sidecar"})}, "must be"},
		{"exact zone", []config.BridgeRule{tag("r", func(r *config.BridgeRule) {
			r.SourceTag = ""
			r.SourceDevices = []config.DeviceSpec{{FQDN: "app.example.ts.net", DNSName: "app.corp.example.com", DNSZone: "app.corp.example.com"}}
		})}, ""},
		{"name inside zone", []config.BridgeRule{tag("r", func(r *config.BridgeRule) {
			r.SourceTag = ""
			r.SourceDevices = []config.DeviceSpec{{FQDN: "app.example.ts.net", DNSName: "app.corp.example.com", DNSZone: "corp.example.com"}}
		})}, ""},
		{"zone without name", []config.BridgeRule{tag("r", func(r *config.BridgeRule) {
			r.SourceTag = ""
			r.SourceDevices = []config.DeviceSpec{{FQDN: "app.example.ts.net", DNSZone: "app.corp.example.com"}}
		})}, "dns_zone requires dns_name"},
		{"name outside zone", []config.BridgeRule{tag("r", func(r *config.BridgeRule) {
			r.SourceTag = ""
			r.SourceServices = []config.ServiceSpec{{Name: "svc:app", DNSName: "app.corp.example.com", DNSZone: "other.example.com"}}
		})}, "must equal dns_zone"},
		{"bad zone", []config.BridgeRule{local("l", config.LocalSourceSpec{Addr: "127.0.0.1:80", DNSName: "app.corp.example.com", DNSZone: "not a zone"})}, "invalid character"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := config.Config{InstanceID: "x", Tailnets: tn, Bridges: c.rules}
			err := cfg.Validate()
			switch {
			case c.want == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Errorf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}
