package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
)

func meshSide(tailnet, id, secret string) string {
	return `{
		"tailnet": "` + tailnet + `",
		"oauth": {"client_id": "` + id + `", "client_secret_file": "` + secret + `"},
		"tags": ["tag:tailnetlink"]
	}`
}

func meshExample() string {
	b, err := os.ReadFile(filepath.Join("..", "..", "config.mesh.example.json"))
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestMeshExample(t *testing.T) {
	cfg, err := config.Parse([]byte(meshExample()))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SharedNodes || cfg.InstanceID != "mesh" || cfg.StateDir != "/var/lib/tailnetlink" {
		t.Fatalf("process = shared %v id %q dir %q", cfg.SharedNodes, cfg.InstanceID, cfg.StateDir)
	}
	if cfg.PollInterval.Duration != 5*time.Second || cfg.DNSDisabled {
		t.Fatalf("intervals/dns = %s %v", cfg.PollInterval, cfg.DNSDisabled)
	}
	if len(cfg.Tailnets) != 3 {
		t.Fatalf("tailnets = %d", len(cfg.Tailnets))
	}
	for _, key := range []string{"home", "work", "partner"} {
		tn := cfg.Tailnets[key]
		if tn.Role != "node" || tn.Ephemeral {
			t.Errorf("%s role=%q ephemeral=%v", key, tn.Role, tn.Ephemeral)
		}
	}
	if cfg.Tailnets["home"].Tailnet != "keiretsu.ts.net" || cfg.Tailnets["work"].Tailnet != "example.ts.net" || cfg.Tailnets["partner"].Tailnet != "partner.example.com" {
		t.Fatalf("tailnet names = %+v", cfg.Tailnets)
	}
	if cfg.Tailnets["home"].DNSDisabled || cfg.Tailnets["work"].DNSDisabled || !cfg.Tailnets["partner"].DNSDisabled {
		t.Fatalf("dns flags home=%v work=%v partner=%v", cfg.Tailnets["home"].DNSDisabled, cfg.Tailnets["work"].DNSDisabled, cfg.Tailnets["partner"].DNSDisabled)
	}
	if cfg.Tailnets["work"].Authz.Mode != config.AuthzAllowLogins {
		t.Errorf("work authz = %+v", cfg.Tailnets["work"].Authz)
	}
	if len(cfg.Bridges) != 3 {
		t.Fatalf("bridges = %+v", cfg.Bridges)
	}
	byName := map[string]config.BridgeRule{}
	for _, r := range cfg.Bridges {
		byName[r.Name] = r
	}
	api := byName["home/api"]
	if api.From != "home" || api.Link != "api" || api.SourceTailnet != "home" || api.SourceTag != "tag:api-server" || len(api.DestTailnets) != 2 || api.DestTailnets[0] != "work" || api.DestTailnets[1] != "partner" || api.Ports[0] != 8080 || api.Ports[1] != 8443 {
		t.Errorf("home/api = %+v", api)
	}
	if api.BridgeRef("work") != "home/work/api" || api.BridgeRef("partner") != "home/partner/api" {
		t.Errorf("bridge refs = %s %s", api.BridgeRef("work"), api.BridgeRef("partner"))
	}
	builds := byName["work/builds"]
	if builds.SourceTailnet != "work" || len(builds.DestTailnets) != 1 || builds.DestTailnets[0] != "home" || builds.SourceTag != "tag:build-runner" {
		t.Errorf("work/builds = %+v", builds)
	}
	billing := byName["partner/billing"]
	if billing.SourceTailnet != "partner" || billing.DestTailnets[0] != "work" || billing.SourceServices[0].Name != "svc:billing" || billing.Ports[0] != 443 {
		t.Errorf("partner/billing = %+v", billing)
	}
}

func TestMeshEmptyBridges(t *testing.T) {
	body := `{
		"name": "mesh",
		"tailnets": {"home": ` + meshSide("keiretsu.ts.net", "home", "/run/home") + `},
		"bridges": []
	}`
	cfg, err := config.Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SharedNodes || len(cfg.Bridges) != 0 || len(cfg.Tailnets) != 1 {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestMeshLocalLinkSetsFrom(t *testing.T) {
	body := `{
		"name": "mesh",
		"tailnets": {
			"home": ` + meshSide("keiretsu.ts.net", "home", "/run/home") + `,
			"work": ` + meshSide("example.ts.net", "work", "/run/work") + `
		},
		"bridges": [{
			"from": "home",
			"to": ["work"],
			"links": [{"name": "db", "local": [{"addr": "10.1.0.5:5432", "dns_name": "db.example.com"}]}]
		}]
	}`
	cfg, err := config.Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Bridges[0]
	if r.Name != "home/db" || r.From != "home" || r.SourceTailnet != "" || r.LocalSources[0].Addr != "10.1.0.5:5432" {
		t.Fatalf("local rule = %+v", r)
	}
}

func TestMeshErrors(t *testing.T) {
	ok := meshExample()
	cases := map[string]struct{ body, want string }{
		"both shapes":     {`{"name":"mesh","source":{"tailnet":"a"},"tailnets":{}}`, "not both"},
		"no name":         {strings.Replace(ok, `"name": "mesh"`, `"name": ""`, 1), "name is required"},
		"bad key":         {strings.Replace(ok, `"home"`, `"Home"`, 1), "tailnet key"},
		"dup tailnet":     {strings.Replace(ok, "example.ts.net", "keiretsu.ts.net", 1), "more than once"},
		"unknown from":    {strings.Replace(ok, `"from": "home"`, `"from": "lab"`, 1), "not a tailnet key"},
		"empty to":        {strings.Replace(ok, `"to": ["work", "partner"]`, `"to": []`, 1), "to is required"},
		"self":            {strings.Replace(ok, `"to": ["home"]`, `"to": ["work"]`, 1), "includes itself"},
		"dup to":          {strings.Replace(ok, `"to": ["work", "partner"]`, `"to": ["work", "work"]`, 1), "duplicated"},
		"unknown to":      {strings.Replace(ok, `"to": ["home"]`, `"to": ["lab"]`, 1), "not a tailnet key"},
		"empty links":     {strings.Replace(ok, `"links": [{"name": "builds", "tag": "tag:build-runner", "ports": [22, 443]}]`, `"links": []`, 1), "links is empty"},
		"dup link":        {strings.Replace(ok, `"links": [{"name": "api", "tag": "tag:api-server", "ports": [8080, 8443]}]`, `"links": [{"name": "api", "tag": "tag:api-server", "ports": [80]}, {"name": "api", "tag": "tag:other", "ports": [81]}]`, 1), "defined more than once"},
		"per-tailnet dir": {strings.Replace(ok, `"tags": ["tag:tailnetlink"]`, `"tags": ["tag:tailnetlink"], "node": {"state_dir": "/tmp/x"}`, 1), "state_dir"},
		"no tailnets":     {`{"name":"mesh","tailnets":{}}`, "tailnets is required"},
	}
	body := strings.Replace(ok,
		`{"name": "api", "tag": "tag:api-server", "ports": [8080, 8443]}`,
		`{"name": "api", "devices": [{"fqdn": "api.keiretsu.ts.net", "short_name": "billing"}], "ports": [8080]}`,
		1)
	body = strings.Replace(body,
		`{"name": "billing", "services": [{"name": "svc:billing"}], "ports": [443]}`,
		`{"name": "billing", "devices": [{"fqdn": "bill.partner.example.com", "short_name": "billing"}], "ports": [443]}`,
		1)
	cases["same short name"] = struct{ body, want string }{body, `short_name "billing"`}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := config.Parse([]byte(c.body))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestMeshGlobalDNSWins(t *testing.T) {
	body := strings.Replace(meshExample(), `"name": "mesh"`, `"name": "mesh", "dns": {"enabled": false}`, 1)
	cfg, err := config.Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DNSDisabled || !cfg.Tailnets["home"].DNSDisabled || !cfg.Tailnets["partner"].DNSDisabled {
		t.Fatalf("dns home=%v partner=%v global=%v", cfg.Tailnets["home"].DNSDisabled, cfg.Tailnets["partner"].DNSDisabled, cfg.DNSDisabled)
	}
}

func TestMeshTopLevelEphemeralOrs(t *testing.T) {
	body := strings.Replace(meshExample(), `"node": {"state_dir": "/var/lib/tailnetlink"}`, `"node": {"state_dir": "/var/lib/tailnetlink", "ephemeral": true}`, 1)
	cfg, err := config.Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Tailnets["home"].Ephemeral || !cfg.Tailnets["partner"].Ephemeral {
		t.Fatal("top-level ephemeral did not apply to every node")
	}
}
