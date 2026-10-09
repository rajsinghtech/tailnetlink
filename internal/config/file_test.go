package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
)

func sample(top string) string {
	if top != "" {
		top = strings.TrimSpace(top)
		if !strings.HasSuffix(top, ",") {
			top += ","
		}
		top += "\n"
	}
	return `{
		"name": "test",
		` + top + `
		"tailnets": {
			"home": {"tailnet": "keiretsu.ts.net", "auth": {"client_id": "a", "client_secret_file": "/run/a"}},
			"work": {"tailnet": "example.ts.net", "auth": {"client_id": "b", "client_secret_env": "B"}}
		},
		"targets": {"web": {"in": "home", "tag": "tag:web", "ports": [80]}},
		"exports": [{"target": "web", "to": ["work"]}]
	}`
}

func TestFileDefaults(t *testing.T) {
	cfg, err := config.Parse([]byte(sample("")))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SharedNodes || cfg.InstanceID != "test" || cfg.PollInterval.Duration != 30*time.Second {
		t.Fatalf("cfg = shared %v id %q poll %s", cfg.SharedNodes, cfg.InstanceID, cfg.PollInterval)
	}
	home := cfg.Tailnets["home"]
	if home.Role != "node" || len(home.Tags) != 1 || home.Tags[0] != "tag:tailnetlink" || home.Hostname != "" {
		t.Fatalf("home = %+v", home)
	}
	if len(cfg.Bridges) != 1 || cfg.Bridges[0].Name != "web/web" || cfg.Bridges[0].SourceTag != "tag:web" || !cfg.Bridges[0].Multi {
		t.Fatalf("rule = %+v", cfg.Bridges[0])
	}
	if cfg.Bridges[0].BridgeRef("work") != "web/work" || cfg.Bridges[0].GrantName() != "web" {
		t.Fatalf("ref %s grant %s", cfg.Bridges[0].BridgeRef("work"), cfg.Bridges[0].GrantName())
	}
	if len(cfg.Bridges[0].Forwards) != 1 || cfg.Bridges[0].Forwards[0].Backend != 80 {
		t.Fatalf("forwards = %+v", cfg.Bridges[0].Forwards)
	}
}

func TestFileFanOutAndShapes(t *testing.T) {
	body := `{
		"name": "mesh",
		"state_dir": "/var/lib/tailnetlink",
		"ephemeral": true,
		"dns": false,
		"tailnets": {
			"home": {"tailnet": "keiretsu.ts.net", "auth": {"client_id": "a", "id_token_file": "/run/a"}, "node": {"hostname": "tnl-home"}},
			"work": {"tailnet": "example.ts.net", "auth": {"client_id": "b", "id_token_env": "WORK"}, "dns": true, "node": {"ephemeral": false}},
			"partner": {"tailnet": "partner.example.com", "auth": {"client_id": "c", "client_secret_file": "/run/c"}, "dns": false},
			"idle": {"tailnet": "lab.example.com", "auth": {"client_id": "d", "client_secret_file": "/run/d"}}
		},
		"targets": {
			"api": {"in": "home", "tag": "tag:api-server", "ports": [8080, 8443]},
			"db": {"in": "home", "addr": "10.20.0.10", "ports": {"5432": 5432}},
			"app": {"in": "home", "host": "app.internal.example.com", "ports": [443]},
			"ollama": {"in": "pod", "addr": "127.0.0.1", "ports": {"80": 11434}},
			"bill": {"in": "partner", "service": "svc:billing", "ports": [443]}
		},
		"exports": [
			{"target": "api", "to": ["work", "partner"], "dns_name": "{host}.api.example.com"},
			{"target": "db", "to": ["work"], "name": "db", "dns_name": "db.example.com", "dns_zone": "db.example.com"},
			{"target": "app", "to": ["work"]},
			{"target": "ollama", "to": ["work"], "dns_name": "ollama.example.com"},
			{"target": "bill", "to": ["home"], "name": "billing"}
		]
	}`
	cfg, err := config.Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Tailnets["idle"]; ok {
		t.Fatal("unreferenced tailnet was joined")
	}
	if len(cfg.Tailnets) != 3 {
		t.Fatalf("tailnets = %d", len(cfg.Tailnets))
	}
	if !cfg.Tailnets["home"].Ephemeral || cfg.Tailnets["home"].Hostname != "tnl-home" || !cfg.Tailnets["home"].OAuth.UsesIDToken() {
		t.Fatalf("home node = %+v", cfg.Tailnets["home"])
	}
	if !cfg.Tailnets["work"].Ephemeral || !cfg.Tailnets["work"].DNSDisabled {
		t.Fatalf("global ephemeral and dns did not apply to work: %+v", cfg.Tailnets["work"])
	}
	if !cfg.Tailnets["partner"].DNSDisabled {
		t.Fatal("partner dns stayed on")
	}
	by := map[string]config.BridgeRule{}
	for _, r := range cfg.Bridges {
		by[r.Name] = r
	}
	api := by["api/api"]
	if len(api.DestTailnets) != 2 || api.DestTailnets[0] != "work" || api.DestTailnets[1] != "partner" || api.DNSName != "{host}.api.example.com" {
		t.Fatalf("api = %+v", api)
	}
	db := by["db/db"]
	if db.SourceTailnet != "home" || db.LocalSources[0].DialVia() != config.ViaTailnet || db.LocalSources[0].Addr != "10.20.0.10" || db.DNSZone != "db.example.com" {
		t.Fatalf("db = %+v", db)
	}
	if by["app/app"].LocalSources[0].DNSName != "app.internal.example.com" || by["app/app"].SourceTailnet != "home" {
		t.Fatalf("app = %+v", by["app/app"])
	}
	if by["ollama/ollama"].SourceTailnet != "" || by["ollama/ollama"].LocalSources[0].DialVia() != config.ViaPod {
		t.Fatalf("ollama = %+v", by["ollama/ollama"])
	}
	if fw := by["ollama/ollama"].LocalSources[0]; fw.Ports.Configured() {
		host, ports, err := fw.Forwards()
		if err != nil || host != "127.0.0.1" || len(ports) != 1 || ports[0].Expose != 80 || ports[0].Backend != 11434 {
			t.Fatalf("ollama forwards %s %+v %v", host, ports, err)
		}
	}
	if by["bill/billing"].SourceServices[0].Name != "svc:billing" || by["bill/billing"].DestTailnets[0] != "home" {
		t.Fatalf("bill = %+v", by["bill/billing"])
	}
}

func TestFileRejectsOldAndUnknown(t *testing.T) {
	bad := []struct{ body, want string }{
		{`{"instance_id":"me","bridges":[]}`, "README"},
		{`{"name":"t","source":{"tailnet":"a"},"dest":{"tailnet":"b"}}`, "old config"},
		{strings.Replace(sample(""), `"tag": "tag:web"`, `"tag": "tag:web", "device": "a.example"`, 1), "only one of"},
		{sample(`"nope": 1`), "README"},
		{`{"name":"pod","tailnets":{"pod":{"tailnet":"a.ts.net","auth":{"client_id":"a","client_secret_file":"/a"}}},"targets":{},"exports":[]}`, "reserved"},
		{`{"name":"t","tailnets":{"home":{"tailnet":"a.ts.net","auth":{"client_id":"a","client_secret_file":"/a"}},"work":{"tailnet":"a.ts.net","auth":{"client_id":"b","client_secret_file":"/b"}}},"targets":{"web":{"in":"home","tag":"tag:web","ports":[1]}},"exports":[{"target":"web","to":["work"]}]}`, "more than once"},
		{`{"name":"t","tailnets":{"home":{"tailnet":"a.ts.net","auth":{"client_id":"a","client_secret_file":"/a"}}},"targets":{"web":{"in":"home","tag":"tag:web","ports":[1]}},"exports":[{"target":"web","to":["home"]}]}`, "target's in"},
		{`{"name":"t","tailnets":{"home":{"tailnet":"a.ts.net","auth":{"client_id":"a","client_secret_file":"/a"}},"work":{"tailnet":"b.ts.net","auth":{"client_id":"b","client_secret_file":"/b"}}},"targets":{"web":{"in":"home","tag":"tag:web","ports":[1]},"db":{"in":"home","device":"db.a.ts.net","ports":[1]}},"exports":[{"target":"web","to":["work"],"name":"same"},{"target":"db","to":["work"],"name":"same"}]}`, "export name"},
		{`{"name":"t","tailnets":{"home":{"tailnet":"a.ts.net","auth":{"client_id":"a","client_secret_file":"/a"}},"work":{"tailnet":"b.ts.net","auth":{"client_id":"b","client_secret_file":"/b"}}},"targets":{"web":{"in":"home","tag":"tag:web","ports":[1]}},"exports":[{"target":"web","to":["work"],"dns_name":"app.example.com"}]}`, "{host}"},
		{`{"name":"t","tailnets":{"home":{"tailnet":"a.ts.net","auth":{"client_id":"a","client_secret_file":"/a"}},"work":{"tailnet":"b.ts.net","auth":{"client_id":"b","client_secret_file":"/b"}}},"targets":{"db":{"in":"home","addr":"10.0.0.1","ports":[1]}},"exports":[{"target":"db","to":["work"]}]}`, "dns_name"},
		{`{"name":"t","tailnets":{"home":{"tailnet":"a.ts.net","auth":{"client_id":"a","client_secret_file":"/a"}},"work":{"tailnet":"b.ts.net","auth":{"client_id":"b","client_secret_file":"/b"}}},"targets":{"ollama":{"in":"pod","tag":"tag:x","ports":[1]}},"exports":[{"target":"ollama","to":["work"]}]}`, "pod"},
		{`{"name":"t","tailnets":{"home":{"tailnet":"a.ts.net","auth":{"client_id":"a","client_secret_env":"A","id_token_file":"/j"}}},"targets":{},"exports":[]}`, "only one of"},
	}
	for _, c := range bad {
		_, err := config.Parse([]byte(c.body))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("Parse error %v, want %q\n%s", err, c.want, c.body)
		}
	}
}

func TestExampleConfigParses(t *testing.T) {
	for _, name := range []string{"config.example.json"} {
		b, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := config.Parse(b); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
