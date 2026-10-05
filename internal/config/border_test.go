package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
)

// borderJSON is a valid border named "test" with extra fields spliced in.
// Without a "links" field in extra it gets one tag link.
func borderJSON(extra string) string {
	links := `"links": [{"name": "web", "tag": "tag:web", "ports": [80]}]`
	if strings.Contains(extra, `"links"`) {
		links = ""
	}
	parts := []string{
		`"name": "test"`,
		`"source": {"tailnet": "a.ts.net", "oauth": {"client_id": "a", "client_secret_file": "/run/a"}, "tags": ["tag:tailnetlink"]}`,
		`"dest": {"tailnet": "b.ts.net", "oauth": {"client_id": "b", "client_secret_env": "B"}, "tags": ["tag:tailnetlink"]}`,
	}
	for _, p := range []string{extra, links} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return "{" + strings.Join(parts, ",\n") + "}"
}

func TestBorderDefaults(t *testing.T) {
	cfg, err := config.Parse([]byte(borderJSON("")))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InstanceID != "test" {
		t.Errorf("owner = %q", cfg.InstanceID)
	}
	if cfg.PollInterval.Duration != 30*time.Second || cfg.DialTimeout.Duration != 10*time.Second || cfg.AuthKeyExpiry.Duration != time.Hour {
		t.Errorf("durations = %v %v %v", cfg.PollInterval, cfg.DialTimeout, cfg.AuthKeyExpiry)
	}
	if cfg.ListenAddr != "127.0.0.1:8888" || cfg.MetricsAddr != "127.0.0.1:9090" {
		t.Errorf("addrs = %q %q", cfg.ListenAddr, cfg.MetricsAddr)
	}
	if !cfg.UIEnabled() || cfg.UIServiceName() != "svc:tailnetlink" || cfg.DNSDisabled {
		t.Errorf("ui/dns defaults wrong: %+v", cfg)
	}
	src, dst := cfg.Tailnets["test-src"], cfg.Tailnets["test-dst"]
	if len(cfg.Tailnets) != 2 || src.Tailnet != "a.ts.net" || dst.Tailnet != "b.ts.net" || src.Ephemeral || !src.HasAuth() || !dst.HasAuth() {
		t.Errorf("tailnets = %+v", cfg.Tailnets)
	}
	if len(cfg.Bridges) != 1 {
		t.Fatalf("bridges = %+v", cfg.Bridges)
	}
	r := cfg.Bridges[0]
	if r.Name != "web" || r.SourceTailnet != "test-src" || len(r.DestTailnets) != 1 || r.DestTailnets[0] != "test-dst" || r.SourceTag != "tag:web" || r.Ports[0] != 80 {
		t.Errorf("rule = %+v", r)
	}
}

func TestBorderEverySetting(t *testing.T) {
	cfg, err := config.Parse([]byte(borderJSON(`
		"node": {"state_dir": "/var/lib/tnl", "ephemeral": true},
		"dns": {"enabled": false},
		"ui": {"enabled": false, "service_name": "svc:tnl-ui", "listen_addr": "127.0.0.1:1"},
		"metrics": {"listen_addr": ":9090"},
		"poll_interval": "5s", "dial_timeout": "2s", "auth_key_expiry": "10m",
		"links": [
			{"name": "dev", "devices": [{"fqdn": "x.a.ts.net", "short_name": "x", "dns_name": "x.corp.internal"}], "ports": [22]},
			{"name": "svc", "services": [{"name": "svc:db"}], "ports": [5432]},
			{"name": "loc", "local": [{"addr": "127.0.0.1:3000", "dns_name": "graf.home.internal"}]}
		]`)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StateDir != "/var/lib/tnl" || !cfg.Tailnets["test-src"].Ephemeral || !cfg.Tailnets["test-dst"].Ephemeral {
		t.Errorf("node settings lost: %+v", cfg)
	}
	if !cfg.DNSDisabled || cfg.UIEnabled() || cfg.UIServiceName() != "svc:tnl-ui" || cfg.ListenAddr != "127.0.0.1:1" || cfg.MetricsAddr != ":9090" {
		t.Errorf("dns/ui/metrics lost: %+v", cfg)
	}
	if cfg.PollInterval.Duration != 5*time.Second || cfg.DialTimeout.Duration != 2*time.Second || cfg.AuthKeyExpiry.Duration != 10*time.Minute {
		t.Errorf("durations lost")
	}
	if len(cfg.Bridges) != 3 || cfg.Bridges[0].SourceDevices[0].ShortName != "x" || cfg.Bridges[1].SourceServices[0].Name != "svc:db" {
		t.Fatalf("bridges = %+v", cfg.Bridges)
	}
	loc := cfg.Bridges[2]
	if loc.SourceTailnet != "" || len(loc.LocalSources) != 1 || loc.DestTailnets[0] != "test-dst" {
		t.Errorf("local link = %+v", loc)
	}
}

func TestBorderErrors(t *testing.T) {
	base := borderJSON("")
	cases := map[string]struct{ body, want string }{
		"bad json":       {`{`, "parse config"},
		"trailing":       {base + `{}`, "parse config"},
		"unknown field":  {borderJSON(`"pol_interval": "5s"`), "unknown field"},
		"no name":        {strings.Replace(base, `"name": "test"`, `"name": ""`, 1), "name is required"},
		"bad name":       {strings.Replace(base, `"name": "test"`, `"name": "Test_1"`, 1), "lowercase"},
		"long name":      {strings.Replace(base, `"name": "test"`, `"name": "`+strings.Repeat("a", 41)+`"`, 1), "1 to 40"},
		"no source":      {strings.Replace(base, `"tailnet": "a.ts.net"`, `"tailnet": ""`, 1), "source: tailnet is required"},
		"no client id":   {strings.Replace(base, `"client_id": "b"`, `"client_id": ""`, 1), "dest: oauth.client_id"},
		"no secret ref":  {strings.Replace(base, `, "client_secret_env": "B"`, ``, 1), "client_secret_file or client_secret_env"},
		"inline secret":  {strings.Replace(base, `"client_secret_env": "B"`, `"client_secret": "hunter2"`, 1), "oauth.client_secret is not supported"},
		"both secrets":   {strings.Replace(base, `"client_secret_env": "B"`, `"client_secret_env": "B", "client_secret_file": "/f"`, 1), "only one of"},
		"no tags":        {strings.Replace(base, `"tags": ["tag:tailnetlink"]}`+",\n"+`"dest"`, `"tags": []}`+",\n"+`"dest"`, 1), "source: tags is required"},
		"no links":       {borderJSON(`"links": []`), "at least one link"},
		"link no name":   {borderJSON(`"links": [{"tag": "tag:x", "ports": [1]}]`), "links[0]: name is required"},
		"no selector":    {borderJSON(`"links": [{"name": "x", "ports": [1]}]`), "needs one of"},
		"two selectors":  {borderJSON(`"links": [{"name": "x", "tag": "tag:x", "services": [{"name": "svc:a"}], "ports": [1]}]`), "only one of"},
		"no ports":       {borderJSON(`"links": [{"name": "x", "tag": "tag:x"}]`), "ports is required"},
		"port range":     {borderJSON(`"links": [{"name": "x", "tag": "tag:x", "ports": [70000]}]`), "port"},
		"local ports":    {borderJSON(`"links": [{"name": "x", "local": [{"addr": "a.lan:1"}], "ports": [1]}]`), "doesn't apply"},
		"local bad addr": {borderJSON(`"links": [{"name": "x", "local": [{"addr": "nope"}]}]`), "addr"},
		"dup short":      {borderJSON(`"links": [{"name": "x", "devices": [{"fqdn": "a.a.ts.net", "short_name": "s"}, {"fqdn": "b.a.ts.net", "short_name": "s"}], "ports": [1]}]`), "s"},
		"dup link":       {borderJSON(`"links": [{"name": "x", "tag": "tag:x", "ports": [1]}, {"name": "x", "tag": "tag:y", "ports": [1]}]`), "x"},
		"short poll":     {borderJSON(`"poll_interval": "1ms"`), "too short"},
		"bad duration":   {borderJSON(`"poll_interval": "soon"`), "parse config"},
		"bad ui service": {borderJSON(`"ui": {"service_name": "tailnetlink"}`), "ui.service_name"},
		"bad short_name": {borderJSON(`"links": [{"name": "x", "devices": [{"fqdn": "a.a.ts.net", "short_name": "Bad_Name"}], "ports": [1]}]`), "short_name"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := config.Parse([]byte(c.body))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want it to mention %q", err, c.want)
			}
			if err != nil && strings.Contains(err.Error(), "hunter2") {
				t.Errorf("error leaks the secret: %v", err)
			}
		})
	}
}

// A v1 file (tailnets/bridges) is not read at all, and the error says where
// to look.
func TestV1ConfigRejected(t *testing.T) {
	for name, body := range map[string]string{
		"full": `{"instance_id": "x", "tailnets": {"a": {"tailnet": "a"}}, "bridges": []}`,
		"ui":   `{"ui": {"enabled": false}, "bridges": []}`,
		"id":   `{"instance_id": "x"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := config.Load(writeFile(t, body))
			if err == nil || !strings.Contains(err.Error(), "v1 config") || !strings.Contains(err.Error(), "README") {
				t.Errorf("err = %v", err)
			}
		})
	}
}

// Every example config in the repo parses.
func TestExampleConfigsParse(t *testing.T) {
	paths, _ := filepath.Glob(filepath.Join("..", "..", "deploy", "*", "*.json"))
	paths = append(paths, filepath.Join("..", "..", "config.example.json"))
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Parse(data)
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.Bridges) == 0 {
				t.Error("example has no links")
			}
		})
	}
}

func TestLoadReadError(t *testing.T) {
	if _, err := config.Load(t.TempDir()); err == nil {
		t.Error("loading a directory worked")
	}
}
