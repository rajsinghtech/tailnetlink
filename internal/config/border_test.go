package config_test

import (
	"encoding/json"
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
	if loc.SourceTailnet != "" || loc.From != "test-src" || len(loc.LocalSources) != 1 || loc.DestTailnets[0] != "test-dst" {
		t.Errorf("local link = %+v", loc)
	}
	if loc.BridgeRef("test-dst") != "test-src/test-dst/loc" {
		t.Errorf("bridge ref = %s", loc.BridgeRef("test-dst"))
	}
}

func TestCompileEmptyLinks(t *testing.T) {
	omitted := strings.Replace(borderJSON(""), `,
`+`"links": [{"name": "web", "tag": "tag:web", "ports": [80]}]`, "", 1)
	for _, body := range []string{borderJSON(`"links": []`), omitted} {
		var b config.Border
		if err := json.Unmarshal([]byte(body), &b); err != nil {
			t.Fatal(err)
		}
		if len(b.Links) != 0 {
			t.Fatalf("links = %+v", b.Links)
		}
		cfg, err := b.Compile()
		if err != nil {
			t.Fatalf("Compile: %v\n%s", err, body)
		}
		if len(cfg.Bridges) != 0 {
			t.Fatalf("bridges = %+v", cfg.Bridges)
		}
		if len(cfg.Tailnets) != 2 || cfg.InstanceID != "test" || !cfg.Tailnets["test-src"].HasAuth() || !cfg.Tailnets["test-dst"].HasAuth() {
			t.Fatalf("tailnets = %+v", cfg.Tailnets)
		}
		parsed, err := config.Parse([]byte(body))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if len(parsed.Bridges) != 0 || len(parsed.Tailnets) != 2 {
			t.Fatalf("parsed = %+v", parsed)
		}
	}
}

func TestBorderIDToken(t *testing.T) {
	body := borderJSON("")
	body = strings.Replace(body, `"client_secret_file": "/run/a"`, `"id_token_file": "/var/run/id-token"`, 1)
	body = strings.Replace(body, `"client_secret_env": "B"`, `"id_token_env": "DEST_ID_TOKEN"`, 1)
	cfg, err := config.Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	src, dst := cfg.Tailnets["test-src"], cfg.Tailnets["test-dst"]
	if !src.HasAuth() || !src.OAuth.UsesIDToken() || src.OAuth.IDTokenFile != "/var/run/id-token" {
		t.Errorf("source oauth = %+v", src.OAuth)
	}
	if !dst.HasAuth() || !dst.OAuth.UsesIDToken() || dst.OAuth.IDTokenEnv != "DEST_ID_TOKEN" || dst.OAuth.ClientSecretEnv != "" {
		t.Errorf("dest oauth = %+v", dst.OAuth)
	}
}

func TestBorderDNSZone(t *testing.T) {
	body := borderJSON(`"links": [{"name": "app", "devices": [{"fqdn": "app.example.ts.net", "dns_name": "app.corp.example.com", "dns_zone": "app.corp.example.com"}], "ports": [443]}]`)
	cfg, err := config.Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	d := cfg.Bridges[0].SourceDevices[0]
	if d.DNSName != "app.corp.example.com" || d.DNSZone != "app.corp.example.com" {
		t.Fatalf("device = %+v", d)
	}
	for name, bad := range map[string]string{
		"outside": borderJSON(`"links": [{"name": "app", "devices": [{"fqdn": "app.example.ts.net", "dns_name": "app.corp.example.com", "dns_zone": "other.example.com"}], "ports": [443]}]`),
		"no name": borderJSON(`"links": [{"name": "app", "local": [{"addr": "db.example:80", "dns_zone": "app.corp.example.com"}]}]`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := config.Parse([]byte(bad)); err == nil {
				t.Fatal("accepted a bad dns_zone")
			}
		})
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
		"no secret ref":  {strings.Replace(base, `, "client_secret_env": "B"`, ``, 1), "id_token_file or id_token_env"},
		"inline secret":  {strings.Replace(base, `"client_secret_env": "B"`, `"client_secret": "hunter2"`, 1), "oauth.client_secret is not supported"},
		"both secrets":   {strings.Replace(base, `"client_secret_env": "B"`, `"client_secret_env": "B", "client_secret_file": "/f"`, 1), "only one of"},
		"secret and jwt": {strings.Replace(base, `"client_secret_env": "B"`, `"client_secret_env": "B", "id_token_file": "/run/jwt"`, 1), "only one of"},
		"both id tokens": {strings.Replace(base, `"client_secret_env": "B"`, `"id_token_file": "/run/jwt", "id_token_env": "J"`, 1), "only one of"},
		"no tags":        {strings.Replace(base, `"tags": ["tag:tailnetlink"]}`+",\n"+`"dest"`, `"tags": []}`+",\n"+`"dest"`, 1), "source: tags is required"},
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

func TestParseLocalMultiPort(t *testing.T) {
	body := borderJSON(`"links": [{
		"name": "app",
		"local": [
			{"addr": "10.0.0.1", "dns_name": "app.example.com", "short_name": "app", "ports": [80, 443]},
			{"addr": "db.lan", "ports": {"80": 8080, "443": 8443}}
		]
	}]`)
	cfg, err := config.Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	srcs := cfg.Bridges[0].LocalSources
	if len(srcs) != 2 {
		t.Fatalf("sources = %+v", srcs)
	}
	_, app, err := srcs[0].Forwards()
	if err != nil || len(app) != 2 || app[0].Expose != 80 || app[1].Backend != 443 {
		t.Fatalf("app forwards = %#v, %v", app, err)
	}
	_, db, err := srcs[1].Forwards()
	if err != nil || db[0] != (config.LocalForward{Expose: 80, Backend: 8080}) || db[1].Backend != 8443 {
		t.Fatalf("db forwards = %#v, %v", db, err)
	}

	bad := borderJSON(`"links": [{"name": "app", "local": [{"addr": "10.0.0.1", "dns_name": "app.example.com", "port_map": {"80": 8080}}]}]`)
	if _, err := config.Parse([]byte(bad)); err == nil {
		t.Fatal("port_map is not a field; want an unknown-field error")
	}
}

func TestParseViaTailnet(t *testing.T) {
	body := borderJSON(`"links": [{
		"name": "db",
		"local": [
			{"addr": "10.20.0.10", "dns_name": "db.example.com", "short_name": "db", "via": "tailnet", "ports": [443, 80]},
			{"addr": "127.0.0.1:8080", "dns_name": "pod.example.com", "short_name": "pod"}
		]
	}]`)
	cfg, err := config.Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	rule := cfg.Bridges[0]
	if rule.SourceTailnet != "test-src" || rule.From != "test-src" || len(rule.LocalSources) != 2 || rule.DestTailnets[0] != "test-dst" {
		t.Fatalf("rule = %+v", rule)
	}
	if rule.LocalSources[0].DialVia() != config.ViaTailnet || rule.LocalSources[1].DialVia() != config.ViaPod {
		t.Fatalf("via = %q %q", rule.LocalSources[0].Via, rule.LocalSources[1].Via)
	}
	_, fw, err := rule.LocalSources[0].Forwards()
	if err != nil || len(fw) != 2 || fw[0].Expose != 443 || fw[1].Expose != 80 {
		t.Fatalf("forwards = %#v, %v", fw, err)
	}
	podOnly := borderJSON(`"links": [{"name": "x", "local": [{"addr": "db.lan:1"}]}]`)
	cfg, err = config.Parse([]byte(podOnly))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Bridges[0].SourceTailnet != "" || cfg.Bridges[0].From != "test-src" {
		t.Fatalf("pod link = %+v", cfg.Bridges[0])
	}
}

func TestLoadReadError(t *testing.T) {
	if _, err := config.Load(t.TempDir()); err == nil {
		t.Error("loading a directory worked")
	}
}
