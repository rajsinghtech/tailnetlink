package config_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

func sideJSON(tailnet, id string, extra string) string {
	s := fmt.Sprintf(`"tailnet": %q, "oauth": {"client_id": %q, "client_secret_file": "/run/s"}, "tags": ["tag:tailnetlink"]`, tailnet, id)
	if extra != "" {
		s += ", " + extra
	}
	return "{" + s + "}"
}

func multiBorder(dests string) string {
	return `{
		"name": "edge",
		"source": ` + sideJSON("keiretsu.ts.net", "src", "") + `,
		"dests": [` + dests + `],
		"links": [{"name": "web", "tag": "tag:web", "ports": [80], "authz": {"mode": "off"}}]
	}`
}

func TestMultiDestValidation(t *testing.T) {
	both := borderJSON(`"dests": [` + sideJSON("c.ts.net", "c", "") + `]`)
	if _, err := config.Parse([]byte(both)); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("both set: %v", err)
	}
	empty := `{
		"name": "edge",
		"source": ` + sideJSON("keiretsu.ts.net", "src", "") + `,
		"dests": [],
		"links": []
	}`
	if _, err := config.Parse([]byte(empty)); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty dests: %v", err)
	}
	missing := `{
		"name": "edge",
		"source": ` + sideJSON("keiretsu.ts.net", "src", "") + `,
		"links": []
	}`
	if _, err := config.Parse([]byte(missing)); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("no dest: %v", err)
	}
	badSide := multiBorder(`{"tailnet": "example.ts.net"}`)
	if _, err := config.Parse([]byte(badSide)); err == nil || !strings.Contains(err.Error(), "dests[0]") {
		t.Fatalf("bad dest: %v", err)
	}
	badAuthz := multiBorder(sideJSON("example.ts.net", "a", `"authz": {"mode": "allow_logins"}`))
	if _, err := config.Parse([]byte(badAuthz)); err == nil || !strings.Contains(err.Error(), "allow_logins") {
		t.Fatalf("bad dest authz: %v", err)
	}
	dup := multiBorder(sideJSON("Example.ts.net", "a", "") + "," + sideJSON("example.ts.net", "b", ""))
	if _, err := config.Parse([]byte(dup)); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate: %v", err)
	}

	// Two tailnet names whose state keys would collide are rejected.
	seen := map[string]string{}
	var a, b string
	for i := 0; i < 100000 && a == ""; i++ {
		name := fmt.Sprintf("n%d.ts.net", i)
		sum := sha256.Sum256([]byte(name))
		suf := hex.EncodeToString(sum[:2])
		if other, ok := seen[suf]; ok {
			a, b = other, name
			break
		}
		seen[suf] = name
	}
	if a == "" {
		t.Fatal("no hash collision found")
	}
	clash := multiBorder(sideJSON(a, "a", "") + "," + sideJSON(b, "b", ""))
	if _, err := config.Parse([]byte(clash)); err == nil || !strings.Contains(err.Error(), "share node state") {
		t.Fatalf("collision: %v", err)
	}
}

func TestMultiDestCompile(t *testing.T) {
	single, err := config.Parse([]byte(borderJSON("")))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := single.Tailnets["test-dst"]; !ok || single.Tailnets["test-dst"].Role != "dest" {
		t.Fatalf("single dest key = %+v", single.Tailnets)
	}

	one := multiBorder(sideJSON("example.ts.net", "one", ""))
	cfg, err := config.Parse([]byte(one))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Tailnets["edge-dst"]; ok {
		t.Fatal("one-element dests reused the single-dest state key")
	}
	var oneKey string
	for k, tc := range cfg.Tailnets {
		if tc.Role == "dest" {
			oneKey = k
		}
	}
	sum := sha256.Sum256([]byte("example.ts.net"))
	want := "edge-dst-" + hex.EncodeToString(sum[:2])
	if oneKey != want {
		t.Fatalf("one-element key = %q, want %q", oneKey, want)
	}

	body := multiBorder(sideJSON("example.ts.net", "ex", `"authz": {"mode": "allow_logins", "allow_logins": ["alice@example.com"]}`) + "," +
		sideJSON("partner.example.com", "pa", `"dns": {"enabled": false}, "authz": {"mode": "allow_tags", "allow_tags": ["tag:eng"]}`))
	cfg, err = config.Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	again, err := config.Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Bridges) != 1 {
		t.Fatalf("rules = %d", len(cfg.Bridges))
	}
	var destKeys []string
	for k, tc := range cfg.Tailnets {
		if tc.Role != "dest" {
			if tc.Role != "source" || k != "edge-src" {
				t.Errorf("source = %s %+v", k, tc)
			}
			continue
		}
		destKeys = append(destKeys, k)
		if !strings.HasPrefix(k, "edge-dst-") || len(k) != len("edge-dst-")+4 {
			t.Errorf("dest key %q", k)
		}
		if len("tailnetlink-"+k) > 63 {
			t.Errorf("hostname too long: tailnetlink-%s", k)
		}
		other, ok := again.Tailnets[k]
		if !ok || other.Tailnet != tc.Tailnet {
			t.Errorf("key %s not stable", k)
		}
		switch tc.Tailnet {
		case "example.ts.net":
			if tc.Authz.Mode != config.AuthzAllowLogins || tc.DNSDisabled {
				t.Errorf("example authz/dns = %+v dns=%v", tc.Authz, tc.DNSDisabled)
			}
		case "partner.example.com":
			if tc.Authz.Mode != config.AuthzAllowTags || !tc.DNSDisabled {
				t.Errorf("partner authz/dns = %+v dns=%v", tc.Authz, tc.DNSDisabled)
			}
		default:
			t.Errorf("unexpected dest %q", tc.Tailnet)
		}
	}
	if len(destKeys) != 2 {
		t.Fatalf("dest keys = %v", destKeys)
	}
	got := append([]string(nil), cfg.Bridges[0].DestTailnets...)
	if len(got) != 2 || (got[0] != destKeys[0] && got[0] != destKeys[1]) || got[0] == got[1] {
		t.Fatalf("rule dests = %v, keys = %v", got, destKeys)
	}
	if cfg.Bridges[0].Authz.Mode != config.AuthzOff {
		t.Errorf("link authz = %+v", cfg.Bridges[0].Authz)
	}

	off := `{
		"name": "edge",
		"source": ` + sideJSON("keiretsu.ts.net", "src", "") + `,
		"dests": [` + sideJSON("example.ts.net", "ex", `"dns": {"enabled": true}`) + `],
		"dns": {"enabled": false},
		"links": []
	}`
	cfg, err = config.Parse([]byte(off))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cfg.Tailnets {
		if tc.Role == "dest" && !tc.DNSDisabled {
			t.Error("border dns off did not win")
		}
	}
}

func TestLoadReadError(t *testing.T) {
	if _, err := config.Load(t.TempDir()); err == nil {
		t.Error("loading a directory worked")
	}
}
