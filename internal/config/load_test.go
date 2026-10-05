package config_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
)

func writeFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadMissingFileGivesDefaults(t *testing.T) {
	cfg, err := config.Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PollInterval.Duration != 30*time.Second {
		t.Errorf("poll_interval = %v", cfg.PollInterval)
	}
	if cfg.DialTimeout.Duration != 10*time.Second {
		t.Errorf("dial_timeout = %v", cfg.DialTimeout)
	}
	if cfg.ListenAddr != "127.0.0.1:8888" {
		t.Errorf("listen_addr = %q", cfg.ListenAddr)
	}
	if cfg.Tailnets == nil || cfg.Bridges == nil || len(cfg.Tailnets) != 0 || len(cfg.Bridges) != 0 {
		t.Errorf("want empty non-nil collections, got %+v", cfg)
	}
}

func TestHasAuth(t *testing.T) {
	cases := []struct {
		oauth config.OAuthCreds
		want  bool
	}{
		{config.OAuthCreds{ClientID: "id", ClientSecretFile: "/run/s"}, true},
		{config.OAuthCreds{ClientID: "id", ClientSecretEnv: "S"}, true},
		{config.OAuthCreds{ClientID: "id"}, false},
		{config.OAuthCreds{ClientSecretFile: "/run/s"}, false},
	}
	for _, c := range cases {
		if got := (config.TailnetConfig{OAuth: c.oauth}).HasAuth(); got != c.want {
			t.Errorf("HasAuth(%+v) = %v", c.oauth, got)
		}
	}
}

func TestDurationRoundTrip(t *testing.T) {
	d := config.Duration{Duration: 90 * time.Second}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"1m30s"` {
		t.Errorf("marshal = %s", b)
	}
	var back config.Duration
	if err := json.Unmarshal(b, &back); err != nil || back.Duration != d.Duration {
		t.Errorf("unmarshal = %v, %v", back, err)
	}
}

// Get hands out deep copies: changing one snapshot changes neither the
// store nor any other snapshot. The bridge manager diffs old against new
// snapshots, so shared maps or slices would hide changes from it.
func TestStoreGetIsDeepCopy(t *testing.T) {
	p := writeFile(t, borderJSON(`"ui": {"enabled": true}, "links": [
		{"name": "r", "devices": [{"fqdn": "d.one"}], "ports": [1]},
		{"name": "s", "services": [{"name": "svc:s"}], "ports": [2]}]`))
	s, err := config.NewStore(p)
	if err != nil {
		t.Fatal(err)
	}
	old := s.Get()
	old.Tailnets["test-src"] = config.TailnetConfig{Tailnet: "two"}
	old.Bridges[0].Ports[0] = 2
	old.Bridges[0].DestTailnets[0] = "b"
	old.Bridges[0].SourceDevices[0].FQDN = "x"
	*old.UI.Enabled = false
	now := s.Get()
	if now.Tailnets["test-src"].Tailnet != "a.ts.net" || now.Bridges[0].Ports[0] != 1 || now.Bridges[0].DestTailnets[0] != "test-dst" ||
		now.Bridges[0].SourceDevices[0].FQDN != "d.one" || !now.UIEnabled() {
		t.Errorf("editing a snapshot changed the store: %+v / %+v", now.Tailnets, now.Bridges)
	}
}

func TestCloneEmpty(t *testing.T) {
	c := (&config.Config{}).Clone()
	if c.Tailnets != nil || c.Bridges != nil || c.UI.Enabled != nil {
		t.Errorf("clone of empty config = %+v", c)
	}
}

// Watch reloads the file when it changes, hands each listener its own copy,
// and ignores a file that no longer loads.
func TestStoreWatchReloads(t *testing.T) {
	p := writeFile(t, borderJSON(""))
	s, err := config.NewStore(p)
	if err != nil {
		t.Fatal(err)
	}
	s.SetWatchInterval(10 * time.Millisecond)
	got := make(chan *config.Config, 4)
	s.OnChange(func(c *config.Config) { got <- c })
	s.OnChange(func(c *config.Config) { got <- c })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Watch(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))

	bump := func(body string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		future := time.Now().Add(time.Duration(bumps.Add(1)) * time.Second)
		if err := os.Chtimes(p, future, future); err != nil {
			t.Fatal(err)
		}
	}
	bump(strings.Replace(borderJSON(`"poll_interval": "5s"`), `"name": "test"`, `"name": "changed"`, 1))
	next := func() *config.Config {
		t.Helper()
		select {
		case c := <-got:
			return c
		case <-time.After(10 * time.Second):
			t.Fatal("no reload")
			return nil
		}
	}
	a, b := next(), next()
	if a == b {
		t.Error("listeners share one config")
	}
	if a.InstanceID != "changed" || a.PollInterval.Duration != 5*time.Second {
		t.Errorf("reloaded = %+v", a)
	}
	if s.Get().InstanceID != "changed" {
		t.Error("store not updated")
	}

	bump(`{not json`)
	select {
	case c := <-got:
		t.Fatalf("bad file reloaded: %+v", c)
	case <-time.After(100 * time.Millisecond):
	}
	if s.Get().InstanceID != "changed" {
		t.Error("bad file replaced the config")
	}
}

var bumps atomic.Int64

func TestUIEnabled(t *testing.T) {
	off, on := false, true
	for _, c := range []struct {
		v    *bool
		want bool
	}{{nil, true}, {&on, true}, {&off, false}} {
		if got := (&config.Config{UI: config.UIConfig{Enabled: c.v}}).UIEnabled(); got != c.want {
			t.Errorf("UIEnabled(%v) = %v", c.v, got)
		}
	}
}

// The public view the UI shows has no oauth block at all.
func TestPublicJSON(t *testing.T) {
	c := &config.Config{InstanceID: "x", Tailnets: map[string]config.TailnetConfig{
		"a": {Tailnet: "a.example", Tags: []string{"tag:t"}, OAuth: config.OAuthCreds{ClientID: "cid-123", ClientSecretFile: "/run/secret-path"}},
	}}
	out := string(c.PublicJSON())
	for _, bad := range []string{"oauth", "cid-123", "/run/secret-path"} {
		if strings.Contains(out, bad) {
			t.Errorf("public JSON has %q:\n%s", bad, out)
		}
	}
	if !strings.Contains(out, "a.example") || !strings.Contains(out, "tag:t") {
		t.Errorf("public JSON lost fields:\n%s", out)
	}
	if c.Tailnets["a"].OAuth.ClientID != "cid-123" {
		t.Error("PublicJSON changed the config")
	}
}

func TestSecret(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	_ = os.WriteFile(good, []byte("  file-secret\n"), 0o600)
	empty := filepath.Join(dir, "empty")
	_ = os.WriteFile(empty, []byte("\n"), 0o600)
	t.Setenv("TNL_TEST_SECRET", "env-secret")
	t.Setenv("TNL_TEST_EMPTY", "")

	cases := []struct {
		name    string
		creds   config.OAuthCreds
		want    string
		wantErr string
	}{
		{"file", config.OAuthCreds{ClientSecretFile: good}, "file-secret", ""},
		{"env", config.OAuthCreds{ClientSecretEnv: "TNL_TEST_SECRET"}, "env-secret", ""},
		{"missing file", config.OAuthCreds{ClientSecretFile: filepath.Join(dir, "nope")}, "", "client_secret_file"},
		{"empty file", config.OAuthCreds{ClientSecretFile: empty}, "", "is empty"},
		{"unset env", config.OAuthCreds{ClientSecretEnv: "TNL_TEST_UNSET_XYZ"}, "", "$TNL_TEST_UNSET_XYZ is not set"},
		{"empty env", config.OAuthCreds{ClientSecretEnv: "TNL_TEST_EMPTY"}, "", "is not set"},
		{"neither", config.OAuthCreds{ClientID: "id"}, "", "set oauth.client_secret_file or oauth.client_secret_env"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.creds.Secret()
			if c.wantErr == "" {
				if err != nil || got != c.want {
					t.Errorf("Secret() = %q, %v; want %q", got, err, c.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("err = %v, want it to mention %q", err, c.wantErr)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tn := map[string]config.TailnetConfig{"a": {}}
	cases := []struct {
		name string
		cfg  config.Config
		want string // substring of the error, or "" for none
	}{
		{"empty config needs no id", config.Config{}, ""},
		{"tailnets need an id", config.Config{Tailnets: tn}, "instance_id is required"},
		{"good id", config.Config{InstanceID: "home-to-work", Tailnets: tn}, ""},
		{"one char", config.Config{InstanceID: "a"}, ""},
		{"upper case", config.Config{InstanceID: "Home"}, "must be 1 to 63"},
		{"leading dash", config.Config{InstanceID: "-a"}, "must be 1 to 63"},
		{"trailing dash", config.Config{InstanceID: "a-"}, "must be 1 to 63"},
		{"too long", config.Config{InstanceID: strings.Repeat("a", 64)}, "must be 1 to 63"},
		{"bad ui name", config.Config{InstanceID: "a", UI: config.UIConfig{ServiceName: "tailnetlink"}}, "ui.service_name"},
		{"custom ui name", config.Config{InstanceID: "a", UI: config.UIConfig{ServiceName: "svc:tnl-ui-b"}}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			switch {
			case c.want == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Errorf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestUIServiceName(t *testing.T) {
	if got := (&config.Config{}).UIServiceName(); got != "svc:tailnetlink" {
		t.Errorf("default = %q", got)
	}
	if got := (&config.Config{UI: config.UIConfig{ServiceName: "svc:x"}}).UIServiceName(); got != "svc:x" {
		t.Errorf("custom = %q", got)
	}
}
