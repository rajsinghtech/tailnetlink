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

// Tests named TestKnownBad_* pin behavior the roadmap says is wrong. They
// pass today on purpose; the PR that fixes the behavior should flip them.

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

func TestLoadPartialFileKeepsDefaults(t *testing.T) {
	cfg, err := config.Load(writeFile(t, `{"dial_timeout": "3s"}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DialTimeout.Duration != 3*time.Second {
		t.Errorf("dial_timeout = %v", cfg.DialTimeout)
	}
	if cfg.PollInterval.Duration != 30*time.Second || cfg.ListenAddr != "127.0.0.1:8888" {
		t.Errorf("defaults lost: %+v", cfg)
	}
}

func TestLoadExampleConfig(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "config.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Tailnets) != 2 || len(cfg.Bridges) != 2 {
		t.Fatalf("tailnets=%d bridges=%d", len(cfg.Tailnets), len(cfg.Bridges))
	}
	src := cfg.Tailnets["source"]
	if !src.HasAuth() || src.Tailnet != "source-org.ts.net" {
		t.Errorf("source tailnet = %+v", src)
	}
	if cfg.InstanceID == "" {
		t.Error("example has no instance_id")
	}
	b := cfg.Bridges[0]
	if b.Name != "api-servers" || b.SourceTag != "tag:api-server" || len(b.Ports) != 2 {
		t.Errorf("first bridge = %+v", b)
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string]string{
		"bad json":     `{`,
		"bad duration": `{"poll_interval": "soon"}`,
		"number dur":   `{"poll_interval": 30}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := config.Load(writeFile(t, body)); err == nil {
				t.Error("want error")
			}
		})
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

func TestStoreUpdatePersists(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	s, err := config.NewStore(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(c *config.Config) error {
		c.InstanceID = "test"
		c.Tailnets["a"] = config.TailnetConfig{Tailnet: "a.example"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
	}
	again, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if again.Tailnets["a"].Tailnet != "a.example" {
		t.Errorf("reloaded = %+v", again.Tailnets)
	}
}

func TestStoreUpdateErrorDoesNotPersist(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	s, _ := config.NewStore(p)
	err := s.Update(func(c *config.Config) error { return os.ErrInvalid })
	if err == nil {
		t.Fatal("want error")
	}
	if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
		t.Errorf("file written despite error: %v", statErr)
	}
}

// KNOWN-BAD: Get and Update make shallow copies, so an older snapshot shares
// the Tailnets map and Bridges array with the new config. The bridge manager
// compares old and new snapshots to decide what to restart, so edits made
// through the UI are invisible to it. Flip in roadmap PR 9 (deep copy and no
// UI writes).
func TestKnownBad_SnapshotsShareState(t *testing.T) {
	s, _ := config.NewStore(filepath.Join(t.TempDir(), "config.json"))
	_ = s.Update(func(c *config.Config) error {
		c.InstanceID = "test"
		c.Tailnets["a"] = config.TailnetConfig{Tailnet: "one"}
		c.Bridges = append(c.Bridges, config.BridgeRule{Name: "r", Ports: []int{1}})
		return nil
	})
	old := s.Get()
	_ = s.Update(func(c *config.Config) error {
		c.Tailnets["a"] = config.TailnetConfig{Tailnet: "two"}
		c.Bridges[0] = config.BridgeRule{Name: "r", Ports: []int{2}}
		return nil
	})
	if old.Tailnets["a"].Tailnet != "two" || old.Bridges[0].Ports[0] != 2 {
		t.Errorf("expected the old snapshot to see the edit today, got %+v / %+v", old.Tailnets, old.Bridges)
	}
}

// An inline client_secret stops the config from loading. The error names
// the field and the tailnet, never the value.
func TestLoadRejectsInlineSecret(t *testing.T) {
	for name, oauth := range map[string]string{
		"alone":     `{"client_id": "id", "client_secret": "hunter2-value"}`,
		"with file": `{"client_id": "id", "client_secret": "hunter2-value", "client_secret_file": "/run/s"}`,
		"empty":     `{"client_id": "id", "client_secret": ""}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := config.Load(writeFile(t, `{"instance_id": "x", "tailnets": {"work": {"tailnet": "w.example", "oauth": `+oauth+`}}}`))
			if err == nil {
				t.Fatal("want an error")
			}
			msg := err.Error()
			if !strings.Contains(msg, "oauth.client_secret is not supported") || !strings.Contains(msg, `"work"`) || !strings.Contains(msg, "client_secret_file") {
				t.Errorf("err = %v", err)
			}
			if strings.Contains(msg, "hunter2") {
				t.Errorf("error leaks the secret: %v", err)
			}
		})
	}
}

func TestLoadRejectsBothSecretSources(t *testing.T) {
	_, err := config.Load(writeFile(t, `{"instance_id": "x", "tailnets": {"a": {"oauth": {"client_id": "id", "client_secret_file": "/f", "client_secret_env": "E"}}}}`))
	if err == nil || !strings.Contains(err.Error(), "only one of") {
		t.Fatalf("err = %v", err)
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

// The config never holds a secret, so neither JSON nor a save can carry
// one.
func TestConfigJSONHasNoSecret(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "secret")
	_ = os.WriteFile(secretFile, []byte("very-secret"), 0o600)
	p := filepath.Join(dir, "config.json")
	s, _ := config.NewStore(p)
	if err := s.Update(func(c *config.Config) error {
		c.InstanceID = "test"
		c.Tailnets["a"] = config.TailnetConfig{OAuth: config.OAuthCreds{ClientID: "id", ClientSecretFile: secretFile}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	saved, _ := os.ReadFile(p)
	for where, out := range map[string]string{"JSON": string(s.JSON()), "file": string(saved)} {
		if strings.Contains(out, "very-secret") || strings.Contains(out, `"client_secret"`) {
			t.Errorf("%s carries a secret:\n%s", where, out)
		}
		if !strings.Contains(out, secretFile) {
			t.Errorf("%s lost client_secret_file:\n%s", where, out)
		}
	}
}

// Writes through the store validate too, so an inline secret sent to the
// UI API is refused.
func TestStoreUpdateRejectsInlineSecret(t *testing.T) {
	s, _ := config.NewStore(filepath.Join(t.TempDir(), "config.json"))
	var oauth config.OAuthCreds
	if err := json.Unmarshal([]byte(`{"client_id":"id","client_secret":"x"}`), &oauth); err != nil {
		t.Fatal(err)
	}
	err := s.Update(func(c *config.Config) error {
		c.InstanceID = "test"
		c.Tailnets["a"] = config.TailnetConfig{OAuth: oauth}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "client_secret is not supported") {
		t.Fatalf("err = %v", err)
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

func TestLoadRejectsMissingInstanceID(t *testing.T) {
	_, err := config.Load(writeFile(t, `{"tailnets": {"a": {"tailnet": "a.example"}}}`))
	if err == nil || !strings.Contains(err.Error(), "instance_id is required") {
		t.Fatalf("err = %v", err)
	}
}

func TestStoreUpdateValidates(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	s, _ := config.NewStore(p)
	err := s.Update(func(c *config.Config) error {
		c.Tailnets["a"] = config.TailnetConfig{}
		return nil
	})
	if err == nil {
		t.Fatal("want an error without instance_id")
	}
	if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
		t.Errorf("file written despite error: %v", statErr)
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
