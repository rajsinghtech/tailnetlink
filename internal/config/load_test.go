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
		{config.OAuthCreds{ClientID: "id", ClientSecret: "s"}, true},
		{config.OAuthCreds{ClientID: "id"}, false},
		{config.OAuthCreds{ClientSecret: "s"}, false},
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

// RedactedJSON, which backs GET /api/config and the SSE init event, never
// carries a client secret. Flipped from TestKnownBad_RawJSONIncludesSecrets.
func TestRedactedJSONHidesSecrets(t *testing.T) {
	s, _ := config.NewStore(filepath.Join(t.TempDir(), "config.json"))
	_ = s.Update(func(c *config.Config) error {
		c.InstanceID = "test"
		c.Tailnets["a"] = config.TailnetConfig{OAuth: config.OAuthCreds{ClientID: "id", ClientSecret: "very-secret"}}
		c.Tailnets["b"] = config.TailnetConfig{OAuth: config.OAuthCreds{ClientID: "id2"}}
		return nil
	})
	out := string(s.RedactedJSON())
	if strings.Contains(out, "very-secret") {
		t.Errorf("secret in RedactedJSON:\n%s", out)
	}
	var got config.Config
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Tailnets["a"].OAuth.ClientSecret != config.RedactedSecret || got.Tailnets["a"].OAuth.ClientID != "id" {
		t.Errorf("a = %+v", got.Tailnets["a"].OAuth)
	}
	if got.Tailnets["b"].OAuth.ClientSecret != "" {
		t.Errorf("an unset secret should stay empty, got %q", got.Tailnets["b"].OAuth.ClientSecret)
	}
	// The live config keeps the real secret.
	if s.Get().Tailnets["a"].OAuth.ClientSecret != "very-secret" {
		t.Error("redaction changed the stored config")
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
