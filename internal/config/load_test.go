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
	if cfg.ListenAddr != ":8888" {
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
	if cfg.PollInterval.Duration != 30*time.Second || cfg.ListenAddr != ":8888" {
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

// KNOWN-BAD: RawJSON, which backs GET /api/config and the SSE init event,
// includes OAuth client secrets. Flip in roadmap PR 7 (redact).
func TestKnownBad_RawJSONIncludesSecrets(t *testing.T) {
	s, _ := config.NewStore(filepath.Join(t.TempDir(), "config.json"))
	_ = s.Update(func(c *config.Config) error {
		c.Tailnets["a"] = config.TailnetConfig{OAuth: config.OAuthCreds{ClientID: "id", ClientSecret: "very-secret"}}
		return nil
	})
	if !strings.Contains(string(s.RawJSON()), "very-secret") {
		t.Error("expected the secret in RawJSON today")
	}
}
