package config_test

import (
	"strings"
	"testing"

	"github.com/rajsinghtech/tailnetlink/internal/config"
)

func TestAuthzEffectiveAndValidate(t *testing.T) {
	border := config.AuthzConfig{Mode: config.AuthzRequireCap}
	link := config.AuthzConfig{Mode: config.AuthzOff}
	if got := link.Effective(border); got.Mode != config.AuthzOff {
		t.Fatalf("link override = %+v", got)
	}
	if got := (config.AuthzConfig{}).Effective(border); got.Mode != config.AuthzRequireCap {
		t.Fatalf("inherit = %+v", got)
	}

	for _, bad := range []string{
		sample(`"authz": {"mode": "weird"}`),
		sample(`"authz": {"mode": "allow_logins"}`),
		sample(`"authz": {"mode": "allow_tags"}`),
		strings.Replace(sample(""), `"exports": [{"target": "web", "to": ["work"]}]`, `"exports": [{"target": "web", "to": ["work"], "authz": {"mode": "allow_logins"}}]`, 1),
	} {
		if _, err := config.Parse([]byte(bad)); err == nil {
			t.Fatalf("accepted bad authz: %s", bad)
		}
	}
	ok := `{
		"name": "test",
		"authz": {"mode": "require_cap"},
		"tailnets": {
			"home": {"tailnet": "keiretsu.ts.net", "auth": {"client_id": "a", "client_secret_file": "/run/a"}},
			"work": {"tailnet": "example.ts.net", "auth": {"client_id": "b", "client_secret_env": "B"}}
		},
		"targets": {
			"web": {"in": "home", "tag": "tag:web", "ports": [80]},
			"open": {"in": "home", "tag": "tag:open", "ports": [80]},
			"users": {"in": "home", "tag": "tag:users", "ports": [80]}
		},
		"exports": [
			{"target": "web", "to": ["work"]},
			{"target": "open", "to": ["work"], "authz": {"mode": "off"}},
			{"target": "users", "to": ["work"], "authz": {"mode": "allow_logins", "allow_logins": ["a@example.com"]}}
		]
	}`
	cfg, err := config.Parse([]byte(ok))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]config.BridgeRule{}
	for _, r := range cfg.Bridges {
		byName[r.Name] = r
	}
	if byName["web/web"].Authz.Mode != config.AuthzRequireCap {
		t.Errorf("web authz = %+v", byName["web/web"].Authz)
	}
	if byName["open/open"].Authz.Mode != config.AuthzOff {
		t.Errorf("open authz = %+v", byName["open/open"].Authz)
	}
	if byName["users/users"].Authz.Mode != config.AuthzAllowLogins || len(byName["users/users"].Authz.AllowLogins) != 1 {
		t.Errorf("users authz = %+v", byName["users/users"].Authz)
	}
}
