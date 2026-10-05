package config_test

import (
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
		borderJSON(`"authz": {"mode": "weird"}`),
		borderJSON(`"authz": {"mode": "allow_logins"}`),
		borderJSON(`"authz": {"mode": "allow_tags"}`),
		borderJSON(`"links": [{"name": "web", "tag": "tag:web", "ports": [80], "authz": {"mode": "allow_logins"}}]`),
	} {
		if _, err := config.Parse([]byte(bad)); err == nil {
			t.Fatalf("accepted bad authz: %s", bad)
		}
	}
	ok := borderJSON(`"authz": {"mode": "require_cap"}, "links": [
		{"name": "web", "tag": "tag:web", "ports": [80]},
		{"name": "open", "tag": "tag:open", "ports": [80], "authz": {"mode": "off"}},
		{"name": "users", "tag": "tag:users", "ports": [80], "authz": {"mode": "allow_logins", "allow_logins": ["a@x"]}}
	]`)
	cfg, err := config.Parse([]byte(ok))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]config.BridgeRule{}
	for _, r := range cfg.Bridges {
		byName[r.Name] = r
	}
	if byName["web"].Authz.Mode != config.AuthzRequireCap {
		t.Errorf("web authz = %+v", byName["web"].Authz)
	}
	if byName["open"].Authz.Mode != config.AuthzOff {
		t.Errorf("open authz = %+v", byName["open"].Authz)
	}
	if byName["users"].Authz.Mode != config.AuthzAllowLogins || len(byName["users"].Authz.AllowLogins) != 1 {
		t.Errorf("users authz = %+v", byName["users"].Authz)
	}
}
