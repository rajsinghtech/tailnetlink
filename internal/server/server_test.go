package server

import (
	"testing"

	"github.com/rajsinghtech/tailnetlink/internal/config"
)

func TestValidateBridgeRule_LocalRequiresDNS(t *testing.T) {
	rule := config.BridgeRule{
		Name:         "test",
		DestTailnets: []string{"dest"},
		LocalSources: []config.LocalSourceSpec{
			{Addr: "localhost:8080"},
		},
	}
	if err := validateBridgeRule(rule); err == nil {
		t.Error("expected error for localhost without dns_name, got nil")
	}
}

func TestValidateBridgeRule_LocalFQDNNoError(t *testing.T) {
	rule := config.BridgeRule{
		Name:         "test",
		DestTailnets: []string{"dest"},
		LocalSources: []config.LocalSourceSpec{
			{Addr: "ai.local.ts.net:8080"},
		},
	}
	if err := validateBridgeRule(rule); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateBridgeRule_LocalWithExplicitDNS(t *testing.T) {
	rule := config.BridgeRule{
		Name:         "test",
		DestTailnets: []string{"dest"},
		LocalSources: []config.LocalSourceSpec{
			{Addr: "localhost:11434", DNSName: "ollama.dest.ts.net"},
		},
	}
	if err := validateBridgeRule(rule); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateBridgeRule_NonLocalMissingTailnet(t *testing.T) {
	rule := config.BridgeRule{
		Name:         "test",
		DestTailnets: []string{"dest"},
		Ports:        []int{8080},
		SourceTag:    "tag:api",
	}
	if err := validateBridgeRule(rule); err == nil {
		t.Error("expected error for missing source_tailnet, got nil")
	}
}

func TestValidateBridgeRule_LocalRejectsSourceTailnet(t *testing.T) {
	rule := config.BridgeRule{
		Name:          "test",
		DestTailnets:  []string{"dest"},
		SourceTailnet: "src",
		LocalSources:  []config.LocalSourceSpec{{Addr: "ai.ts.net:8080"}},
	}
	if err := validateBridgeRule(rule); err == nil {
		t.Error("expected error when local rule sets source_tailnet, got nil")
	}
}
