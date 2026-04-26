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

func TestValidateLocalSources_InvalidAddr(t *testing.T) {
	if err := validateLocalSources([]config.LocalSourceSpec{{Addr: "nocolon"}}); err == nil {
		t.Error("expected error for addr without port, got nil")
	}
}

func TestValidateLocalSources_PortOutOfRange(t *testing.T) {
	if err := validateLocalSources([]config.LocalSourceSpec{{Addr: "host:99999"}}); err == nil {
		t.Error("expected error for port > 65535, got nil")
	}
}

func TestValidateLocalSources_IPRequiresDNS(t *testing.T) {
	if err := validateLocalSources([]config.LocalSourceSpec{{Addr: "192.168.1.5:8080"}}); err == nil {
		t.Error("expected error for IP addr without dns_name, got nil")
	}
}
