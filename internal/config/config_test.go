package config_test

import (
	"encoding/json"
	"testing"

	"github.com/rajsinghtech/tailnetlink/internal/config"
)

func TestLocalSourceSpecRoundtrip(t *testing.T) {
	rule := config.BridgeRule{
		Name:         "test",
		DestTailnets: []string{"dest"},
		LocalSources: []config.LocalSourceSpec{
			{Addr: "localhost:11434", ExposePort: 80, DNSName: "ollama.dest.ts.net"},
			{Addr: "ai.lan.ts.net:8080"},
			{Addr: "localhost:3000", DNSName: "app.dest.ts.net", ShortName: "app"},
		},
	}

	data, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got config.BridgeRule
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.LocalSources) != 3 {
		t.Fatalf("expected 3 local_sources, got %d", len(got.LocalSources))
	}
	if got.LocalSources[0].Addr != "localhost:11434" {
		t.Errorf("Addr[0] = %q, want %q", got.LocalSources[0].Addr, "localhost:11434")
	}
	if got.LocalSources[0].ExposePort != 80 {
		t.Errorf("ExposePort[0] = %d, want 80", got.LocalSources[0].ExposePort)
	}
	if got.LocalSources[0].DNSName != "ollama.dest.ts.net" {
		t.Errorf("DNSName[0] = %q, want %q", got.LocalSources[0].DNSName, "ollama.dest.ts.net")
	}
	if got.LocalSources[1].Addr != "ai.lan.ts.net:8080" {
		t.Errorf("Addr[1] = %q, want %q", got.LocalSources[1].Addr, "ai.lan.ts.net:8080")
	}
	if got.LocalSources[2].ShortName != "app" {
		t.Errorf("ShortName[2] = %q, want %q", got.LocalSources[2].ShortName, "app")
	}
}

func TestBridgeRuleOmitsLocalSourcesWhenEmpty(t *testing.T) {
	rule := config.BridgeRule{
		Name:          "test",
		SourceTailnet: "src",
		DestTailnets:  []string{"dest"},
		Ports:         []int{8080},
	}
	data, _ := json.Marshal(rule)
	var m map[string]any
	json.Unmarshal(data, &m)
	if _, ok := m["local_sources"]; ok {
		t.Error("local_sources should be omitted when empty")
	}
}
