package server

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/state"
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

func TestServeStopsWithOpenSSEStream(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cs, err := config.NewStore(filepath.Join(t.TempDir(), "c.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := New(ln.Addr().String(), state.New(), cs, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()

	resp, err := http.Get("http://" + ln.Addr().String() + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := bufio.NewReader(resp.Body).ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("Serve took %v to stop with an SSE stream open", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
}

func TestRunListenError(t *testing.T) {
	s := New("256.0.0.1:0", state.New(), nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := s.Run(context.Background()); err == nil {
		t.Fatal("want a listen error")
	}
}
