package bridge

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

func TestAuthorize(t *testing.T) {
	cap := func(links ...string) tailcfg.PeerCapMap {
		raw, err := tailcfg.MarshalCapJSON(capParams{Links: links})
		if err != nil {
			t.Fatal(err)
		}
		return tailcfg.PeerCapMap{CapName: {raw}}
	}
	cases := []struct {
		name    string
		az      config.AuthzConfig
		link    string
		peer    whoIsResult
		whoErr  error
		wantErr string
	}{
		{"off ignores whois error", config.AuthzConfig{}, "web", whoIsResult{}, errors.New("x"), ""},
		{"require_cap allows listed link", config.AuthzConfig{Mode: config.AuthzRequireCap}, "web", whoIsResult{CapMap: cap("web", "db")}, nil, ""},
		{"require_cap allows star", config.AuthzConfig{Mode: config.AuthzRequireCap}, "web", whoIsResult{CapMap: cap("*")}, nil, ""},
		{"require_cap denies other link", config.AuthzConfig{Mode: config.AuthzRequireCap}, "web", whoIsResult{CapMap: cap("db")}, nil, "missing capability"},
		{"require_cap denies absent", config.AuthzConfig{Mode: config.AuthzRequireCap}, "web", whoIsResult{}, nil, "missing capability"},
		{"require_cap fails closed on whois", config.AuthzConfig{Mode: config.AuthzRequireCap}, "web", whoIsResult{CapMap: cap("web")}, errors.New("boom"), "whois"},
		{"allow_logins allows", config.AuthzConfig{Mode: config.AuthzAllowLogins, AllowLogins: []string{"a@x"}}, "web", whoIsResult{Login: "a@x"}, nil, ""},
		{"allow_logins denies", config.AuthzConfig{Mode: config.AuthzAllowLogins, AllowLogins: []string{"a@x"}}, "web", whoIsResult{Login: "b@x"}, nil, "not allowed"},
		{"allow_tags allows", config.AuthzConfig{Mode: config.AuthzAllowTags, AllowTags: []string{"tag:ok"}}, "web", whoIsResult{Tags: []string{"tag:other", "tag:ok"}}, nil, ""},
		{"allow_tags denies", config.AuthzConfig{Mode: config.AuthzAllowTags, AllowTags: []string{"tag:ok"}}, "web", whoIsResult{Tags: []string{"tag:other"}}, nil, "none of tags"},
		{"unknown mode", config.AuthzConfig{Mode: "weird"}, "web", whoIsResult{}, nil, "unknown authz mode"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := authorize(c.az, c.link, c.peer, c.whoErr)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, c.wantErr)
			}
		})
	}
}

// authorize runs before dial: a denied peer never reaches the dialer.
func TestForwarderAuthzBeforeDial(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		_, _ = io.WriteString(server, "PROXY TCP4 100.64.0.1 100.64.0.2 1 2\r\npayload")
		_ = server.Close()
	}()

	dialed := false
	oldWho, oldDial := whoIs, (*tsnet.Server).Dial
	t.Cleanup(func() { whoIs = oldWho })
	whoIs = func(context.Context, *tsnet.Server, string) (whoIsResult, error) {
		return whoIsResult{}, nil // no caps
	}
	// Replace dialSrv with a stub via localAddr instead, and watch DialFailed.
	// Use localAddr so dial is net.Dial; we never get there if authz denies.
	f := &Forwarder{
		listenSrv: &tsnet.Server{},
		localAddr: "127.0.0.1:1",
		vip:       &VIPService{ServiceName: "svc:x"},
		bridgeID:  "web/d/x",
		timeout:   time.Second,
		store:     state.New(),
		logger:    discardLogger(),
		rule:      "web",
		authz:     config.AuthzConfig{Mode: config.AuthzRequireCap},
	}
	_ = oldDial
	f.handle(context.Background(), client, 80)
	if dialed {
		t.Fatal("dialed after deny")
	}
	// Backend address was never contacted: localAddr port 1 should not have
	// accepted anything; the proof is authorize returned before dial and the
	// store has an authz warn, not a dial failure.
	logs := f.store.GetLogs(10)
	found := false
	for _, l := range logs {
		if strings.Contains(l.Message, "authz denied") {
			found = true
		}
		if strings.Contains(l.Message, "dial failed") {
			t.Fatalf("dialed despite deny: %s", l.Message)
		}
	}
	if !found {
		t.Fatalf("no authz log: %+v", logs)
	}
}
