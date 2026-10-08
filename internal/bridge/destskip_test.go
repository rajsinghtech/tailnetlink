package bridge

import (
	"context"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	"github.com/rajsinghtech/tailnetlink/internal/testutil/fakeapi"
	"tailscale.com/tsnet"
)

func TestLocalShutdownDeletesOnlyTheDestThatLeft(t *testing.T) {
	stubForwarders(t)
	keep := fakeapi.New(t)
	keep.AssignAddrs = false
	gone := fakeapi.New(t)
	gone.AssignAddrs = false
	m := New(state.New(), discardLogger(), nil)
	m.owner = testOwner
	m.servers["keep"] = &tsnet.Server{}
	m.servers["gone"] = &tsnet.Server{}
	m.apiClients["keep"] = keep.Client()
	m.apiClients["gone"] = gone.Client()
	m.cfg = &config.Config{Tailnets: map[string]config.TailnetConfig{
		"keep": {Tags: []string{"tag:bridge"}},
		"gone": {Tags: []string{"tag:bridge"}},
	}}
	rule := config.BridgeRule{
		Name: "loc", From: "home", DestTailnets: []string{"keep", "gone"},
		LocalSources: []config.LocalSourceSpec{{Addr: "10.0.0.1:80", DNSName: "app.example.com", ShortName: "app"}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.runLocalRule(ctx, rule, time.Second)
	}()
	waitFor(t, 5*time.Second, "both dests active", func() bool {
		var n int
		for _, b := range m.store.GetBridges() {
			if b.Status == state.BridgeStatusActive {
				n++
			}
		}
		return n == 2
	})
	m.markDropDest("loc", "gone")
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("local rule did not stop")
	}
	if _, ok := keep.Service("svc:app"); !ok {
		t.Fatal("remaining dest lost its VIP")
	}
	if _, ok := gone.Service("svc:app"); ok {
		t.Fatal("departed dest kept its VIP")
	}
}

func TestAuthzForUsesTheLinkWhenDestSetsNoMode(t *testing.T) {
	m := New(state.New(), discardLogger(), nil)
	m.cfg = &config.Config{Tailnets: map[string]config.TailnetConfig{
		"dest": {},
	}}
	rule := config.BridgeRule{Authz: config.AuthzConfig{Mode: config.AuthzRequireCap}}
	if got := m.authzFor(rule, "dest"); got.Mode != config.AuthzRequireCap {
		t.Fatalf("authz = %+v", got)
	}
}
