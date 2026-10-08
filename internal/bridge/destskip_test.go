package bridge

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	"github.com/rajsinghtech/tailnetlink/internal/testutil/fakeapi"
	"tailscale.com/tsnet"
)

func TestLocalRuleSkipsDownDest(t *testing.T) {
	stubForwarders(t)
	good := fakeapi.New(t)
	good.Tailnet = "example.ts.net"
	good.AssignAddrs = false
	m := New(state.New(), discardLogger(), nil)
	m.owner = testOwner
	m.servers["good"] = &tsnet.Server{}
	m.apiClients["good"] = good.Client()
	m.cfg = &config.Config{Tailnets: map[string]config.TailnetConfig{
		"good": {
			Tailnet: "example.ts.net", Tags: []string{"tag:bridge"},
			Authz: config.AuthzConfig{Mode: config.AuthzAllowTags, AllowTags: []string{"tag:eng"}},
		},
		"bad": {Tailnet: "partner.example.com", Tags: []string{"tag:bridge"}},
	}}
	rule := config.BridgeRule{
		Name: "loc", From: "home", DestTailnets: []string{"bad", "good"},
		LocalSources: []config.LocalSourceSpec{{Addr: "127.0.0.1:3000", DNSName: "app.example.com"}},
		Authz:        config.AuthzConfig{Mode: config.AuthzOff},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.runLocalRule(ctx, rule, time.Second)
	}()
	id := "loc/local/good/127.0.0.1:3000"
	waitFor(t, 5*time.Second, "local bridge on the up dest", func() bool {
		for _, b := range m.store.GetBridges() {
			if b.ID == id && b.Status == state.BridgeStatusActive {
				return true
			}
		}
		return false
	})
	for _, b := range m.store.GetBridges() {
		if strings.Contains(b.ID, "bad") {
			t.Errorf("down dest has bridge %s", b.ID)
		}
	}
	svcName := ServiceName("local", "app.example.com", "app")
	svc, ok := good.Service(svcName)
	if !ok {
		t.Fatalf("services = %v", good.ServiceNames())
	}
	if svc.Annotations[annotationBridge] != rule.BridgeRef("good") {
		t.Errorf("bridge annotation = %q, want %q", svc.Annotations[annotationBridge], rule.BridgeRef("good"))
	}
	m.mu.Lock()
	az := m.forwarders[id].authz
	m.mu.Unlock()
	if az.Mode != config.AuthzAllowTags {
		t.Errorf("local authz = %+v, want the destination mode", az)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("local rule did not stop")
	}
}

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
