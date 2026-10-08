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

func TestViaTailnetSkipsWhenSourceOrDestIsDown(t *testing.T) {
	m := New(state.New(), discardLogger(), nil)
	m.cfg = &config.Config{}
	m.runLocalRule(context.Background(), config.BridgeRule{
		Name: "db", SourceTailnet: "src", DestTailnets: []string{"dst"},
		LocalSources: []config.LocalSourceSpec{{
			Addr: "10.20.0.10", Via: config.ViaTailnet, DNSName: "db.example.com", Ports: config.LocalPortList(80),
		}},
	}, time.Second)
	m.runLocalRule(context.Background(), config.BridgeRule{
		Name: "pod", DestTailnets: []string{"missing"},
		LocalSources: []config.LocalSourceSpec{{Addr: "10.0.0.1:80", DNSName: "app.example.com"}},
	}, time.Second)
	var sawSource, sawDest bool
	for _, l := range m.store.GetLogs(20) {
		if strings.Contains(l.Message, `source tailnet "src" not connected`) {
			sawSource = true
		}
		if strings.Contains(l.Message, "no destination is connected") {
			sawDest = true
		}
	}
	if !sawSource || !sawDest {
		t.Fatalf("logs source=%v dest=%v", sawSource, sawDest)
	}

	bare := &Manager{store: state.New(), logger: discardLogger()}
	bare.markDropDest("loc", "gone")
	if len(bare.takeDrops("loc")) != 0 {
		t.Fatal("idle sweep left a drop behind")
	}
	bare.sweepIdleDrops("missing")
	cancel := func() {}
	bare.rules = map[string]context.CancelFunc{"loc": cancel}
	bare.dropDest = map[string]map[string]bool{"loc": {"gone": true}}
	bare.sweepIdleDrops("loc")
	if !bare.dropDest["loc"]["gone"] {
		t.Fatal("sweep cleared a drop for a running rule")
	}
	if destOfBridge("loc", "nope") != "" || destOfBridge("loc", "loc/local/keep/10.0.0.1:80") != "keep" || destOfBridge("web", "web/dest/host.example") != "dest" {
		t.Fatal("destOfBridge")
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
