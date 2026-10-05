package e2e

import (
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	tsclient "tailscale.com/client/tailscale/v2"
	"tailscale.com/tsnet"
)

// hostForeignService starts a node in tn tagged tag:other that serves svc on
// port, and creates the service by hand the way an admin would.
func hostForeignService(t *testing.T, b *border, tn *tailnet, api *ctlBridge, svcName string, port int) tsclient.VIPService {
	t.Helper()
	ctx := t.Context()
	api.setHostTags("apihost", "tag:other")
	foreign := api.PutService(tsclient.VIPService{
		Name: svcName, Comment: "hand made", Ports: []string{fmt.Sprintf("tcp:%d", port)}, Tags: []string{"tag:other"},
	})
	host := tn.node(t, ctx, "apihost")
	waitFor(t, 20*time.Second, "apihost tagged", func() bool {
		lc, _ := host.srv.LocalClient()
		st, err := lc.StatusWithoutPeers(ctx)
		return err == nil && st.Self.Tags != nil && st.Self.Tags.Len() > 0
	})
	ln, err := host.srv.ListenService(svcName, tsnet.ServiceModeTCP{Port: uint16(port)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go serveEcho(ln, make(chan string, 16))
	return foreign
}

// A hand-made svc:api in dst survives a rule with short_name "api": the
// rule reports a conflict, the service is unchanged, and it still routes to
// its own host.
func TestManagerLeavesForeignServiceAlone(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	echoBackend(t, ctx, b.src, "backend", 8080)
	short := "api-" + b.sfx
	foreign := hostForeignService(t, b, b.dst, b.dstAPI, "svc:"+short, 9000)
	cl := client(t, ctx, b.dst, "client")
	vip := netip.MustParseAddr(foreign.Addrs[0])
	echoVia(t, ctx, cl, netip.AddrPortFrom(vip, 9000), "before")

	r := startManager(t, b.config(b.deviceRule("web", "backend", short, 8080)), "")
	id := "web/" + b.dstName + "/backend." + b.src.domain
	waitFor(t, 30*time.Second, "bridge reports a name conflict", func() bool {
		st, msg := r.bridgeStatus(id)
		return st == string(state.BridgeStatusError) && strings.HasPrefix(msg, "name conflict")
	})

	if got, _ := b.dstAPI.Service(foreign.Name); !reflect.DeepEqual(got, foreign) {
		t.Errorf("foreign service changed:\n got %+v\nwant %+v", got, foreign)
	}
	for _, w := range b.dstAPI.Writes() {
		if strings.HasSuffix(w, "/"+foreign.Name) {
			t.Errorf("tailnetlink wrote to the foreign service: %s", w)
		}
	}
	echoVia(t, ctx, cl, netip.AddrPortFrom(vip, 9000), "after")

	r.stop(t)
	time.Sleep(500 * time.Millisecond)
	if got, _ := b.dstAPI.Service(foreign.Name); !reflect.DeepEqual(got, foreign) {
		t.Errorf("foreign service changed after shutdown: %+v", got)
	}
}

// Two instances with different instance ids on the same border never touch
// each other's services, when one of them shuts down or removes its link.
func TestManagerInstancesDoNotTouchEachOther(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	echoBackend(t, ctx, b.src, "one", 7001)
	echoBackend(t, ctx, b.src, "two", 7002)

	cfgA := b.config(b.deviceRule("one", "one", "", 7001))

	// Instance B uses its own names, tags and instance id.
	cfgB := b.config()
	cfgB.InstanceID = "e2e-b-" + b.sfx
	srcB, dstB := "srcb"+b.sfx, "dstb"+b.sfx
	cfgB.Tailnets = map[string]config.TailnetConfig{srcB: cfgB.Tailnets[b.srcName], dstB: cfgB.Tailnets[b.dstName]}
	for name, tc := range cfgB.Tailnets {
		tc.Tags = []string{"tag:tailnetlink-b"}
		cfgB.Tailnets[name] = tc
	}
	b.srcAPI.setHostTags("tailnetlink-srcb", "tag:tailnetlink-b")
	b.dstAPI.setHostTags("tailnetlink-dstb", "tag:tailnetlink-b")
	ruleB := b.deviceRule("two", "two", "", 7002)
	ruleB.SourceTailnet, ruleB.DestTailnets = srcB, []string{dstB}
	cfgB.Bridges = []config.BridgeRule{ruleB}

	startManager(t, cfgA, "")
	rb := startManager(t, cfgB, "")

	svcA := b.serviceName("one", "")
	svcB := "svc:tnl-" + srcB + "-two"
	waitVIP(t, b.dstAPI, svcA)
	waitVIP(t, b.dstAPI, svcB)

	ownerOf := func(name string) string {
		s, _ := b.dstAPI.Service(name)
		return s.Annotations["tailnetlink/owner"]
	}
	if ownerOf(svcA) != cfgA.InstanceID || ownerOf(svcB) != cfgB.InstanceID {
		t.Fatalf("owners: %s=%q %s=%q", svcA, ownerOf(svcA), svcB, ownerOf(svcB))
	}
	dnsVIP := "svc:tnl-dns-src-ts-net-dns"
	waitFor(t, 30*time.Second, "shared DNS VIP", func() bool { return ownerOf(dnsVIP) != "" })
	dnsOwner := ownerOf(dnsVIP)
	before, _ := b.dstAPI.Service(svcA)

	beforeB, _ := b.dstAPI.Service(svcB)

	// B removes its link: only B's service goes.
	cfgB2 := *cfgB
	cfgB2.Bridges = nil
	rb.m.Reconcile(rb.ctx, &cfgB2)
	waitFor(t, 30*time.Second, "instance B's service removed with its link", func() bool {
		_, ok := b.dstAPI.Service(svcB)
		return !ok
	})
	time.Sleep(500 * time.Millisecond)
	if after, ok := b.dstAPI.Service(svcA); !ok || !reflect.DeepEqual(after, before) {
		t.Errorf("instance A's service changed when B removed its link: %+v", after)
	}

	// B shuts down: nothing in dst changes.
	b.dstAPI.PutService(beforeB)
	b.dstAPI.ResetCalls()
	rb.stop(t)
	time.Sleep(500 * time.Millisecond)
	if after, ok := b.dstAPI.Service(svcA); !ok || !reflect.DeepEqual(after, before) {
		t.Errorf("instance A's service changed when B stopped: %+v", after)
	}
	if _, ok := b.dstAPI.Service(svcB); !ok {
		t.Error("instance B's service deleted on shutdown")
	}
	if dnsOwner == cfgA.InstanceID && ownerOf(dnsVIP) != cfgA.InstanceID {
		t.Errorf("instance A's DNS VIP was touched by B")
	}
}

// A hand-made svc:tailnetlink in dst is left alone and the UI is not
// published there, while it still is in src.
func TestManagerUIServiceConflict(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	foreign := b.dstAPI.PutService(tsclient.VIPService{Name: "svc:tailnetlink", Comment: "not ours", Ports: []string{"tcp:80"}})
	srcClient := client(t, ctx, b.src, "src-client")
	cfg := b.config()
	webAddr := freeAddr(t)
	r := startManager(t, cfg, webAddr)

	vip := waitVIP(t, b.srcAPI, "svc:tailnetlink")
	if s, _ := b.srcAPI.Service("svc:tailnetlink"); s.Annotations["tailnetlink/owner"] != cfg.InstanceID {
		t.Errorf("src UI service owner = %q", s.Annotations["tailnetlink/owner"])
	}
	hc := httpVia(srcClient, netip.AddrPortFrom(vip, 80))
	waitFor(t, 30*time.Second, "UI through the src VIP", func() bool {
		resp, err := hc.Get("http://tailnetlink/api/status")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode == http.StatusOK
	})

	waitFor(t, 30*time.Second, "conflict reported for dst", func() bool {
		return r.logged("web UI not published")
	})
	if got, _ := b.dstAPI.Service("svc:tailnetlink"); !reflect.DeepEqual(got, foreign) {
		t.Errorf("foreign svc:tailnetlink changed: %+v", got)
	}
}

// With ui.service_name set, the UI is published under that name instead.
func TestManagerUIServiceName(t *testing.T) {
	e2eSetup(t)
	b := newBorder(t)
	cfg := b.config()
	cfg.UI.ServiceName = "svc:tnl-ui-" + b.sfx
	startManager(t, cfg, freeAddr(t))
	waitVIP(t, b.dstAPI, cfg.UI.ServiceName)
	if _, ok := b.dstAPI.Service("svc:tailnetlink"); ok {
		t.Error("svc:tailnetlink was created too")
	}
}
