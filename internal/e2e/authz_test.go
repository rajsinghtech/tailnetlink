package e2e

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/bridge"
	"github.com/rajsinghtech/tailnetlink/internal/config"
	"tailscale.com/tailcfg"
)

// require_cap denies before dial when the peer has no grant, and allows after
// the destination control server hands out the app capability.
func TestManagerAuthzRequireCap(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	_, peers := echoBackend(t, ctx, b.src, "backend", 8080)
	rule := b.deviceRule("web", "backend", "", 8080)
	rule.Authz = config.AuthzConfig{Mode: config.AuthzRequireCap}
	startManager(t, b.config(rule), "")
	vip := waitVIP(t, b.dstAPI, b.serviceName("backend", ""))
	cl := client(t, ctx, b.dst, "client")
	addr := netip.AddrPortFrom(vip, 8080)

	if err := tryEcho(ctx, cl, addr, "denied"); err == nil {
		t.Fatal("echo succeeded without the capability")
	} else if dialTimedOut(err) {
		// A kernel timeout means the VIP was never installed in the
		// userspace route table. Authz closes the connection only after
		// the handshake, so a timeout is not a denial.
		t.Fatalf("denied dial never reached the forwarder: %v", err)
	}
	select {
	case p := <-peers:
		t.Fatalf("backend saw a denied connection from %s", p)
	case <-time.After(500 * time.Millisecond):
	}

	raw, err := tailcfg.MarshalCapJSON(struct {
		Links []string `json:"links"`
	}{Links: []string{"web"}})
	if err != nil {
		t.Fatal(err)
	}
	b.dst.control.SetGlobalAppCaps(tailcfg.PeerCapMap{bridge.CapName: {raw}})
	// The grant is one wake. Replay it so a poll with a full buffer still
	// builds a map that contains the capability.
	b.dstAPI.keepWaking(routeWakeFor)
	echoVia(t, ctx, cl, addr, "allowed")
	select {
	case <-peers:
	case <-time.After(5 * time.Second):
		t.Fatal("backend never saw the allowed connection")
	}
}

// dialTimedOut reports a dial that never entered the tailnet. The kernel
// dialer returns this when the VIP prefix is not in the userspace route table.
func dialTimedOut(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// A client that is already streaming a netmap when the VIP appears must
// learn the route. Otherwise it dials the address forever.
func TestClientLearnsVIPRoute(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	echoBackend(t, ctx, b.src, "backend", 8080)
	cl := client(t, ctx, b.dst, "client")
	startManager(t, b.config(b.deviceRule("web", "backend", "", 8080)), "")
	vip := waitVIP(t, b.dstAPI, b.serviceName("backend", ""))
	echoVia(t, ctx, cl, netip.AddrPortFrom(vip, 8080), "open")
}

// A link authz of off overrides a border require_cap default.
func TestManagerAuthzLinkOverridesBorder(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	echoBackend(t, ctx, b.src, "backend", 8080)
	bd := b.fileConfig(b.deviceLink("web", "backend", "", 8080))
	bd.Authz = config.AuthzConfig{Mode: config.AuthzRequireCap}
	bd.Exports[0].Authz = config.AuthzConfig{Mode: config.AuthzOff}
	startManager(t, loadBorder(t, bd), "")
	vip := waitVIP(t, b.dstAPI, "svc:web")
	echoVia(t, ctx, client(t, ctx, b.dst, "client"), netip.AddrPortFrom(vip, 8080), "open")
}
