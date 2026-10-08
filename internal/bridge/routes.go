package bridge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"tailscale.com/tsnet"
)

// errNoSubnetRoute means no peer in the source tailnet is advertising a
// route that covers the address.
var errNoSubnetRoute = errors.New("no subnet route to that address")

// routedFailureReason classifies a routed dial error for metrics.
// A timeout counts as denied: the source tailnet drops packets a grant
// does not allow, and that looks like a dial that never completes.
func routedFailureReason(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, errNoSubnetRoute) {
		return "no_route"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "denied"),
		strings.Contains(msg, "filtered"),
		strings.Contains(msg, "not allowed"),
		strings.Contains(msg, "acl"),
		strings.Contains(msg, "rejected"),
		errors.Is(err, context.DeadlineExceeded),
		strings.Contains(msg, "timeout"),
		strings.Contains(msg, "i/o timeout"):
		return "denied"
	default:
		return "error"
	}
}

func routedDialMessage(svc, target, reason string, err error) string {
	switch reason {
	case "no_route":
		return fmt.Sprintf("routed dial: no subnet route for %s (%s): %v", target, svc, err)
	case "denied":
		return fmt.Sprintf("routed dial denied: %s → %s: %v; grant this node's tag access to that IP and port in the source tailnet (filtered packets are dropped)", svc, target, err)
	default:
		return fmt.Sprintf("routed dial failed: %s → %s: %v", svc, target, err)
	}
}

// tailnetDial dials through a tsnet node. Tests replace it.
var tailnetDial = func(ctx context.Context, srv *tsnet.Server, network, addr string) (net.Conn, error) {
	if srv == nil {
		return nil, errors.New("no source node")
	}
	return srv.Dial(ctx, network, addr)
}
