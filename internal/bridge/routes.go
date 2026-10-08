package bridge

import (
	"net/netip"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"tailscale.com/tsnet"
)

// acceptNodeRoutes programs subnet-route acceptance on one node. The default
// does nothing, so this process never accepts, rejects or rewrites routes
// or policy. A later change should replace it with a function that accepts
// only advertised routes covering addrs.
//
// refreshAcceptedRoutes calls it after every Reconcile, including a hot
// reload that did not restart the node. The replacement must not call
// Reconcile.
var acceptNodeRoutes = func(*tsnet.Server, []netip.Addr) error { return nil }

// refreshAcceptedRoutes recomputes the local addresses each live node may
// accept routes for. Nodes that did not restart still see the new set.
func (m *Manager) refreshAcceptedRoutes() {
	m.mu.Lock()
	cfg := m.cfg
	type live struct {
		name string
		srv  *tsnet.Server
	}
	nodes := make([]live, 0, len(m.servers))
	for name, srv := range m.servers {
		if srv != nil {
			nodes = append(nodes, live{name, srv})
		}
	}
	m.mu.Unlock()
	for _, n := range nodes {
		addrs := config.AcceptedRouteAddrs(cfg, n.name)
		if err := acceptNodeRoutes(n.srv, addrs); err != nil {
			m.logger.Warn("accept routes", "tailnet", n.name, "err", err)
		}
	}
}
