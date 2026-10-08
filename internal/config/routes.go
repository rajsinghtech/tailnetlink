package config

import (
	"net"
	"net/netip"
	"slices"
)

// AcceptedRouteAddrs is the set of local addresses a tailnet's node may
// accept subnet routes for. It is the union of parseable IPs in local
// links on bridges whose from tailnet is that key. Hostnames that are not
// IPs are skipped. The result is sorted and has no duplicates.
//
// The node does not program routes from this list yet. A later change that
// dials subnet-routed addresses should accept only advertised routes that
// cover these addresses, and should recompute the set whenever the config
// is applied. LocalSourceSpec is left unchanged so that change can add
// ports beside addr without a conflict here.
func AcceptedRouteAddrs(cfg *Config, tailnet string) []netip.Addr {
	if cfg == nil || tailnet == "" {
		return nil
	}
	seen := map[netip.Addr]struct{}{}
	var out []netip.Addr
	for _, rule := range cfg.Bridges {
		if rule.FromTailnet() != tailnet {
			continue
		}
		for _, src := range rule.LocalSources {
			host, _, err := net.SplitHostPort(src.Addr)
			if err != nil {
				continue
			}
			ip, err := netip.ParseAddr(host)
			if err != nil || !ip.IsValid() {
				continue
			}
			ip = ip.Unmap()
			if _, ok := seen[ip]; ok {
				continue
			}
			seen[ip] = struct{}{}
			out = append(out, ip)
		}
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return out
}
