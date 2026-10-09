package config

import (
	"net"
	"net/netip"
	"slices"
)

// AcceptedRouteAddrs is the set of IP addresses on targets that leave
// tailnet. Hostnames are skipped. The dialer installs advertised prefixes
// from the node's netmap, not from this list. The result is sorted and has
// no duplicates.
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
			host := src.Addr
			if h, _, err := net.SplitHostPort(src.Addr); err == nil {
				host = h
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
