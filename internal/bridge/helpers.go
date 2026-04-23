package bridge

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	tsclient "tailscale.com/client/tailscale/v2"
)

type halfCloser interface{ CloseWrite() error }

// firstIP returns the first valid IP from addrs, accepting both plain address
// and CIDR notation. IPv4 is naturally preferred since Tailscale lists it first.
func firstIP(addrs []string) (netip.Addr, bool) {
	for _, a := range addrs {
		if prefix, err := netip.ParsePrefix(a); err == nil {
			if addr := prefix.Addr().Unmap(); addr.IsValid() {
				return addr, true
			}
		} else if addr, err := netip.ParseAddr(a); err == nil {
			if addr = addr.Unmap(); addr.IsValid() {
				return addr, true
			}
		}
	}
	return netip.Addr{}, false
}

// ensureVIPService creates or updates svc, preserving any existing VIP addresses,
// then fetches and returns the service with its assigned addresses.
func ensureVIPService(ctx context.Context, client *tsclient.Client, svc tsclient.VIPService) (*tsclient.VIPService, error) {
	if existing, err := client.VIPServices().Get(ctx, svc.Name); err == nil {
		svc.Addrs = existing.Addrs
	}
	if err := client.VIPServices().CreateOrUpdate(ctx, svc); err != nil {
		return nil, fmt.Errorf("create/update VIP service %q: %w", svc.Name, err)
	}
	created, err := client.VIPServices().Get(ctx, svc.Name)
	if err != nil {
		return nil, fmt.Errorf("get VIP service %q: %w", svc.Name, err)
	}
	return created, nil
}

// formatBytes returns a human-readable byte count.
func formatBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// connLabel returns the most informative display string for a connection peer.
func connLabel(addr, nodeName, identity string) string {
	if identity != "" {
		if nodeName != "" {
			return identity + " (" + nodeName + ")"
		}
		return identity
	}
	if nodeName != "" {
		return nodeName
	}
	return addr
}

// newAPIClient constructs a Tailscale API client from a TailnetConfig.
func newAPIClient(tc config.TailnetConfig) *tsclient.Client {
	tailnet := tc.Tailnet
	if tailnet == "" {
		tailnet = "-"
	}
	return &tsclient.Client{
		Tailnet: tailnet,
		Auth:    &tsclient.OAuth{ClientID: tc.OAuth.ClientID, ClientSecret: tc.OAuth.ClientSecret},
	}
}
