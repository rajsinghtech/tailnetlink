package bridge

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	tsclient "tailscale.com/client/tailscale/v2"
)

// SplitDNSConfigurator manages split-DNS routing on the destination tailnet
// so that queries for the bridge zone resolve to the given nameservers.
type SplitDNSConfigurator struct {
	client  *tsclient.Client
	zone    string
	dnsAddr string
	logger  *slog.Logger
}

func NewSplitDNSConfigurator(client *tsclient.Client, zone, dnsAddr string, logger *slog.Logger) *SplitDNSConfigurator {
	return &SplitDNSConfigurator{client: client, zone: zone, dnsAddr: dnsAddr, logger: logger}
}

func (s *SplitDNSConfigurator) Configure(ctx context.Context) error {
	current, err := s.client.DNS().SplitDNS(ctx)
	if err != nil {
		return fmt.Errorf("get split-DNS: %w", err)
	}

	existing := current[s.zone]
	if slices.Contains(existing, s.dnsAddr) {
		return nil // already present, nothing to do
	}

	_, err = s.client.DNS().UpdateSplitDNS(ctx, tsclient.SplitDNSRequest{
		s.zone: append(existing, s.dnsAddr),
	})
	if err != nil {
		return fmt.Errorf("update split-DNS: %w", err)
	}

	s.logger.Info("split-DNS configured", "zone", s.zone, "resolver", s.dnsAddr)
	return nil
}

func (s *SplitDNSConfigurator) Remove(ctx context.Context) error {
	current, err := s.client.DNS().SplitDNS(ctx)
	if err != nil {
		return fmt.Errorf("get split-DNS: %w", err)
	}

	existing := current[s.zone]
	filtered := make([]string, 0, len(existing))
	for _, r := range existing {
		if r != s.dnsAddr {
			filtered = append(filtered, r)
		}
	}

	if len(filtered) == len(existing) {
		return nil // our resolver wasn't there, nothing to do
	}

	// If others remain, keep the zone with those resolvers. If none remain,
	// nil removes the zone entry entirely.
	var resolvers []string
	if len(filtered) > 0 {
		resolvers = filtered
	}
	_, err = s.client.DNS().UpdateSplitDNS(ctx, tsclient.SplitDNSRequest{
		s.zone: resolvers,
	})
	if err != nil {
		return fmt.Errorf("remove split-DNS: %w", err)
	}

	s.logger.Info("split-DNS resolver removed", "zone", s.zone, "resolver", s.dnsAddr)
	return nil
}
