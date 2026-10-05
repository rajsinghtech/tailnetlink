package bridge

import (
	"context"
	"fmt"
	"slices"
	"sort"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	tsclient "tailscale.com/client/tailscale/v2"
)

// PruneAction is one change Prune made, or would make in a dry run.
type PruneAction struct {
	Tailnet string // tailnet name in the config
	What    string // "delete service" or "remove split-DNS resolver"
	Name    string // service name, or "zone resolver"
}

func (a PruneAction) String() string {
	return fmt.Sprintf("%s: %s %s", a.Tailnet, a.What, a.Name)
}

// Prune deletes every VIP service owned by cfg.InstanceID in every
// configured tailnet, and takes their addresses out of split-DNS. It is the
// explicit cleanup for services that tailnetlink no longer deletes on its
// own, for example after a link was removed while tailnetlink was stopped.
// Run it while tailnetlink is stopped; the next start recreates whatever
// the config still needs. With dryRun set nothing is changed.
func Prune(ctx context.Context, cfg *config.Config, dryRun bool) ([]PruneAction, error) {
	if cfg.InstanceID == "" {
		return nil, fmt.Errorf("prune: instance_id is not set")
	}
	names := make([]string, 0, len(cfg.Tailnets))
	for name := range cfg.Tailnets {
		names = append(names, name)
	}
	sort.Strings(names)

	var actions []PruneAction
	for _, name := range names {
		a, err := pruneTailnet(ctx, name, newAPIClient(cfg.Tailnets[name]), cfg.InstanceID, dryRun)
		actions = append(actions, a...)
		if err != nil {
			return actions, fmt.Errorf("prune %s: %w", name, err)
		}
	}
	return actions, nil
}

func pruneTailnet(ctx context.Context, name string, client *tsclient.Client, owner string, dryRun bool) ([]PruneAction, error) {
	svcs, err := client.VIPServices().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	var actions []PruneAction
	var addrs []string
	for _, svc := range svcs {
		if !ownedBy(&svc, owner) {
			continue
		}
		actions = append(actions, PruneAction{Tailnet: name, What: "delete service", Name: svc.Name})
		addrs = append(addrs, svc.Addrs...)
		if dryRun {
			continue
		}
		if err := deleteOwnedVIPService(ctx, client, owner, svc.Name); err != nil {
			return actions, err
		}
	}
	if len(addrs) == 0 {
		return actions, nil
	}

	zones, err := client.DNS().SplitDNS(ctx)
	if err != nil {
		return actions, fmt.Errorf("get split-DNS: %w", err)
	}
	update := tsclient.SplitDNSRequest{}
	zoneNames := make([]string, 0, len(zones))
	for zone := range zones {
		zoneNames = append(zoneNames, zone)
	}
	sort.Strings(zoneNames)
	for _, zone := range zoneNames {
		resolvers := zones[zone]
		kept := slices.DeleteFunc(slices.Clone(resolvers), func(r string) bool { return slices.Contains(addrs, r) })
		if len(kept) == len(resolvers) {
			continue
		}
		for _, r := range resolvers {
			if slices.Contains(addrs, r) {
				actions = append(actions, PruneAction{Tailnet: name, What: "remove split-DNS resolver", Name: zone + " " + r})
			}
		}
		if len(kept) == 0 {
			kept = nil
		}
		update[zone] = kept
	}
	if len(update) > 0 && !dryRun {
		if _, err := client.DNS().UpdateSplitDNS(ctx, update); err != nil {
			return actions, fmt.Errorf("update split-DNS: %w", err)
		}
	}
	return actions, nil
}
