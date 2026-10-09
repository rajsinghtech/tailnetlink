package bridge

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/tsapi"
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

// Annotations tailnetlink puts on every VIP service it creates. The owner
// annotation is what the ownership guard checks. The bridge annotation names
// the from/dest/link that published the service, so two bridges in one
// tailnet do not overwrite each other. managed is informational.
const (
	annotationManaged = "tailnetlink/managed"
	annotationOwner   = "tailnetlink/owner"
	annotationBridge  = "tailnetlink/export"
)

// ErrNameConflict is returned when a VIP service with the wanted name exists
// and is not owned by this instance.
var ErrNameConflict = errors.New("name conflict")

// ConflictError says which service is in the way and who owns it, if anyone.
type ConflictError struct {
	Service string
	Owner   string // value of the owner annotation, empty when there is none
}

func (e *ConflictError) Error() string {
	if e.Owner == "" {
		return fmt.Sprintf("name conflict: %s already exists and was not created by this tailnetlink instance", e.Service)
	}
	return fmt.Sprintf("name conflict: %s is owned by tailnetlink instance %q", e.Service, e.Owner)
}

func (e *ConflictError) Is(target error) bool { return target == ErrNameConflict }

// ownedBy reports whether svc belongs to owner. With bridge set, a service
// that already names a different bridge is not ours to change. An empty
// bridge annotation still matches, so a service this process created before
// bridge ids were written can be updated by the bridge that owns that name.
// An empty bridge argument ignores the bridge annotation. Prune, the UI and
// DNS use that form and may touch any service this instance owns.
func ownedBy(svc *tsclient.VIPService, owner, bridge string) bool {
	if svc == nil || owner == "" || svc.Annotations[annotationOwner] != owner {
		return false
	}
	if bridge == "" {
		return true
	}
	got := svc.Annotations[annotationBridge]
	return got == "" || got == bridge
}

// conflictOwner is the Owner string on a ConflictError. When the existing
// service names a bridge, that id is included. A service with no bridge
// annotation keeps the owner value alone, including empty.
func conflictOwner(svc *tsclient.VIPService) string {
	if svc == nil {
		return ""
	}
	owner := svc.Annotations[annotationOwner]
	bridge := svc.Annotations[annotationBridge]
	if bridge == "" {
		return owner
	}
	if owner == "" {
		return "bridge " + bridge
	}
	return owner + " bridge " + bridge
}

// ensureVIPService creates svc, or updates it if it already exists and is
// owned by owner, keeping its VIP addresses. A service that exists without
// our owner annotation is left alone and a *ConflictError is returned. So is
// a service from older versions that only has the managed annotation.
func ensureVIPService(ctx context.Context, client *tsclient.Client, owner string, svc tsclient.VIPService) (*tsclient.VIPService, error) {
	if owner == "" {
		return nil, errors.New("ensure VIP service: no instance id")
	}
	wantBridge := svc.Annotations[annotationBridge]
	existing, err := client.VIPServices().Get(ctx, svc.Name)
	switch {
	case err == nil:
		if !ownedBy(existing, owner, wantBridge) {
			return nil, &ConflictError{Service: svc.Name, Owner: conflictOwner(existing)}
		}
		svc.Addrs = existing.Addrs
	case tsclient.IsNotFound(err):
	default:
		return nil, fmt.Errorf("get VIP service %q: %w", svc.Name, err)
	}
	annotations := make(map[string]string, len(svc.Annotations)+2)
	maps.Copy(annotations, svc.Annotations)
	annotations[annotationManaged] = "true"
	annotations[annotationOwner] = owner
	if wantBridge == "" {
		delete(annotations, annotationBridge)
	} else {
		annotations[annotationBridge] = wantBridge
	}
	svc.Annotations = annotations
	if err := client.VIPServices().CreateOrUpdate(ctx, svc); err != nil {
		return nil, fmt.Errorf("create/update VIP service %q: %w", svc.Name, err)
	}
	created, err := client.VIPServices().Get(ctx, svc.Name)
	if err != nil {
		return nil, fmt.Errorf("get VIP service %q: %w", svc.Name, err)
	}
	return created, nil
}

// deleteOwnedVIPService re-reads the service and deletes it only if owner
// still owns it. A service that is already gone is not an error. A service
// someone else now owns is left alone and a *ConflictError is returned.
func deleteOwnedVIPService(ctx context.Context, client *tsclient.Client, owner, name string) error {
	existing, err := client.VIPServices().Get(ctx, name)
	switch {
	case tsclient.IsNotFound(err):
		return nil
	case err != nil:
		return fmt.Errorf("get VIP service %q: %w", name, err)
	case !ownedBy(existing, owner, ""):
		return &ConflictError{Service: name, Owner: conflictOwner(existing)}
	}
	if err := client.VIPServices().Delete(ctx, name); err != nil && !tsclient.IsNotFound(err) {
		return fmt.Errorf("delete VIP service %q: %w", name, err)
	}
	return nil
}

// deleteOwnedBridge deletes name only when owner and bridge still match.
// An empty bridge falls back to the owner check, which is what prune uses.
// A service owned by this instance but published by a different bridge is
// left in place.
func deleteOwnedBridge(ctx context.Context, client *tsclient.Client, owner, bridge, name string) error {
	if bridge == "" {
		return deleteOwnedVIPService(ctx, client, owner, name)
	}
	existing, err := client.VIPServices().Get(ctx, name)
	switch {
	case tsclient.IsNotFound(err):
		return nil
	case err != nil:
		return fmt.Errorf("get VIP service %q: %w", name, err)
	case !ownedBy(existing, owner, bridge):
		return &ConflictError{Service: name, Owner: conflictOwner(existing)}
	}
	if err := client.VIPServices().Delete(ctx, name); err != nil && !tsclient.IsNotFound(err) {
		return fmt.Errorf("delete VIP service %q: %w", name, err)
	}
	return nil
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
	return tsapi.NewClient(tc, tsapi.LimitedTransport(nil, tsapi.DefaultAPIRatePerSec, tsapi.DefaultAPIBurst, nil))
}
