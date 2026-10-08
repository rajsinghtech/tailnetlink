package bridge

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"sync"

	tsclient "tailscale.com/client/tailscale/v2"
)

// VIPService represents a managed VIP service on the destination tailnet.
type VIPService struct {
	ServiceName string
	SourceFQDN  string
	SourceIP    netip.Addr
	VIP         netip.Addr
	Ports       []int
}

// Reconciler creates and deletes VIP services on the destination tailnet to
// match the set of discovered source devices.
type Reconciler struct {
	client *tsclient.Client
	ports  []int
	tags   []string // ACL tags applied to the VIP service (must match dest tsnet node tags)
	owner  string   // instance id written to and checked against tailnetlink/owner
	bridge string   // from/dest/link; empty keeps the owner-only annotation
	logger *slog.Logger

	mu       sync.RWMutex
	services map[string]*VIPService // key: ServiceName
}

func NewReconciler(client *tsclient.Client, ports []int, tags []string, owner string, logger *slog.Logger) *Reconciler {
	return &Reconciler{
		client:   client,
		ports:    ports,
		tags:     tags,
		owner:    owner,
		logger:   logger,
		services: make(map[string]*VIPService),
	}
}

// Ensure creates or updates a VIP service for the given device if needed, then
// returns the resolved service (including its assigned VIP address).
func (r *Reconciler) Ensure(ctx context.Context, srcTailnet string, dev Device, shortName string) (*VIPService, error) {
	svcName := ServiceName(srcTailnet, dev.FQDN, shortName)

	r.mu.RLock()
	if svc, ok := r.services[svcName]; ok {
		r.mu.RUnlock()
		return svc, nil
	}
	r.mu.RUnlock()

	// Ports are stored as "tcp:<port>" strings in the Tailscale API.
	portStrings := make([]string, 0, len(r.ports))
	for _, p := range r.ports {
		portStrings = append(portStrings, "tcp:"+strconv.Itoa(p))
	}

	annotations := map[string]string{
		"tailnetlink/source": srcTailnet,
	}
	if r.bridge != "" {
		annotations[annotationBridge] = r.bridge
	}
	created, err := ensureVIPService(ctx, r.client, r.owner, tsclient.VIPService{
		Name:        svcName,
		Ports:       portStrings,
		Tags:        r.tags,
		Comment:     fmt.Sprintf("managed by tailnetlink (source: %s → %s)", srcTailnet, dev.FQDN),
		Annotations: annotations,
	})
	if err != nil {
		return nil, err
	}

	vip, _ := firstIP(created.Addrs)

	result := &VIPService{
		ServiceName: svcName,
		SourceFQDN:  dev.FQDN,
		SourceIP:    dev.IP,
		VIP:         vip,
		Ports:       r.ports,
	}

	r.mu.Lock()
	r.services[svcName] = result
	r.mu.Unlock()

	r.logger.Info("VIP service created", "name", svcName, "vip", vip, "source", dev.FQDN)
	return result, nil
}

// Delete removes the VIP service for the given source device. It only acts
// on services this Reconciler ensured, and re-reads the service first so it
// never deletes one whose owner annotation has changed since.
func (r *Reconciler) Delete(ctx context.Context, srcTailnet string, dev Device, shortName string) error {
	svcName := ServiceName(srcTailnet, dev.FQDN, shortName)

	r.mu.Lock()
	svc, ok := r.services[svcName]
	if !ok {
		r.mu.Unlock()
		return nil
	}
	delete(r.services, svcName)
	r.mu.Unlock()

	if err := deleteOwnedBridge(ctx, r.client, r.owner, r.bridge, svcName); err != nil {
		// Put it back so a later Delete tries the API again. Dropping it
		// here made one failed delete look like success forever.
		r.mu.Lock()
		if _, exists := r.services[svcName]; !exists {
			r.services[svcName] = svc
		}
		r.mu.Unlock()
		return err
	}

	r.logger.Info("VIP service deleted", "name", svcName, "source", dev.FQDN)
	return nil
}
