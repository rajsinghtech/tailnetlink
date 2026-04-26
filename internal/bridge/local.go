package bridge

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	"tailscale.com/tsnet"
)

// isLocalHost returns true when host is localhost, 127.0.0.1, ::1, or any bare IP address.
func isLocalHost(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "0.0.0.0" {
		return true
	}
	_, err := netip.ParseAddr(h)
	return err == nil
}

// localSourceEffectiveDNSName returns the DNS name to register in the dest tailnet.
// If spec.DNSName is set it is returned directly. If addr's hostname is a real FQDN
// (not localhost/IP), it is auto-derived. Returns an error if the host is localhost
// or a bare IP and no dns_name is provided.
func localSourceEffectiveDNSName(spec config.LocalSourceSpec) (string, error) {
	if spec.DNSName != "" {
		return spec.DNSName, nil
	}
	host, _, err := net.SplitHostPort(spec.Addr)
	if err != nil {
		return "", fmt.Errorf("invalid addr %q: %w", spec.Addr, err)
	}
	if isLocalHost(host) {
		return "", fmt.Errorf("addr %q requires an explicit dns_name (cannot derive from localhost/IP)", spec.Addr)
	}
	return host, nil
}

// localSourceShortName returns the VIP service short name. shortName from the spec
// takes precedence; otherwise the first DNS label of dnsName is used.
func localSourceShortName(shortName, dnsName string) string {
	if shortName != "" {
		return shortName
	}
	if dot := strings.IndexByte(dnsName, '.'); dot > 0 {
		return dnsName[:dot]
	}
	return dnsName
}

// localSourceExposePort returns the VIP-side listen port. Falls back to addr's port
// when spec.ExposePort is zero.
func localSourceExposePort(spec config.LocalSourceSpec) (int, error) {
	if spec.ExposePort > 0 && spec.ExposePort <= 65535 {
		return spec.ExposePort, nil
	}
	if spec.ExposePort != 0 {
		return 0, fmt.Errorf("expose_port %d out of range", spec.ExposePort)
	}
	_, portStr, err := net.SplitHostPort(spec.Addr)
	if err != nil {
		return 0, fmt.Errorf("invalid addr %q: %w", spec.Addr, err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return 0, fmt.Errorf("invalid port in addr %q", spec.Addr)
	}
	return p, nil
}

// newLocalForwarder constructs a Forwarder that dials localAddr directly via net.DialContext.
// dialSrv is nil; localAddr is used instead in handle().
func newLocalForwarder(
	listenSrv *tsnet.Server,
	localAddr string,
	vip *VIPService,
	bridgeID string,
	timeout time.Duration,
	store *state.Store,
	logger *slog.Logger,
) *Forwarder {
	return &Forwarder{
		listenSrv: listenSrv,
		localAddr: localAddr,
		vip:       vip,
		bridgeID:  bridgeID,
		timeout:   timeout,
		store:     store,
		logger:    logger,
	}
}

type localBridgeInfo struct {
	bridgeID  string
	rec       *Reconciler
	dev       Device
	shortName string
}

// runLocalRule handles bridge rules with local_sources. It creates a VIP service and
// Forwarder for each local_source in each dest tailnet, then blocks until ctx is cancelled.
func (m *Manager) runLocalRule(ctx context.Context, rule config.BridgeRule, dialTimeout time.Duration) {
	m.mu.Lock()
	dests := make([]destCtx, 0, len(rule.DestTailnets))
	for _, destName := range rule.DestTailnets {
		destSrv := m.servers[destName]
		destClient := m.apiClients[destName]
		destTags := m.cfg.Tailnets[destName].Tags
		m.mu.Unlock()
		if destSrv == nil {
			m.logger.Error("local rule: dest tailnet not connected", "rule", rule.Name, "dest", destName)
			m.store.Log("error", fmt.Sprintf("[%s] rule failed: dest tailnet %q not connected", rule.Name, destName), nil)
			return
		}
		dests = append(dests, destCtx{name: destName, srv: destSrv, client: destClient, tags: destTags})
		m.mu.Lock()
	}
	m.mu.Unlock()

	m.logger.Info("local rule started", "rule", rule.Name, "sources", len(rule.LocalSources))
	m.store.Log("info", fmt.Sprintf("[%s] local rule started: %d sources", rule.Name, len(rule.LocalSources)), nil)

	var bridges []localBridgeInfo

	for _, src := range rule.LocalSources {
		dnsName, err := localSourceEffectiveDNSName(src)
		if err != nil {
			m.logger.Error("local rule: invalid source", "rule", rule.Name, "addr", src.Addr, "err", err)
			m.store.Log("error", fmt.Sprintf("[%s] skipping %s: %v", rule.Name, src.Addr, err), nil)
			continue
		}
		exposePort, err := localSourceExposePort(src)
		if err != nil {
			m.logger.Error("local rule: invalid expose port", "rule", rule.Name, "addr", src.Addr, "err", err)
			continue
		}

		shortName := localSourceShortName(src.ShortName, dnsName)
		syntheticDev := Device{Name: src.Addr, FQDN: dnsName}
		createdAt := time.Now()

		for _, dest := range dests {
			bridgeID := rule.Name + "/local/" + dest.name + "/" + src.Addr
			srcRec := NewReconciler(dest.client, []int{exposePort}, dest.tags, m.logger)

			m.store.UpsertBridge(state.BridgeEntry{
				ID: bridgeID, RuleName: rule.Name, DestTailnet: dest.name,
				ServiceName: ServiceName("local", dnsName, shortName),
				SourceHost:  src.Addr, SourceIP: src.Addr,
				Ports: []int{exposePort}, Status: state.BridgeStatusPending, CreatedAt: createdAt,
			})

			vip, err := srcRec.Ensure(ctx, "local", syntheticDev, shortName)
			if err != nil {
				m.logger.Error("local rule: VIP ensure failed", "rule", rule.Name, "dest", dest.name, "addr", src.Addr, "err", err)
				m.store.UpsertBridge(state.BridgeEntry{
					ID: bridgeID, RuleName: rule.Name, DestTailnet: dest.name,
					ServiceName: ServiceName("local", dnsName, shortName),
					SourceHost: src.Addr, SourceIP: src.Addr,
					Ports: []int{exposePort}, Status: state.BridgeStatusError, Error: err.Error(), CreatedAt: createdAt,
				})
				m.store.Log("error", fmt.Sprintf("[%s] VIP failed for %s→%s: %v", rule.Name, src.Addr, dest.name, err), nil)
				continue
			}

			fwd := newLocalForwarder(dest.srv, src.Addr, vip, bridgeID, dialTimeout, m.store, m.logger)
			if err := fwd.Start(ctx); err != nil {
				m.logger.Error("local rule: forwarder start failed", "rule", rule.Name, "dest", dest.name, "addr", src.Addr, "err", err)
				_ = srcRec.Delete(context.Background(), "local", syntheticDev, shortName)
				m.store.DeleteBridge(bridgeID)
				continue
			}

			m.store.UpsertBridge(state.BridgeEntry{
				ID: bridgeID, RuleName: rule.Name, DestTailnet: dest.name,
				ServiceName: vip.ServiceName, SourceHost: src.Addr, SourceIP: src.Addr,
				DestVIP: vip.VIP.String(), Ports: []int{exposePort},
				Status: state.BridgeStatusActive, CreatedAt: createdAt,
			})
			m.store.Log("info", fmt.Sprintf("[%s] local bridge active: %s → %s (%s)", rule.Name, src.Addr, vip.VIP, dest.name), nil)

			m.mu.Lock()
			m.forwarders[bridgeID] = fwd
			m.mu.Unlock()

			if vip.VIP.IsValid() {
				m.startDeviceDNS(ctx, bridgeID, rule.Name, "", dnsName, "", vip.VIP, dest)
			}

			bridges = append(bridges, localBridgeInfo{
				bridgeID:  bridgeID,
				rec:       srcRec,
				dev:       syntheticDev,
				shortName: shortName,
			})
		}
	}

	<-ctx.Done()

	var wg sync.WaitGroup
	for _, lb := range bridges {
		wg.Add(1)
		go func(lb localBridgeInfo) {
			defer wg.Done()
			m.mu.Lock()
			if fwd, ok := m.forwarders[lb.bridgeID]; ok {
				fwd.Stop()
				delete(m.forwarders, lb.bridgeID)
			}
			cleanup := m.dnsCleanups[lb.bridgeID]
			delete(m.dnsCleanups, lb.bridgeID)
			m.mu.Unlock()
			if cleanup != nil {
				cleanup()
			}
			if err := lb.rec.Delete(context.Background(), "local", lb.dev, lb.shortName); err != nil {
				m.logger.Warn("local rule: VIP delete failed", "bridge", lb.bridgeID, "err", err)
			}
			m.store.DeleteBridge(lb.bridgeID)
		}(lb)
	}
	wg.Wait()
	m.store.Log("info", fmt.Sprintf("[%s] local rule stopped", rule.Name), nil)
}
