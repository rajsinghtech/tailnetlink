package bridge

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	"tailscale.com/tsnet"
)

// newLocalForwarder constructs a Forwarder that dials on the host network.
// dialSrv stays nil. Set localAddr to dial one address for every listen port,
// or localTargets to choose the backend address per listen port.
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

// localBridgeID keys one local target in one destination. The classic
// host:port form keeps the historical id. A host with no port would otherwise
// collide when two targets share that host, so the short name is part of the id.
func localBridgeID(rule, dest, addr, shortName string) string {
	id := rule + "/local/" + dest + "/" + addr
	if _, _, err := net.SplitHostPort(addr); err != nil {
		id += "/" + shortName
	}
	return id
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
	dests := make([]destCtx, 0, len(rule.DestTailnets))
	for _, destName := range rule.DestTailnets {
		m.mu.Lock()
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
	}

	m.logger.Info("local rule started", "rule", rule.Name, "sources", len(rule.LocalSources))
	m.store.Log("info", fmt.Sprintf("[%s] local rule started: %d sources", rule.Name, len(rule.LocalSources)), nil)

	var bridges []localBridgeInfo

	for _, src := range rule.LocalSources {
		dnsName, err := src.EffectiveDNSName()
		if err != nil {
			m.logger.Error("local rule: invalid source", "rule", rule.Name, "addr", src.Addr, "err", err)
			m.store.Log("error", fmt.Sprintf("[%s] skipping %s: %v", rule.Name, src.Addr, err), nil)
			continue
		}
		host, forwards, err := src.Forwards()
		if err != nil {
			m.logger.Error("local rule: invalid ports", "rule", rule.Name, "addr", src.Addr, "err", err)
			m.store.Log("error", fmt.Sprintf("[%s] skipping %s: %v", rule.Name, src.Addr, err), nil)
			continue
		}
		exposePorts := make([]int, len(forwards))
		targets := make(map[int]string, len(forwards))
		for i, fw := range forwards {
			exposePorts[i] = fw.Expose
			targets[fw.Expose] = net.JoinHostPort(host, strconv.Itoa(fw.Backend))
		}

		shortName := src.EffectiveShortName()
		svcName := ServiceName("local", dnsName, shortName)
		syntheticDev := Device{Name: src.Addr, FQDN: dnsName}
		createdAt := time.Now()

		for _, dest := range dests {
			bridgeID := localBridgeID(rule.Name, dest.name, src.Addr, shortName)
			srcRec := NewReconciler(dest.client, exposePorts, dest.tags, m.ownerID(), m.logger)

			m.store.UpsertBridge(state.BridgeEntry{
				ID: bridgeID, RuleName: rule.Name, DestTailnet: dest.name,
				ServiceName: svcName,
				SourceHost:  src.Addr, SourceIP: src.Addr,
				Ports: slices.Clone(exposePorts), Status: state.BridgeStatusPending, CreatedAt: createdAt,
			})

			vip, err := srcRec.Ensure(ctx, "local", syntheticDev, shortName)
			if err != nil {
				m.conflict(dest.name, err)
				m.logger.Error("local rule: VIP ensure failed", "rule", rule.Name, "dest", dest.name, "addr", src.Addr, "err", err)
				m.store.UpsertBridge(state.BridgeEntry{
					ID: bridgeID, RuleName: rule.Name, DestTailnet: dest.name,
					ServiceName: svcName,
					SourceHost:  src.Addr, SourceIP: src.Addr,
					Ports: slices.Clone(exposePorts), Status: state.BridgeStatusError, Error: err.Error(), CreatedAt: createdAt,
				})
				m.store.Log("error", fmt.Sprintf("[%s] VIP failed for %s→%s: %v", rule.Name, src.Addr, dest.name, err), nil)
				continue
			}

			fwd := newLocalForwarder(dest.srv, "", vip, bridgeID, dialTimeout, m.store, m.logger)
			fwd.localTargets = targets
			fwd.rule, fwd.metrics, fwd.authz = rule.Name, m.metricsRef(), rule.Authz
			if err := startForwarder(fwd, ctx); err != nil {
				m.logger.Error("local rule: forwarder start failed", "rule", rule.Name, "dest", dest.name, "addr", src.Addr, "err", err)
				_ = srcRec.Delete(context.Background(), "local", syntheticDev, shortName)
				m.store.DeleteBridge(bridgeID)
				continue
			}

			m.store.UpsertBridge(state.BridgeEntry{
				ID: bridgeID, RuleName: rule.Name, DestTailnet: dest.name,
				ServiceName: vip.ServiceName, SourceHost: src.Addr, SourceIP: src.Addr,
				DestVIP: vip.VIP.String(), Ports: slices.Clone(exposePorts),
				Status: state.BridgeStatusActive, CreatedAt: createdAt,
			})
			m.store.Log("info", fmt.Sprintf("[%s] local bridge active: %s → %s (%s) ports %v", rule.Name, src.Addr, vip.VIP, dest.name, exposePorts), nil)

			m.mu.Lock()
			m.forwarders[bridgeID] = fwd
			m.mu.Unlock()

			if vip.VIP.IsValid() {
				m.startDeviceDNS(ctx, bridgeID, rule.Name, "", dnsName, src.DNSZone, "", "", vip.VIP, dest)
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

	// Shutdown and restarts leave the services in place; only removing the
	// rule from the config deletes them.
	remove := m.removing(rule.Name)
	var wg sync.WaitGroup
	for _, lb := range bridges {
		wg.Add(1)
		go func(lb localBridgeInfo) {
			defer wg.Done()
			m.stopBridge(lb.bridgeID, remove)
			if remove {
				if err := lb.rec.Delete(context.Background(), "local", lb.dev, lb.shortName); err != nil {
					m.logger.Warn("local rule: VIP delete failed", "bridge", lb.bridgeID, "err", err)
				}
			}
			m.store.DeleteBridge(lb.bridgeID)
		}(lb)
	}
	wg.Wait()
	m.store.Log("info", fmt.Sprintf("[%s] local rule stopped", rule.Name), nil)
}
