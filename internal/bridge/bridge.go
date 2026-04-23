package bridge

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	tsclient "tailscale.com/client/tailscale/v2"
	"tailscale.com/tsnet"
)

// Manager orchestrates all bridging. Reconcile() diffs old vs new config and
// hot-applies changes without restarting unchanged bridges.
type Manager struct {
	logger  *slog.Logger
	store   *state.Store
	webAddr string // local web UI listen address (e.g. ":8888")

	reconcileMu  sync.Mutex                    // serializes concurrent Reconcile calls
	mu           sync.Mutex
	cfg          *config.Config               // last applied config
	servers      map[string]*tsnet.Server      // keyed by tailnet name
	apiClients   map[string]*tsclient.Client
	forwarders   map[string]*Forwarder         // keyed by bridge entry ID (rule/dest/fqdn)
	dnsCleanups  map[string]func()             // keyed by bridge entry ID; tears down per-device DNS
	rules        map[string]context.CancelFunc // keyed by bridge rule name
	ruleDone     map[string]chan struct{}       // closed when the rule goroutine fully exits
	webListeners map[string]net.Listener       // keyed by tailnet name

	dnsMu      sync.Mutex                       // protects sharedDNS and dnsPending
	sharedDNS  map[string]*sharedDNSEntry       // keyed by destName+"/"+parentDomain
	dnsPending map[string]*dnsCreation          // in-progress creations, same key space
}

func New(store *state.Store, logger *slog.Logger, webAddr string) *Manager {
	return &Manager{
		logger:       logger,
		store:        store,
		webAddr:      webAddr,
		cfg:          &config.Config{Tailnets: map[string]config.TailnetConfig{}, Bridges: []config.BridgeRule{}},
		servers:      make(map[string]*tsnet.Server),
		apiClients:   make(map[string]*tsclient.Client),
		forwarders:   make(map[string]*Forwarder),
		dnsCleanups:  make(map[string]func()),
		rules:        make(map[string]context.CancelFunc),
		ruleDone:     make(map[string]chan struct{}),
		webListeners: make(map[string]net.Listener),
		sharedDNS:    make(map[string]*sharedDNSEntry),
		dnsPending:   make(map[string]*dnsCreation),
	}
}

// Reconcile diffs newCfg against the running config and applies the minimum
// set of changes. Unchanged bridges keep running.
func (m *Manager) Reconcile(ctx context.Context, newCfg *config.Config) {
	m.reconcileMu.Lock()
	defer m.reconcileMu.Unlock()

	m.mu.Lock()
	old := m.cfg
	m.mu.Unlock()

	// ── Tailnets ─────────────────────────────────────────────────────────────

	for name, oldTC := range old.Tailnets {
		newTC, still := newCfg.Tailnets[name]
		if !still || !reflect.DeepEqual(oldTC, newTC) {
			// Stop dependent rules first so they can clean up while the tailnet is
			// still reachable, then tear down the tailnet itself.
			for _, rule := range old.Bridges {
				if rule.SourceTailnet == name {
					m.stopRule(rule.Name)
					continue
				}
				for _, dt := range rule.DestTailnets {
					if dt == name {
						m.stopRule(rule.Name)
						break
					}
				}
			}
			m.stopTailnet(name)
		}
	}

	for name, tc := range newCfg.Tailnets {
		m.mu.Lock()
		_, running := m.servers[name]
		m.mu.Unlock()
		if !running {
			if err := m.startTailnet(ctx, name, tc); err != nil {
				m.logger.Error("failed to start tailnet", "name", name, "err", err)
				m.store.Log("error", fmt.Sprintf("tailnet %q failed to connect: %v", name, err), nil)
			}
		}
	}

	// ── Bridge rules ─────────────────────────────────────────────────────────

	newByName := make(map[string]config.BridgeRule, len(newCfg.Bridges))
	for _, r := range newCfg.Bridges {
		newByName[r.Name] = r
	}
	oldByName := make(map[string]config.BridgeRule, len(old.Bridges))
	for _, r := range old.Bridges {
		oldByName[r.Name] = r
	}

	for name, oldRule := range oldByName {
		newRule, still := newByName[name]
		if !still || !reflect.DeepEqual(oldRule, newRule) {
			m.stopRule(name)
		}
	}

	for name, rule := range newByName {
		m.mu.Lock()
		_, running := m.rules[name]
		m.mu.Unlock()
		if !running {
			ruleCtx, cancel := context.WithCancel(ctx)
			done := make(chan struct{})
			m.mu.Lock()
			m.rules[name] = cancel
			m.ruleDone[name] = done
			m.mu.Unlock()
			go func(r config.BridgeRule, d chan struct{}) {
				defer func() {
					close(d)
					// If the goroutine exits on its own (not via stopRule), clean up
					// the map entries so the next Reconcile can restart the rule.
					m.mu.Lock()
					if m.ruleDone[r.Name] == d {
						delete(m.rules, r.Name)
						delete(m.ruleDone, r.Name)
					}
					m.mu.Unlock()
				}()
				m.runRule(ruleCtx, r, newCfg.PollInterval.Duration, newCfg.DialTimeout.Duration)
			}(rule, done)
		}
	}

	m.mu.Lock()
	m.cfg = newCfg
	m.mu.Unlock()
}

func (m *Manager) startTailnet(ctx context.Context, name string, tc config.TailnetConfig) error {
	apiClient := newAPIClient(tc)

	authKey, err := m.fetchAuthKey(ctx, apiClient, tc.Tags)
	if err != nil {
		return fmt.Errorf("fetch auth key: %w", err)
	}

	srv := &tsnet.Server{
		Hostname:  "tailnetlink-" + name,
		AuthKey:   authKey,
		Ephemeral: true,
		Dir:       filepath.Join(os.TempDir(), "tailnetlink-"+name),
		Logf: func(format string, args ...any) {
			m.logger.Debug(fmt.Sprintf("[tsnet/%s] "+format, append([]any{name}, args...)...))
		},
	}

	m.logger.Info("connecting to tailnet", "name", name, "tailnet", tc.Tailnet)
	if _, err := srv.Up(ctx); err != nil {
		return fmt.Errorf("up: %w", err)
	}

	m.mu.Lock()
	m.servers[name] = srv
	m.apiClients[name] = apiClient
	m.mu.Unlock()

	m.store.SetTailnet(name, state.TailnetStatus{Name: tc.Tailnet, Role: name, Connected: true})
	m.store.Log("info", fmt.Sprintf("connected to tailnet %q (%s)", name, tc.Tailnet), nil)

	// Expose the web UI as svc:tailnetlink TCP:80 in this tailnet.
	if m.webAddr != "" {
		go m.serveWebUI(ctx, name, srv, apiClient, tc.Tags)
	}
	return nil
}

func (m *Manager) stopTailnet(name string) {
	m.mu.Lock()
	srv, ok := m.servers[name]
	if ok {
		delete(m.servers, name)
		delete(m.apiClients, name)
	}
	if wl, ok := m.webListeners[name]; ok {
		_ = wl.Close()
		delete(m.webListeners, name)
	}
	m.mu.Unlock()

	if ok {
		_ = srv.Close()
		m.store.DeleteTailnet(name)
		m.store.Log("info", fmt.Sprintf("disconnected from tailnet %q", name), nil)
	}
}

func (m *Manager) stopRule(name string) {
	m.mu.Lock()
	cancel, ok := m.rules[name]
	done := m.ruleDone[name]
	if ok {
		delete(m.rules, name)
		delete(m.ruleDone, name)
	}
	m.mu.Unlock()
	if !ok {
		return
	}
	cancel()
	// Wait for the goroutine to fully exit so its cleanup (DNS teardown, forwarder
	// stops) completes before the new rule starts.
	if done != nil {
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			m.logger.Warn("rule goroutine did not exit within 30s", "rule", name)
		}
	}
}

type destCtx struct {
	name   string
	srv    *tsnet.Server
	client *tsclient.Client
	tags   []string
	rec    *Reconciler
}

func (m *Manager) runRule(ctx context.Context, rule config.BridgeRule, pollInterval, dialTimeout time.Duration) {
	m.mu.Lock()
	srcSrv := m.servers[rule.SourceTailnet]
	srcClient := m.apiClients[rule.SourceTailnet]
	m.mu.Unlock()

	if srcSrv == nil {
		m.logger.Error("bridge rule: source tailnet not connected", "rule", rule.Name, "source", rule.SourceTailnet)
		m.store.Log("error", fmt.Sprintf("[%s] rule failed: source tailnet %q not connected", rule.Name, rule.SourceTailnet), nil)
		return
	}

	dests := make([]destCtx, 0, len(rule.DestTailnets))
	for _, destName := range rule.DestTailnets {
		m.mu.Lock()
		destSrv := m.servers[destName]
		destClient := m.apiClients[destName]
		destTags := m.cfg.Tailnets[destName].Tags
		m.mu.Unlock()

		if destSrv == nil {
			m.logger.Error("bridge rule: dest tailnet not connected", "rule", rule.Name, "dest", destName)
			m.store.Log("error", fmt.Sprintf("[%s] rule failed: dest tailnet %q not connected", rule.Name, destName), nil)
			return
		}

		rec := NewReconciler(destClient, rule.Ports, destTags, m.logger)
		dests = append(dests, destCtx{name: destName, srv: destSrv, client: destClient, tags: destTags, rec: rec})
	}

	deviceFQDNs := make([]string, len(rule.SourceDevices))
	for i, s := range rule.SourceDevices {
		deviceFQDNs[i] = s.FQDN
	}
	svcNames := make([]string, len(rule.SourceServices))
	for i, s := range rule.SourceServices {
		svcNames[i] = s.Name
	}
	disc := NewDiscoverer(srcClient, rule.SourceTag, deviceFQDNs, svcNames, pollInterval, m.logger)
	disc.OnWarn(func(msg string) {
		m.store.Log("warn", fmt.Sprintf("[%s] %s", rule.Name, msg), nil)
	})

	destNames := make([]string, len(dests))
	for i, d := range dests {
		destNames[i] = d.name
	}
	m.logger.Info("bridge rule started", "rule", rule.Name, "source", rule.SourceTailnet, "dests", destNames, "ports", rule.Ports)
	m.store.Log("info", fmt.Sprintf("[%s] rule started: %s→%v ports=%v", rule.Name, rule.SourceTailnet, destNames, rule.Ports), nil)

	activeDevices := make(map[string]Device)
	var mu sync.Mutex
	var devWg sync.WaitGroup

	go disc.Run(ctx)

	for {
		select {
		case <-ctx.Done():
			devWg.Wait() // drain in-flight handlers before cleanup
			mu.Lock()
			devs := make([]Device, 0, len(activeDevices))
			for _, dev := range activeDevices {
				devs = append(devs, dev)
			}
			mu.Unlock()
			for _, dev := range devs {
				for _, dest := range dests {
					bridgeID := rule.Name + "/" + dest.name + "/" + dev.FQDN
					m.mu.Lock()
					if fwd, ok := m.forwarders[bridgeID]; ok {
						fwd.Stop()
						delete(m.forwarders, bridgeID)
					}
					cleanup := m.dnsCleanups[bridgeID]
					delete(m.dnsCleanups, bridgeID)
					m.mu.Unlock()
					if cleanup != nil {
						cleanup()
					}
					_ = dest.rec.Delete(context.Background(), rule.SourceTailnet, dev, shortNameFor(rule, dev.FQDN))
					m.store.DeleteBridge(bridgeID)
				}
				m.store.Log("info", fmt.Sprintf("[%s] bridge removed: %s", rule.Name, dev.Name), nil)
			}
			return
		case dev := <-disc.Added():
			devWg.Add(1)
			go func(d Device) {
				defer devWg.Done()
				m.handleDeviceAdded(ctx, rule, d, dests, srcSrv, dialTimeout, activeDevices, &mu)
			}(dev)
		case dev := <-disc.Removed():
			devWg.Add(1)
			go func(d Device) {
				defer devWg.Done()
				m.handleDeviceRemoved(ctx, rule, d, dests, activeDevices, &mu)
			}(dev)
		}
	}
}

func (m *Manager) handleDeviceAdded(
	ctx context.Context,
	rule config.BridgeRule,
	dev Device,
	dests []destCtx,
	srcSrv *tsnet.Server,
	dialTimeout time.Duration,
	activeDevices map[string]Device,
	mu *sync.Mutex,
) {
	createdAt := time.Now()
	shortName := shortNameFor(rule, dev.FQDN)
	svcName := ServiceName(rule.SourceTailnet, dev.FQDN, shortName)
	m.store.Log("info", fmt.Sprintf("[%s] provisioning bridge for %s", rule.Name, dev.Name), nil)

	for _, dest := range dests {
		bridgeID := rule.Name + "/" + dest.name + "/" + dev.FQDN

		m.store.UpsertBridge(state.BridgeEntry{
			ID: bridgeID, RuleName: rule.Name, DestTailnet: dest.name,
			ServiceName: svcName,
			SourceHost:  dev.Name, SourceIP: dev.IP.String(),
			Ports: rule.Ports, Status: state.BridgeStatusPending, CreatedAt: createdAt,
		})

		vip, err := dest.rec.Ensure(ctx, rule.SourceTailnet, dev, shortName)
		if err != nil {
			m.logger.Error("reconciler: ensure failed", "rule", rule.Name, "dest", dest.name, "device", dev.Name, "err", err)
			m.store.UpsertBridge(state.BridgeEntry{
				ID: bridgeID, RuleName: rule.Name, DestTailnet: dest.name,
				ServiceName: svcName,
				SourceHost:  dev.Name, SourceIP: dev.IP.String(),
				Ports: rule.Ports, Status: state.BridgeStatusError, Error: err.Error(), CreatedAt: createdAt,
			})
			m.store.Log("error", fmt.Sprintf("[%s] bridge failed for %s→%s: %v", rule.Name, dev.Name, dest.name, err), nil)
			continue
		}

		fwd := NewForwarder(dest.srv, srcSrv, vip, bridgeID, dialTimeout, m.store, m.logger)
		if err := fwd.Start(ctx); err != nil {
			m.logger.Error("forwarder: start failed", "rule", rule.Name, "dest", dest.name, "device", dev.Name, "err", err)
			m.store.UpsertBridge(state.BridgeEntry{
				ID: bridgeID, RuleName: rule.Name, DestTailnet: dest.name, ServiceName: vip.ServiceName,
				SourceHost: dev.Name, SourceIP: dev.IP.String(),
				Ports: rule.Ports, Status: state.BridgeStatusError, Error: err.Error(), CreatedAt: createdAt,
			})
			_ = dest.rec.Delete(context.Background(), rule.SourceTailnet, dev, shortName)
			continue
		}

		m.store.UpsertBridge(state.BridgeEntry{
			ID: bridgeID, RuleName: rule.Name, DestTailnet: dest.name, ServiceName: vip.ServiceName,
			SourceHost: dev.Name, SourceIP: dev.IP.String(), DestVIP: vip.VIP.String(),
			Ports: rule.Ports, Status: state.BridgeStatusActive, CreatedAt: createdAt,
		})
		m.store.Log("info", fmt.Sprintf("[%s] bridge active: %s → %s (%s)", rule.Name, dev.Name, vip.VIP, dest.name), nil)

		if vip.VIP.IsValid() {
			m.mu.Lock()
			srcDomain := m.cfg.Tailnets[rule.SourceTailnet].Tailnet
			m.mu.Unlock()
			m.startDeviceDNS(ctx, bridgeID, rule.Name, srcDomain, dev.FQDN, dnsNameFor(rule, dev.FQDN), vip.VIP, dest)
		}

		m.mu.Lock()
		m.forwarders[bridgeID] = fwd
		m.mu.Unlock()
	}

	mu.Lock()
	activeDevices[dev.FQDN] = dev
	mu.Unlock()
}

func (m *Manager) handleDeviceRemoved(
	ctx context.Context,
	rule config.BridgeRule,
	dev Device,
	dests []destCtx,
	activeDevices map[string]Device,
	mu *sync.Mutex,
) {
	shortName := shortNameFor(rule, dev.FQDN)
	for _, dest := range dests {
		bridgeID := rule.Name + "/" + dest.name + "/" + dev.FQDN

		m.mu.Lock()
		if fwd, ok := m.forwarders[bridgeID]; ok {
			fwd.Stop()
			delete(m.forwarders, bridgeID)
		}
		m.mu.Unlock()

		if err := dest.rec.Delete(ctx, rule.SourceTailnet, dev, shortName); err != nil {
			m.logger.Error("reconciler: delete failed", "rule", rule.Name, "dest", dest.name, "device", dev.Name, "err", err)
			m.store.Log("error", fmt.Sprintf("[%s] bridge cleanup failed for %s→%s: %v", rule.Name, dev.Name, dest.name, err), nil)
		}

		m.mu.Lock()
		cleanup := m.dnsCleanups[bridgeID]
		delete(m.dnsCleanups, bridgeID)
		m.mu.Unlock()
		if cleanup != nil {
			cleanup()
		}

		m.store.DeleteBridge(bridgeID)
	}

	m.store.Log("info", fmt.Sprintf("[%s] bridge removed: %s", rule.Name, dev.Name), nil)

	mu.Lock()
	delete(activeDevices, dev.FQDN)
	mu.Unlock()
}

func (m *Manager) fetchAuthKey(ctx context.Context, client *tsclient.Client, tags []string) (string, error) {
	req := tsclient.CreateKeyRequest{
		ExpirySeconds: 3600,
		Description:   "tailnetlink-tsnet-node",
		Capabilities: tsclient.KeyCapabilities{
			Devices: struct {
				Create struct {
					Reusable      bool     `json:"reusable"`
					Ephemeral     bool     `json:"ephemeral"`
					Tags          []string `json:"tags"`
					Preauthorized bool     `json:"preauthorized"`
				} `json:"create"`
			}{
				Create: struct {
					Reusable      bool     `json:"reusable"`
					Ephemeral     bool     `json:"ephemeral"`
					Tags          []string `json:"tags"`
					Preauthorized bool     `json:"preauthorized"`
				}{
					Reusable: false, Ephemeral: true, Preauthorized: true, Tags: tags,
				},
			},
		},
	}

	key, err := client.Keys().CreateAuthKey(ctx, req)
	if err != nil {
		return "", fmt.Errorf("create auth key: %w", err)
	}
	m.logger.Info("auth key created", "id", key.ID, "expires", key.Expires)
	return key.Key, nil
}

func dnsNameFor(rule config.BridgeRule, fqdn string) string {
	for _, spec := range rule.SourceDevices {
		if strings.EqualFold(spec.FQDN, fqdn) {
			return spec.DNSName
		}
	}
	for _, spec := range rule.SourceServices {
		if strings.EqualFold(spec.Name, fqdn) {
			return spec.DNSName
		}
	}
	return ""
}

func shortNameFor(rule config.BridgeRule, fqdn string) string {
	for _, spec := range rule.SourceDevices {
		if strings.EqualFold(spec.FQDN, fqdn) {
			return spec.ShortName
		}
	}
	for _, spec := range rule.SourceServices {
		if strings.EqualFold(spec.Name, fqdn) {
			return spec.ShortName
		}
	}
	return ""
}

// parseHostname splits a full DNS hostname into (parentDomain, recordLabel).
// "ai.keiretsu.ts.net" → ("keiretsu.ts.net", "ai")
// "ai" (bare)          → ("ai", "@")
func parseHostname(dnsName string) (parentDomain, recordLabel string) {
	if dot := strings.IndexByte(dnsName, '.'); dot >= 0 {
		return dnsName[dot+1:], dnsName[:dot]
	}
	return dnsName, "@"
}

type sharedDNSEntry struct {
	server *DNSServer
	sdns   *SplitDNSConfigurator
	refs   int
}

// dnsCreation tracks an in-progress acquireSharedDNS call so other goroutines
// for the same key can wait rather than race.
type dnsCreation struct {
	done chan struct{}
	err  error
}

// acquireSharedDNS returns the shared DNS entry for (dest, parentDomain), creating
// it if necessary. API calls happen outside the mutex so different zones proceed
// concurrently; same-zone goroutines wait for the single in-flight creation.
// Callers must call releaseSharedDNS when the record is removed.
func (m *Manager) acquireSharedDNS(ctx context.Context, destName, parentDomain string, dest destCtx) (*sharedDNSEntry, error) {
	key := destName + "/" + parentDomain

	for {
		m.dnsMu.Lock()

		// Fast path: entry already exists.
		if entry, ok := m.sharedDNS[key]; ok {
			entry.refs++
			m.dnsMu.Unlock()
			return entry, nil
		}

		// Another goroutine is creating this key — wait for it.
		if pending, ok := m.dnsPending[key]; ok {
			m.dnsMu.Unlock()
			select {
			case <-pending.done:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			continue // retry; the entry should now be in sharedDNS
		}

		// We are the creator — claim the key.
		pending := &dnsCreation{done: make(chan struct{})}
		m.dnsPending[key] = pending
		m.dnsMu.Unlock()

		// Create DNS VIP and configure split-DNS outside the mutex.
		entry, err := func() (*sharedDNSEntry, error) {
			dnsServer := NewDNSServer(dest.srv, dest.client, "dns-"+sanitize(parentDomain), dest.tags, parentDomain, m.logger)
			resolverIP, err := dnsServer.Start(ctx)
			if err != nil {
				return nil, fmt.Errorf("shared DNS start: %w", err)
			}
			sdns := NewSplitDNSConfigurator(dest.client, parentDomain, resolverIP.String(), m.logger)
			if err := sdns.Configure(ctx); err != nil {
				dnsServer.Stop()
				dnsServer.DeleteService(context.Background())
				return nil, fmt.Errorf("split-DNS configure: %w", err)
			}
			m.logger.Info("shared DNS VIP active", "dest", destName, "zone", parentDomain, "resolver", resolverIP)
			return &sharedDNSEntry{server: dnsServer, sdns: sdns, refs: 1}, nil
		}()

		// Publish the result and wake waiters.
		m.dnsMu.Lock()
		delete(m.dnsPending, key)
		if err == nil {
			m.sharedDNS[key] = entry
		}
		pending.err = err
		m.dnsMu.Unlock()
		close(pending.done)

		return entry, err
	}
}

func (m *Manager) releaseSharedDNS(destName, parentDomain, recordLabel string) {
	key := destName + "/" + parentDomain

	m.dnsMu.Lock()
	entry, ok := m.sharedDNS[key]
	if !ok {
		m.dnsMu.Unlock()
		return
	}
	entry.server.RemoveRecord(recordLabel)
	entry.refs--
	if entry.refs > 0 {
		m.dnsMu.Unlock()
		return
	}
	delete(m.sharedDNS, key)
	m.dnsMu.Unlock()

	entry.server.Stop()
	entry.server.DeleteService(context.Background())
	if err := entry.sdns.Remove(context.Background()); err != nil {
		m.logger.Warn("split-DNS remove failed", "dest", destName, "zone", parentDomain, "err", err)
	}
}

// startDeviceDNS configures split-DNS so the device is reachable by name in the
// destination tailnet. For real device FQDNs it wires up the source hostname. For
// service-mode FQDNs (svc:name, no dot) it derives {short-name}.{srcDomain} so the
// service resolves at its canonical ts.net name from the destination tailnet.
// A custom dns_name is always attempted independently.
func (m *Manager) startDeviceDNS(ctx context.Context, bridgeID, ruleName, srcDomain, sourceFQDN, customDNS string, vipIP netip.Addr, dest destCtx) {
	var srcParent, srcLabel string
	var srcAcquired bool

	// Determine the effective always-on FQDN.
	// For real device FQDNs (e.g. aperture.keiretsu.ts.net) use as-is.
	// For service names (e.g. svc:ai), derive ai.keiretsu.ts.net so it resolves
	// from dest tailnets the same way it does within the source tailnet.
	effectiveFQDN := sourceFQDN
	if !strings.Contains(sourceFQDN, ".") && srcDomain != "" {
		shortName := strings.TrimPrefix(sourceFQDN, "svc:")
		effectiveFQDN = shortName + "." + srcDomain
	}

	if strings.Contains(effectiveFQDN, ".") {
		srcParent, srcLabel = parseHostname(effectiveFQDN)
		if entry, err := m.acquireSharedDNS(ctx, dest.name, srcParent, dest); err != nil {
			m.logger.Warn("shared DNS acquire failed", "rule", ruleName, "dest", dest.name, "hostname", effectiveFQDN, "err", err)
		} else {
			entry.server.AddRecord(srcLabel, vipIP)
			m.logger.Info("DNS record added", "rule", ruleName, "hostname", effectiveFQDN, "dest", dest.name)
			srcAcquired = true
		}
	}

	// Custom hostname: always attempted independently, regardless of above.
	var customParent, customLabel string
	var customAcquired bool
	if customDNS != "" && customDNS != sourceFQDN {
		customParent, customLabel = parseHostname(customDNS)
		if entry, err := m.acquireSharedDNS(ctx, dest.name, customParent, dest); err != nil {
			m.logger.Warn("custom DNS acquire failed", "rule", ruleName, "dest", dest.name, "hostname", customDNS, "err", err)
		} else {
			entry.server.AddRecord(customLabel, vipIP)
			m.logger.Info("custom DNS record added", "rule", ruleName, "hostname", customDNS, "dest", dest.name)
			customAcquired = true
		}
	}

	if !srcAcquired && !customAcquired {
		return
	}

	m.mu.Lock()
	m.dnsCleanups[bridgeID] = func() {
		if srcAcquired {
			m.releaseSharedDNS(dest.name, srcParent, srcLabel)
		}
		if customAcquired {
			m.releaseSharedDNS(dest.name, customParent, customLabel)
		}
	}
	m.mu.Unlock()
}

// serveWebUI registers svc:tailnetlink as a TCP:80 VIP service in the given
// tailnet and proxies incoming connections to the local web UI server.
func (m *Manager) serveWebUI(ctx context.Context, tailnetName string, srv *tsnet.Server, client *tsclient.Client, tags []string) {
	const svcName = "svc:tailnetlink"

	if _, err := ensureVIPService(ctx, client, tsclient.VIPService{
		Name:    svcName,
		Ports:   []string{"tcp:80"},
		Tags:    tags,
		Comment: "managed by tailnetlink (web UI)",
		Annotations: map[string]string{
			"tailnetlink/managed": "true",
		},
	}); err != nil {
		m.logger.Warn("web UI VIP: create failed", "tailnet", tailnetName, "err", err)
		m.store.Log("warn", fmt.Sprintf("[%s] web UI VIP setup failed: %v", tailnetName, err), nil)
		return
	}

	ln, err := listenServiceWithRetry(srv, svcName, tsnet.ServiceModeTCP{Port: 80})
	if err != nil {
		m.logger.Warn("web UI VIP: listen failed", "tailnet", tailnetName, "err", err)
		m.store.Log("warn", fmt.Sprintf("[%s] web UI VIP listen failed: %v", tailnetName, err), nil)
		return
	}

	m.mu.Lock()
	m.webListeners[tailnetName] = ln
	m.mu.Unlock()

	_, port, _ := net.SplitHostPort(m.webAddr)
	if port == "" {
		port = "8888"
	}
	localAddr := "127.0.0.1:" + port

	m.logger.Info("web UI VIP service active", "tailnet", tailnetName, "service", svcName, "local", localAddr)
	m.store.Log("info", fmt.Sprintf("[%s] web UI: %s → %s", tailnetName, svcName, localAddr), nil)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
			default:
				m.logger.Warn("web UI VIP: accept error", "tailnet", tailnetName, "err", err)
			}
			return
		}
		go proxyToLocal(conn, localAddr)
	}
}

func proxyToLocal(client net.Conn, localAddr string) {
	defer client.Close()
	upstream, err := net.Dial("tcp", localAddr)
	if err != nil {
		return
	}
	defer upstream.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(upstream, client) //nolint:errcheck
		if hc, ok := upstream.(halfCloser); ok {
			hc.CloseWrite() //nolint:errcheck
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(client, upstream) //nolint:errcheck
		if hc, ok := client.(halfCloser); ok {
			hc.CloseWrite() //nolint:errcheck
		}
	}()
	wg.Wait()
}
