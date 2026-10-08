package bridge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/metrics"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	"github.com/rajsinghtech/tailnetlink/internal/tsapi"
	tsclient "tailscale.com/client/tailscale/v2"
	"tailscale.com/tsnet"
)

// Manager orchestrates all bridging. Reconcile() diffs old vs new config and
// hot-applies changes without restarting unchanged bridges.
type Manager struct {
	logger *slog.Logger
	store  *state.Store
	ui     http.Handler // the read-only web UI; nil means never publish it

	reconcileMu sync.Mutex // serializes concurrent Reconcile calls
	mu          sync.Mutex
	closed      bool           // set by Close; Reconcile does nothing after
	cfg         *config.Config // last applied config
	owner       string         // instance id, written to tailnetlink/owner
	uiService   string         // VIP service name for the web UI
	uiOn        bool           // the UI is published (ui set and ui.enabled not false)

	defaultStateDir string            // used when the config has no state_dir
	nodeDirs        map[string]string // tailnet name -> node state dir
	ephemeral       map[string]bool   // tailnet name -> node is ephemeral

	servers     map[string]*tsnet.Server // keyed by tailnet name
	apiClients  map[string]*tsclient.Client
	forwarders  map[string]*Forwarder         // keyed by bridge entry ID (rule/dest/fqdn)
	dnsCleanups map[string]func(remove bool)  // keyed by bridge entry ID; tears down per-device DNS
	rules       map[string]context.CancelFunc // keyed by bridge rule name
	ruleDone    map[string]chan struct{}      // closed when the rule goroutine fully exits
	ruleRemove  map[string]bool               // set by stopRule: true means delete what the rule owns
	webServers  map[string]*http.Server       // UI server on the VIP, keyed by tailnet name

	dnsOff        bool          // split-DNS is off for this border
	dropDNS       bool          // stopping rules should also delete their DNS (dns turned off)
	authKeyExpiry time.Duration // lifetime of auth keys for new nodes

	metrics  *metrics.Metrics     // nil means no metrics
	lastPoll map[string]time.Time // rule name -> last successful discovery poll
	applied  bool                 // a Reconcile has finished at least once

	// vipDesired / vipAdvertised feed tailnetlink_vip_services. A name is
	// desired once ListenService starts for it and advertised once it is
	// verified in the node's AdvertiseServices list.
	vipMu         sync.Mutex
	vipDesired    map[string]map[string]struct{}
	vipAdvertised map[string]map[string]struct{}

	dnsMu      sync.Mutex                 // protects sharedDNS and dnsPending
	sharedDNS  map[string]*sharedDNSEntry // keyed by destName+"/"+parentDomain
	dnsPending map[string]*dnsCreation    // in-progress creations, same key space
}

// startForwarder starts a forwarder. It is a variable only so tests can stub
// it out, since the real Start needs a running tsnet node.
var startForwarder = (*Forwarder).Start

// closeServer closes a tsnet node. A variable so tests can use nodes that
// were never started.
var closeServer = (*tsnet.Server).Close

// New returns a manager. ui is the read-only web UI handler to publish as a
// VIP service in every tailnet; nil means the UI is off.
func New(store *state.Store, logger *slog.Logger, ui http.Handler) *Manager {
	return &Manager{
		logger:        logger,
		store:         store,
		ui:            ui,
		cfg:           &config.Config{Tailnets: map[string]config.TailnetConfig{}, Bridges: []config.BridgeRule{}},
		servers:       make(map[string]*tsnet.Server),
		apiClients:    make(map[string]*tsclient.Client),
		forwarders:    make(map[string]*Forwarder),
		dnsCleanups:   make(map[string]func(bool)),
		rules:         make(map[string]context.CancelFunc),
		ruleDone:      make(map[string]chan struct{}),
		ruleRemove:    make(map[string]bool),
		webServers:    make(map[string]*http.Server),
		nodeDirs:      make(map[string]string),
		ephemeral:     make(map[string]bool),
		sharedDNS:     make(map[string]*sharedDNSEntry),
		dnsPending:    make(map[string]*dnsCreation),
		lastPoll:      make(map[string]time.Time),
		vipDesired:    map[string]map[string]struct{}{},
		vipAdvertised: map[string]map[string]struct{}{},
	}
}

// SetMetrics makes the manager record into mt. Call it before the first
// Reconcile.
func (m *Manager) SetMetrics(mt *metrics.Metrics) {
	m.mu.Lock()
	m.metrics = mt
	m.mu.Unlock()
	mt.TrackBridges([]string{state.BridgeStatusPending, state.BridgeStatusActive, state.BridgeStatusError}, func() map[string]int {
		counts := make(map[string]int)
		for _, b := range m.store.GetBridges() {
			counts[b.Status]++
		}
		return counts
	})
	mt.TrackVIPServices(m.vipCounts)
}

// Ready returns nil once the config has been applied, every configured
// tailnet's node is up and every tailnet rule has polled recently (within
// three poll intervals). Otherwise it says what is missing.
func (m *Manager) Ready() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.applied {
		return errors.New("config not applied yet")
	}
	for _, name := range slices.Sorted(maps.Keys(m.cfg.Tailnets)) {
		if m.servers[name] == nil {
			return fmt.Errorf("tailnet %q is not connected", name)
		}
	}
	poll := m.cfg.PollInterval.Duration
	if poll <= 0 {
		poll = 30 * time.Second
	}
	for _, r := range m.cfg.Bridges {
		if len(r.LocalSources) > 0 {
			continue
		}
		last, ok := m.lastPoll[r.Name]
		if !ok {
			return fmt.Errorf("rule %q has not polled yet", r.Name)
		}
		if age := time.Since(last); age > 3*poll {
			return fmt.Errorf("rule %q last polled %s ago", r.Name, age.Round(time.Second))
		}
	}
	return nil
}

func (m *Manager) pollDone(rule string, d time.Duration, err error) {
	m.mu.Lock()
	mt := m.metrics
	if err == nil {
		m.lastPoll[rule] = time.Now()
	}
	m.mu.Unlock()
	mt.PollDone(rule, d, err)
}

// conflict records an ownership conflict in tailnet if err is one.
func (m *Manager) conflict(tailnet string, err error) {
	if errors.Is(err, ErrNameConflict) {
		m.mu.Lock()
		mt := m.metrics
		m.mu.Unlock()
		mt.Conflict(tailnet)
	}
}

func (m *Manager) metricsRef() *metrics.Metrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.metrics
}

func (m *Manager) newAPIClient(tc config.TailnetConfig) *tsclient.Client {
	mt := m.metricsRef()
	var obs tsapi.APIObserver
	if mt != nil {
		obs = mt
	}
	return tsapi.NewClient(tc, tsapi.LimitedTransport(nil, tsapi.DefaultAPIRatePerSec, tsapi.DefaultAPIBurst, obs))
}

// Reconcile diffs newCfg against the running config and applies the minimum
// set of changes. Unchanged bridges keep running.
func (m *Manager) Reconcile(ctx context.Context, newCfg *config.Config) {
	m.reconcileMu.Lock()
	defer m.reconcileMu.Unlock()

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	old := m.cfg
	// A new instance id or UI service name changes what every running piece
	// owns or publishes, so everything restarts.
	restartAll := m.owner != newCfg.InstanceID || m.uiService != newCfg.UIServiceName()
	uiOn := m.ui != nil && newCfg.UIEnabled()
	uiToggled := !restartAll && uiOn != m.uiOn
	m.uiOn = uiOn
	dnsToggled := !restartAll && m.applied && newCfg.DNSDisabled != m.dnsOff
	m.dnsOff = newCfg.DNSDisabled
	m.authKeyExpiry = newCfg.AuthKeyExpiry.Duration
	running := make(map[string]bool, len(m.servers))
	for name := range m.servers {
		running[name] = true
	}
	m.mu.Unlock()

	// ui.enabled changed: publish the UI in, or withdraw it from, every
	// running tailnet. Tailnets that start or restart below follow uiOn.
	if uiToggled {
		for name := range running {
			if uiOn {
				m.startWebUI(ctx, name, old.Tailnets[name].Tags)
			} else {
				m.stopWebUI(name, true)
			}
		}
	}

	// dns.enabled changed: restart every rule so DNS records come or go.
	// Turning it off also deletes the DNS VIP and split-DNS entries the
	// rules made; the bridged services stay.
	if dnsToggled {
		m.mu.Lock()
		m.dropDNS = newCfg.DNSDisabled
		m.mu.Unlock()
		for _, rule := range old.Bridges {
			m.stopRule(rule.Name, false)
		}
		m.mu.Lock()
		m.dropDNS = false
		m.mu.Unlock()
	}

	if restartAll {
		for _, rule := range old.Bridges {
			m.stopRule(rule.Name, false)
		}
		for name := range old.Tailnets {
			m.stopTailnet(name, false)
		}
		m.mu.Lock()
		m.owner = newCfg.InstanceID
		m.uiService = newCfg.UIServiceName()
		m.mu.Unlock()
	}

	// ── Tailnets ─────────────────────────────────────────────────────────────

	// A tailnet whose config changed is restarted: its rules stop and come
	// back, and nothing is deleted. A tailnet that left the config is removed:
	// its rules delete what they own first, while the tailnet is still
	// reachable.
	for name, oldTC := range old.Tailnets {
		newTC, still := newCfg.Tailnets[name]
		if !still || !reflect.DeepEqual(oldTC, newTC) {
			for _, rule := range old.Bridges {
				if rule.SourceTailnet == name || slices.Contains(rule.DestTailnets, name) {
					m.stopRule(rule.Name, !still)
				}
			}
			m.stopTailnet(name, !still)
		}
	}

	for name, tc := range newCfg.Tailnets {
		m.mu.Lock()
		_, running := m.servers[name]
		m.mu.Unlock()
		if !running {
			if err := m.startTailnet(ctx, name, tc, newCfg.StateDir); err != nil {
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

	// A changed rule restarts without deleting anything; a removed rule
	// deletes the services it owns.
	for name, oldRule := range oldByName {
		newRule, still := newByName[name]
		if !still || !reflect.DeepEqual(oldRule, newRule) {
			m.stopRule(name, !still)
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
	m.applied = true
	m.mu.Unlock()
}

// Close stops every rule, closes every listener and tsnet node, and makes
// later Reconcile calls do nothing. It waits for that to finish or for ctx
// to be done, whichever comes first, and returns ctx's error in the second
// case. The work carries on in the background after a timeout; the caller
// is expected to exit.
func (m *Manager) Close(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Wait for an in-flight Reconcile so nothing starts after this.
		m.reconcileMu.Lock()
		defer m.reconcileMu.Unlock()

		m.mu.Lock()
		m.closed = true
		rules := make([]string, 0, len(m.rules))
		for name := range m.rules {
			rules = append(rules, name)
		}
		tailnets := make([]string, 0, len(m.servers))
		for name := range m.servers {
			tailnets = append(tailnets, name)
		}
		m.mu.Unlock()

		var wg sync.WaitGroup
		for _, name := range rules {
			wg.Add(1)
			go func() {
				defer wg.Done()
				m.stopRule(name, false)
			}()
		}
		wg.Wait()

		m.dnsMu.Lock()
		for key, entry := range m.sharedDNS {
			entry.server.Stop()
			delete(m.sharedDNS, key)
		}
		m.dnsMu.Unlock()

		for _, name := range tailnets {
			wg.Add(1)
			go func() {
				defer wg.Done()
				m.stopTailnet(name, false)
			}()
		}
		wg.Wait()
		m.logger.Info("bridge manager closed")
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("close: %w", ctx.Err())
	}
}

// SetDefaultStateDir sets where node state goes when the config has no
// state_dir. main points it next to the config file.
func (m *Manager) SetDefaultStateDir(dir string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.defaultStateDir = dir
}

// reuseTimeout bounds how long a node with saved state gets to come up
// before it is treated as logged out and re-registered with a new key.
var reuseTimeout = time.Minute

// nodeDir returns the state directory for a tailnet's node, creating it.
// Persistent nodes live under state_dir and keep their identity across
// restarts. Ephemeral nodes get a fresh directory under the same state_dir
// on every start, so a read-only root filesystem only needs that mount.
func (m *Manager) nodeDir(name string, tc config.TailnetConfig, stateDir string) (string, error) {
	if stateDir == "" {
		m.mu.Lock()
		stateDir = m.defaultStateDir
		m.mu.Unlock()
	}
	if stateDir == "" {
		stateDir = "tailnetlink-state"
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", fmt.Errorf("state dir: %w", err)
	}
	if tc.Ephemeral {
		dir, err := os.MkdirTemp(stateDir, sanitize(name)+"-")
		if err != nil {
			return "", fmt.Errorf("state dir: %w", err)
		}
		return dir, nil
	}
	dir := filepath.Join(stateDir, sanitize(name))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("state dir: %w", err)
	}
	return dir, nil
}

// hasNodeState reports whether dir holds a node that already registered.
func hasNodeState(dir string) bool {
	fi, err := os.Stat(filepath.Join(dir, "tailscaled.state"))
	return err == nil && fi.Size() > 0
}

func (m *Manager) startTailnet(ctx context.Context, name string, tc config.TailnetConfig, stateDir string) error {
	apiClient := m.newAPIClient(tc)
	dir, err := m.nodeDir(name, tc, stateDir)
	if err != nil {
		return err
	}

	newServer := func(authKey string) *tsnet.Server {
		return &tsnet.Server{
			Hostname:   "tailnetlink-" + name,
			AuthKey:    authKey,
			Ephemeral:  tc.Ephemeral,
			Dir:        dir,
			ControlURL: tc.ControlURL,
			Logf: func(format string, args ...any) {
				m.logger.Debug(fmt.Sprintf("[tsnet/%s] "+format, append([]any{name}, args...)...))
			},
		}
	}

	m.logger.Info("connecting to tailnet", "name", name, "tailnet", tc.Tailnet, "ephemeral", tc.Ephemeral, "dir", dir)
	var srv *tsnet.Server
	if !tc.Ephemeral && hasNodeState(dir) {
		// Reuse the saved identity; no auth key needed.
		srv = newServer("")
		uctx, cancel := context.WithTimeout(ctx, reuseTimeout)
		_, err := srv.Up(uctx)
		cancel()
		if err != nil {
			m.logger.Warn("saved node did not come up; registering a new one", "name", name, "err", err)
			_ = closeServer(srv)
			srv = nil
			if err := os.RemoveAll(dir); err != nil {
				return fmt.Errorf("reset state dir: %w", err)
			}
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return fmt.Errorf("state dir: %w", err)
			}
		}
	}
	if srv == nil {
		authKey, err := m.fetchAuthKey(ctx, apiClient, tc.Tags, tc.Ephemeral)
		if err != nil {
			return fmt.Errorf("fetch auth key: %w", err)
		}
		srv = newServer(authKey)
		if _, err := srv.Up(ctx); err != nil {
			_ = closeServer(srv)
			return fmt.Errorf("up: %w", err)
		}
	}

	m.mu.Lock()
	m.servers[name] = srv
	m.apiClients[name] = apiClient
	m.nodeDirs[name] = dir
	m.ephemeral[name] = tc.Ephemeral
	m.mu.Unlock()
	m.bindNode(name, srv)

	m.store.SetTailnet(name, state.TailnetStatus{Name: tc.Tailnet, Role: name, Connected: true})
	m.store.Log("info", fmt.Sprintf("connected to tailnet %q (%s)", name, tc.Tailnet), nil)

	// Publish the web UI as svc:tailnetlink TCP:80 in this tailnet.
	m.mu.Lock()
	uiOn := m.uiOn
	m.mu.Unlock()
	if uiOn {
		go m.serveWebUI(ctx, name, srv, apiClient, tc.Tags)
	}
	return nil
}

// startWebUI publishes the UI in a running tailnet.
func (m *Manager) startWebUI(ctx context.Context, name string, tags []string) {
	m.mu.Lock()
	srv, client := m.servers[name], m.apiClients[name]
	m.mu.Unlock()
	if srv != nil {
		go m.serveWebUI(ctx, name, srv, client, tags)
	}
}

// stopWebUI stops serving the UI in a tailnet, closing open connections.
// With remove set it also deletes the UI service if we own it.
func (m *Manager) stopWebUI(name string, remove bool) {
	m.mu.Lock()
	ws, ok := m.webServers[name]
	delete(m.webServers, name)
	client := m.apiClients[name]
	uiService, owner := m.uiService, m.owner
	m.mu.Unlock()
	if ok {
		_ = ws.Close()
	}
	m.forgetVIP(name, uiService)
	if remove && client != nil {
		if err := deleteOwnedVIPService(context.Background(), client, owner, uiService); err != nil {
			m.logger.Warn("web UI VIP: delete failed", "tailnet", name, "err", err)
		} else {
			m.store.Log("info", fmt.Sprintf("[%s] web UI withdrawn", name), nil)
		}
	}
}

// stopTailnet closes a tailnet's node and UI listener. With remove set (the
// tailnet left the config) it first deletes the UI service if we own it.
// The node's saved state is kept either way, except for ephemeral nodes.
func (m *Manager) stopTailnet(name string, remove bool) {
	m.mu.Lock()
	srv, ok := m.servers[name]
	client := m.apiClients[name]
	dir, ephemeral := m.nodeDirs[name], m.ephemeral[name]
	uiService, owner := m.uiService, m.owner
	if ok {
		delete(m.servers, name)
		delete(m.apiClients, name)
		delete(m.nodeDirs, name)
		delete(m.ephemeral, name)
	}
	ws, hasUI := m.webServers[name]
	delete(m.webServers, name)
	m.mu.Unlock()
	if hasUI {
		_ = ws.Close()
	}

	if !ok {
		return
	}
	m.unbindNode(name, srv)
	if remove {
		if err := deleteOwnedVIPService(context.Background(), client, owner, uiService); err != nil {
			m.logger.Warn("web UI VIP: delete failed", "tailnet", name, "err", err)
		}
	}
	_ = closeServer(srv)
	if ephemeral && dir != "" {
		_ = os.RemoveAll(dir)
	}
	m.store.DeleteTailnet(name)
	m.store.Log("info", fmt.Sprintf("disconnected from tailnet %q", name), nil)
}

// stopRule stops a running rule and waits for it to exit. With remove set
// the rule deletes the services and DNS it owns on the way out; otherwise it
// only stops listening and leaves everything in the tailnets as it is.
func (m *Manager) stopRule(name string, remove bool) {
	m.mu.Lock()
	cancel, ok := m.rules[name]
	done := m.ruleDone[name]
	if ok {
		delete(m.rules, name)
		delete(m.ruleDone, name)
		delete(m.lastPoll, name)
		m.ruleRemove[name] = remove
	}
	m.mu.Unlock()
	if !ok {
		return
	}
	defer func() {
		m.mu.Lock()
		delete(m.ruleRemove, name)
		m.mu.Unlock()
	}()
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

// removing reports whether the rule is being stopped for good, as opposed
// to a restart or shutdown.
func (m *Manager) removing(rule string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ruleRemove[rule]
}

// stopBridge stops one bridge's forwarder and DNS records. With remove set
// the DNS cleanup may delete the shared DNS VIP; the bridge's own VIP
// service is the caller's to delete.
func (m *Manager) stopBridge(bridgeID string, remove bool) {
	m.mu.Lock()
	if fwd, ok := m.forwarders[bridgeID]; ok {
		fwd.Stop()
		delete(m.forwarders, bridgeID)
	}
	cleanup := m.dnsCleanups[bridgeID]
	delete(m.dnsCleanups, bridgeID)
	dropDNS := m.dropDNS
	m.mu.Unlock()
	if cleanup != nil {
		cleanup(remove || dropDNS)
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
	if len(rule.LocalSources) > 0 {
		m.runLocalRule(ctx, rule, dialTimeout)
		return
	}

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

		rec := NewReconciler(destClient, rule.Ports, destTags, m.ownerID(), m.logger)
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
	disc.onPoll = func(d time.Duration, err error) { m.pollDone(rule.Name, d, err) }

	destNames := make([]string, len(dests))
	for i, d := range dests {
		destNames[i] = d.name
	}
	m.logger.Info("bridge rule started", "rule", rule.Name, "source", rule.SourceTailnet, "dests", destNames, "ports", rule.Ports)
	m.store.Log("info", fmt.Sprintf("[%s] rule started: %s→%v ports=%v", rule.Name, rule.SourceTailnet, destNames, rule.Ports), nil)

	destByName := make(map[string]destCtx, len(dests))
	for _, dest := range dests {
		destByName[dest.name] = dest
	}
	q := newReconcileQueue(reconcileWorkers, func(ctx context.Context, item qItem) error {
		dest, ok := destByName[item.dest]
		if !ok {
			return fmt.Errorf("unknown dest %q", item.dest)
		}
		return m.converge(ctx, rule, dest, srcSrv, dialTimeout, item)
	})
	disc.onSnapshot = func(found map[string]Device) {
		if ctx.Err() != nil {
			return
		}
		q.Replace(specsFor(rule, dests, found))
	}
	q.start(ctx)

	var discWG sync.WaitGroup
	discWG.Add(1)
	go func() {
		defer discWG.Done()
		disc.Run(ctx)
	}()

	<-ctx.Done()
	discWG.Wait()
	q.wg.Wait()

	remove := m.removing(rule.Name)
	for _, b := range m.store.GetBridges() {
		if b.RuleName != rule.Name {
			continue
		}
		m.forgetVIP(b.DestTailnet, b.ServiceName)
		m.stopBridge(b.ID, remove)
		if remove {
			destName, fqdn, ok := splitBridgeID(rule.Name, b.ID)
			if dest, known := destByName[destName]; ok && known {
				dev := Device{Name: b.SourceHost, FQDN: fqdn}
				if err := dest.rec.Delete(context.Background(), rule.SourceTailnet, dev, shortNameFor(rule, fqdn)); err != nil {
					m.logger.Warn("reconciler: delete failed", "rule", rule.Name, "dest", destName, "device", dev.Name, "err", err)
				}
			}
		}
		m.store.DeleteBridge(b.ID)
	}
	if !remove {
		m.store.Log("info", fmt.Sprintf("[%s] rule stopped; services left in place", rule.Name), nil)
	}
}

// splitBridgeID parses rule/dest/fqdn. The fqdn is the remainder, so it may
// contain slashes only if a name did; configured names do not.
func splitBridgeID(ruleName, id string) (dest, fqdn string, ok bool) {
	rest, found := strings.CutPrefix(id, ruleName+"/")
	if !found {
		return "", "", false
	}
	dest, fqdn, ok = strings.Cut(rest, "/")
	return dest, fqdn, ok && dest != "" && fqdn != ""
}

func (m *Manager) fetchAuthKey(ctx context.Context, client *tsclient.Client, tags []string, ephemeral bool) (string, error) {
	m.mu.Lock()
	expiry := m.authKeyExpiry
	m.mu.Unlock()
	if expiry <= 0 {
		expiry = time.Hour
	}
	req := tsclient.CreateKeyRequest{
		ExpirySeconds: int64(expiry.Seconds()),
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
					Reusable: false, Ephemeral: ephemeral, Preauthorized: true, Tags: tags,
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
			dnsServer := NewDNSServer(dest.srv, dest.client, dest.tags, m.ownerID(), parentDomain, m.logger)
			resolverIP, err := dnsServer.Start(ctx)
			if err != nil {
				m.forgetVIP(destName, DNSServiceName(parentDomain))
				m.conflict(destName, err)
				return nil, fmt.Errorf("shared DNS start: %w", err)
			}
			sdns := NewSplitDNSConfigurator(dest.client, parentDomain, resolverIP.String(), m.logger)
			if err := sdns.Configure(ctx); err != nil {
				dnsServer.Stop()
				m.forgetVIP(destName, DNSServiceName(parentDomain))
				_ = dnsServer.DeleteService(context.Background())
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

// releaseSharedDNS drops one record and one reference from a shared zone.
// When the last reference goes the DNS listener stops, and with remove set
// the DNS VIP and its split-DNS entry are deleted as well.
func (m *Manager) releaseSharedDNS(destName, parentDomain, recordLabel string, remove bool) {
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
	m.forgetVIP(destName, DNSServiceName(parentDomain))
	if !remove {
		return
	}
	if err := entry.server.DeleteService(context.Background()); errors.Is(err, ErrNameConflict) {
		// Someone else owns the DNS VIP now, so its address is not ours to
		// take out of split-DNS either.
		m.logger.Warn("DNS VIP is no longer ours; leaving split-DNS alone", "dest", destName, "zone", parentDomain, "err", err)
		return
	}
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
	m.mu.Lock()
	off := m.dnsOff
	m.mu.Unlock()
	if off {
		return
	}
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
	m.dnsCleanups[bridgeID] = func(remove bool) {
		if srcAcquired {
			m.releaseSharedDNS(dest.name, srcParent, srcLabel, remove)
		}
		if customAcquired {
			m.releaseSharedDNS(dest.name, customParent, customLabel, remove)
		}
	}
	m.mu.Unlock()
}

// ownerID returns the instance id the running config set.
func (m *Manager) ownerID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.owner
}

// serveWebUI registers the web UI VIP service (svc:tailnetlink unless the
// config names another) as TCP:80 in the given tailnet and serves the
// read-only UI handler on it directly. The service goes through the same
// ownership guard as every other: if a service with that name exists and is
// not ours, the UI is not published in this tailnet.
func (m *Manager) serveWebUI(ctx context.Context, tailnetName string, srv *tsnet.Server, client *tsclient.Client, tags []string) {
	m.mu.Lock()
	svcName, owner, handler := m.uiService, m.owner, m.ui
	m.mu.Unlock()

	if _, err := ensureVIPService(ctx, client, owner, tsclient.VIPService{
		Name:    svcName,
		Ports:   []string{"tcp:80"},
		Tags:    tags,
		Comment: "managed by tailnetlink (web UI)",
	}); err != nil {
		if errors.Is(err, ErrNameConflict) {
			m.conflict(tailnetName, err)
			m.logger.Error("web UI not published", "tailnet", tailnetName, "err", err)
			m.store.Log("error", fmt.Sprintf("[%s] web UI not published: %v", tailnetName, err), nil)
			return
		}
		m.logger.Warn("web UI VIP: create failed", "tailnet", tailnetName, "err", err)
		m.store.Log("warn", fmt.Sprintf("[%s] web UI VIP setup failed: %v", tailnetName, err), nil)
		return
	}

	ln, err := listenServiceWithRetry(srv, svcName, tsnet.ServiceModeTCP{Port: 80})
	if err != nil {
		m.forgetVIP(tailnetName, svcName)
		m.logger.Warn("web UI VIP: listen failed", "tailnet", tailnetName, "err", err)
		m.store.Log("warn", fmt.Sprintf("[%s] web UI VIP listen failed: %v", tailnetName, err), nil)
		return
	}

	hs := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	m.mu.Lock()
	// The UI may have been turned off, or the tailnet stopped, while the
	// service was being set up.
	if !m.uiOn || m.servers[tailnetName] != srv {
		m.mu.Unlock()
		_ = ln.Close()
		return
	}
	if old, ok := m.webServers[tailnetName]; ok {
		_ = old.Close()
	}
	m.webServers[tailnetName] = hs
	m.mu.Unlock()

	m.logger.Info("web UI VIP service active", "tailnet", tailnetName, "service", svcName)
	m.store.Log("info", fmt.Sprintf("[%s] web UI published as %s", tailnetName, svcName), nil)

	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		select {
		case <-ctx.Done():
		default:
			m.logger.Warn("web UI VIP: serve error", "tailnet", tailnetName, "err", err)
		}
	}
}
