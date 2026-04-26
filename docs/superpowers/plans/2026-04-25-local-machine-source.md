# Local Machine Source Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `local_sources` source type to bridge rules so tailnetlink can proxy services running on the host machine (localhost or LAN-reachable hosts) into destination tailnets as VIP services.

**Architecture:** Each `LocalSourceSpec` in a bridge rule is a self-contained endpoint — `addr` (host:port to dial), `expose_port` (VIP port, defaults to addr's port), `dns_name` (FQDN to register in dest tailnet), and `short_name`. Local rules skip the Discoverer entirely (static, no polling). The `Forwarder` gains a `localAddr string` field; when set, `handle()` uses `net.DialContext` instead of the source tsnet's `Dial`. Split-DNS and VIP service creation reuse the existing `Reconciler` and `startDeviceDNS` machinery unchanged.

**Tech Stack:** Go 1.26.1, `net` stdlib, existing `tsnet`/Tailscale API client, vanilla JS + HTML (single-file web UI)

---

## File Map

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `internal/config/config.go` | Add `LocalSourceSpec` struct + `LocalSources` field on `BridgeRule` |
| Create | `internal/config/config_test.go` | JSON roundtrip tests for `LocalSourceSpec` |
| Create | `internal/bridge/local.go` | Pure helpers (Task 2) + `newLocalForwarder` + `runLocalRule` (Task 4) |
| Create | `internal/bridge/local_test.go` | Unit tests for local.go helpers |
| Modify | `internal/bridge/forwarder.go` | Add `localAddr string` to `Forwarder`; branch in `handle()` |
| Modify | `internal/bridge/bridge.go` | Detect local rule in `runRule`, dispatch to `runLocalRule` |
| Modify | `internal/server/server.go` | Validation for local rules; extend `checkShortNameConflicts` |
| Modify | `internal/server/web/index.html` | Source type toggle, local endpoints builder, render updates |

---

## Task 1: Add `LocalSourceSpec` to config

**Files:**
- Modify: `internal/config/config.go`
- Create: `internal/config/config_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/config/config_test.go`:

```go
package config_test

import (
	"encoding/json"
	"testing"

	"github.com/rajsinghtech/tailnetlink/internal/config"
)

func TestLocalSourceSpecRoundtrip(t *testing.T) {
	rule := config.BridgeRule{
		Name:         "test",
		DestTailnets: []string{"dest"},
		LocalSources: []config.LocalSourceSpec{
			{Addr: "localhost:11434", ExposePort: 80, DNSName: "ollama.dest.ts.net"},
			{Addr: "ai.lan.ts.net:8080"},
			{Addr: "localhost:3000", DNSName: "app.dest.ts.net", ShortName: "app"},
		},
	}

	data, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got config.BridgeRule
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.LocalSources) != 3 {
		t.Fatalf("expected 3 local_sources, got %d", len(got.LocalSources))
	}
	if got.LocalSources[0].Addr != "localhost:11434" {
		t.Errorf("Addr[0] = %q, want %q", got.LocalSources[0].Addr, "localhost:11434")
	}
	if got.LocalSources[0].ExposePort != 80 {
		t.Errorf("ExposePort[0] = %d, want 80", got.LocalSources[0].ExposePort)
	}
	if got.LocalSources[0].DNSName != "ollama.dest.ts.net" {
		t.Errorf("DNSName[0] = %q, want %q", got.LocalSources[0].DNSName, "ollama.dest.ts.net")
	}
	if got.LocalSources[1].Addr != "ai.lan.ts.net:8080" {
		t.Errorf("Addr[1] = %q, want %q", got.LocalSources[1].Addr, "ai.lan.ts.net:8080")
	}
	if got.LocalSources[2].ShortName != "app" {
		t.Errorf("ShortName[2] = %q, want %q", got.LocalSources[2].ShortName, "app")
	}
}

func TestBridgeRuleOmitsLocalSourcesWhenEmpty(t *testing.T) {
	rule := config.BridgeRule{
		Name:          "test",
		SourceTailnet: "src",
		DestTailnets:  []string{"dest"},
		Ports:         []int{8080},
	}
	data, _ := json.Marshal(rule)
	var m map[string]any
	json.Unmarshal(data, &m)
	if _, ok := m["local_sources"]; ok {
		t.Error("local_sources should be omitted when empty")
	}
}
```

- [ ] **Step 2: Run test to confirm it fails**

```
cd /Users/rajsingh/Documents/GitHub/tailnetlink
go test ./internal/config/...
```
Expected: `FAIL — config.LocalSourceSpec undefined`

- [ ] **Step 3: Add types to `internal/config/config.go`**

After `type ServiceSpec struct { ... }` (line ~63), insert:

```go
// LocalSourceSpec identifies a service on the local machine (or host-reachable network)
// to proxy into a destination tailnet. Addr is "host:port" dialed directly via net.DialContext.
// ExposePort is the VIP-side listen port (defaults to addr's port if zero). DNSName is required
// when host is localhost or a bare IP; auto-derived from addr hostname otherwise.
type LocalSourceSpec struct {
	Addr       string `json:"addr"`
	ExposePort int    `json:"expose_port,omitempty"`
	DNSName    string `json:"dns_name,omitempty"`
	ShortName  string `json:"short_name,omitempty"`
}
```

Replace the existing `BridgeRule` struct definition with:

```go
type BridgeRule struct {
	Name           string            `json:"name"`
	SourceTailnet  string            `json:"source_tailnet,omitempty"`
	DestTailnets   []string          `json:"dest_tailnets"`
	SourceTag      string            `json:"source_tag,omitempty"`
	SourceDevices  []DeviceSpec      `json:"source_devices,omitempty"`
	SourceServices []ServiceSpec     `json:"source_services,omitempty"`
	LocalSources   []LocalSourceSpec `json:"local_sources,omitempty"`
	Ports          []int             `json:"ports,omitempty"`
}
```

- [ ] **Step 4: Run tests**

```
go test ./internal/config/...
```
Expected: `PASS`

- [ ] **Step 5: Build**

```
go build ./...
```
Expected: no output

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat: add LocalSourceSpec to BridgeRule config"
```

---

## Task 2: Local source pure helper functions

**Files:**
- Create: `internal/bridge/local.go` (helpers only — `newLocalForwarder` and `runLocalRule` added in Task 4)
- Create: `internal/bridge/local_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/bridge/local_test.go`:

```go
package bridge

import (
	"testing"

	"github.com/rajsinghtech/tailnetlink/internal/config"
)

func TestIsLocalHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"0.0.0.0", true},
		{"192.168.1.5", true},
		{"10.0.0.1", true},
		{"ai.localtailnet.ts.net", false},
		{"local.app.custom.domain", false},
		{"myapp", false},
	}
	for _, c := range cases {
		got := isLocalHost(c.host)
		if got != c.want {
			t.Errorf("isLocalHost(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestLocalSourceEffectiveDNSName(t *testing.T) {
	cases := []struct {
		spec    config.LocalSourceSpec
		want    string
		wantErr bool
	}{
		{config.LocalSourceSpec{Addr: "localhost:11434", DNSName: "ollama.dest.ts.net"}, "ollama.dest.ts.net", false},
		{config.LocalSourceSpec{Addr: "ai.localtailnet.ts.net:8080"}, "ai.localtailnet.ts.net", false},
		{config.LocalSourceSpec{Addr: "local.app.custom.domain:80"}, "local.app.custom.domain", false},
		{config.LocalSourceSpec{Addr: "localhost:11434"}, "", true},
		{config.LocalSourceSpec{Addr: "192.168.1.5:8080"}, "", true},
		{config.LocalSourceSpec{Addr: "localhost:3000", DNSName: "app.dest.ts.net"}, "app.dest.ts.net", false},
	}
	for _, c := range cases {
		got, err := localSourceEffectiveDNSName(c.spec)
		if c.wantErr {
			if err == nil {
				t.Errorf("localSourceEffectiveDNSName(%v): want error, got nil (result %q)", c.spec, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("localSourceEffectiveDNSName(%v): unexpected error: %v", c.spec, err)
			continue
		}
		if got != c.want {
			t.Errorf("localSourceEffectiveDNSName(%v) = %q, want %q", c.spec, got, c.want)
		}
	}
}

func TestLocalSourceShortName(t *testing.T) {
	cases := []struct {
		shortName string
		dnsName   string
		want      string
	}{
		{"myapp", "anything.ts.net", "myapp"},
		{"", "ollama.dest.ts.net", "ollama"},
		{"", "ai.localtailnet.ts.net", "ai"},
		{"", "local.app.custom.domain", "local"},
		{"custom", "ai.ts.net", "custom"},
		{"", "singleword", "singleword"},
	}
	for _, c := range cases {
		got := localSourceShortName(c.shortName, c.dnsName)
		if got != c.want {
			t.Errorf("localSourceShortName(%q, %q) = %q, want %q", c.shortName, c.dnsName, got, c.want)
		}
	}
}

func TestLocalSourceExposePort(t *testing.T) {
	cases := []struct {
		spec config.LocalSourceSpec
		want int
	}{
		{config.LocalSourceSpec{Addr: "localhost:11434", ExposePort: 80}, 80},
		{config.LocalSourceSpec{Addr: "localhost:11434"}, 11434},
		{config.LocalSourceSpec{Addr: "ai.ts.net:8080", ExposePort: 443}, 443},
		{config.LocalSourceSpec{Addr: "ai.ts.net:8080"}, 8080},
	}
	for _, c := range cases {
		got, err := localSourceExposePort(c.spec)
		if err != nil {
			t.Errorf("localSourceExposePort(%v): unexpected error: %v", c.spec, err)
			continue
		}
		if got != c.want {
			t.Errorf("localSourceExposePort(%v) = %d, want %d", c.spec, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```
go test ./internal/bridge/... -run "TestIsLocalHost|TestLocalSource"
```
Expected: `FAIL — isLocalHost undefined`

- [ ] **Step 3: Create `internal/bridge/local.go` with pure helpers**

```go
package bridge

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/rajsinghtech/tailnetlink/internal/config"
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
	if spec.ExposePort > 0 {
		return spec.ExposePort, nil
	}
	_, portStr, err := net.SplitHostPort(spec.Addr)
	if err != nil {
		return 0, fmt.Errorf("invalid addr %q: %w", spec.Addr, err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 {
		return 0, fmt.Errorf("invalid port in addr %q", spec.Addr)
	}
	return p, nil
}
```

- [ ] **Step 4: Run tests**

```
go test ./internal/bridge/... -run "TestIsLocalHost|TestLocalSource"
```
Expected: `PASS`

- [ ] **Step 5: Build**

```
go build ./...
```
Expected: no output

- [ ] **Step 6: Commit**

```bash
git add internal/bridge/local.go internal/bridge/local_test.go
git commit -m "feat: add local source helper functions"
```

---

## Task 3: Add `localAddr` to Forwarder

**Files:**
- Modify: `internal/bridge/forwarder.go`

- [ ] **Step 1: Add `localAddr` field to `Forwarder` struct**

In `internal/bridge/forwarder.go`, replace the `Forwarder` struct (lines 30–43):

```go
type Forwarder struct {
	listenSrv   *tsnet.Server
	dialSrv     *tsnet.Server // nil for local-mode forwarders
	localAddr   string        // when non-empty, dials via net.DialContext instead of dialSrv
	vip         *VIPService
	bridgeID    string
	timeout     time.Duration
	store       *state.Store
	logger      *slog.Logger
	connCounter atomic.Int64

	cancel    context.CancelFunc
	listeners []net.Listener
	wg        sync.WaitGroup
}
```

- [ ] **Step 2: Update `handle()` to branch on `localAddr`**

In `handle()` (line ~119), replace this block:

```go
	target := net.JoinHostPort(f.vip.SourceIP.String(), strconv.Itoa(port))

	dialCtx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	// Dial through the source tailnet to reach the actual backend service.
	upstream, err := f.dialSrv.Dial(dialCtx, "tcp", target)
	if err != nil {
```

With:

```go
	dialCtx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	var target string
	var upstream net.Conn
	var dialErr error

	if f.localAddr != "" {
		target = f.localAddr
		upstream, dialErr = (&net.Dialer{}).DialContext(dialCtx, "tcp", f.localAddr)
	} else {
		target = net.JoinHostPort(f.vip.SourceIP.String(), strconv.Itoa(port))
		upstream, dialErr = f.dialSrv.Dial(dialCtx, "tcp", target)
	}

	if err := dialErr; err != nil {
```

The remaining body of `handle()` is unchanged — the `err` variable check now reads from `dialErr` via the `err := dialErr` reassignment. Verify the variable shadowing is correct by checking that `err` is not used again after this block before the next `err` declaration.

- [ ] **Step 3: Build**

```
go build ./...
```
Expected: no output

- [ ] **Step 4: Run tests**

```
go test ./...
```
Expected: `PASS`

- [ ] **Step 5: Commit**

```bash
git add internal/bridge/forwarder.go
git commit -m "feat: support local dial mode in Forwarder"
```

---

## Task 4: Add `newLocalForwarder` and `runLocalRule`

**Files:**
- Modify: `internal/bridge/local.go` (append to existing file)

- [ ] **Step 1: Append `newLocalForwarder` and `runLocalRule` to `internal/bridge/local.go`**

Add these imports to the top of `local.go` (replace the existing import block with the expanded version):

```go
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
```

Then append to the bottom of `local.go`:

```go
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
		lb := lb
		wg.Add(1)
		go func() {
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
		}()
	}
	wg.Wait()
	m.store.Log("info", fmt.Sprintf("[%s] local rule stopped", rule.Name), nil)
}
```

Note: `destCtx` is defined in `bridge.go`. The `rec` field on `destCtx` is set to `nil` here since each local source creates its own `Reconciler`.

- [ ] **Step 2: Build**

```
go build ./...
```
Expected: no output

- [ ] **Step 3: Commit**

```bash
git add internal/bridge/local.go
git commit -m "feat: add newLocalForwarder and runLocalRule"
```

---

## Task 5: Wire `runLocalRule` into `runRule`

**Files:**
- Modify: `internal/bridge/bridge.go`

- [ ] **Step 1: Add local rule dispatch at the top of `runRule`**

In `internal/bridge/bridge.go`, find `func (m *Manager) runRule(` (around line 250). Add the local rule fast-path as the very first statement in the function body, before the existing `m.mu.Lock()` block:

Find this text:
```go
func (m *Manager) runRule(ctx context.Context, rule config.BridgeRule, pollInterval, dialTimeout time.Duration) {
	m.mu.Lock()
	srcSrv := m.servers[rule.SourceTailnet]
```

Replace with:
```go
func (m *Manager) runRule(ctx context.Context, rule config.BridgeRule, pollInterval, dialTimeout time.Duration) {
	if len(rule.LocalSources) > 0 {
		m.runLocalRule(ctx, rule, dialTimeout)
		return
	}

	m.mu.Lock()
	srcSrv := m.servers[rule.SourceTailnet]
```

- [ ] **Step 2: Build**

```
go build ./...
```
Expected: no output

- [ ] **Step 3: Run all tests**

```
go test ./...
```
Expected: `PASS`

- [ ] **Step 4: Commit**

```bash
git add internal/bridge/bridge.go
git commit -m "feat: dispatch local rules to runLocalRule in runRule"
```

---

## Task 6: Server validation for local rules

**Files:**
- Modify: `internal/server/server.go`

- [ ] **Step 1: Add `validateBridgeRule` and related helpers**

Add these new functions at the bottom of `server.go`, before or after `checkShortNameConflicts`:

```go
// validateBridgeRule validates a bridge rule for both tailnet and local-source rules.
func validateBridgeRule(rule config.BridgeRule) error {
	if rule.Name == "" {
		return fmt.Errorf("name is required")
	}
	if len(rule.DestTailnets) == 0 {
		return fmt.Errorf("dest_tailnets is required")
	}
	if len(rule.LocalSources) > 0 {
		if rule.SourceTailnet != "" || rule.SourceTag != "" || len(rule.SourceDevices) > 0 || len(rule.SourceServices) > 0 || len(rule.Ports) > 0 {
			return fmt.Errorf("local rules must not set source_tailnet, source_tag, source_devices, source_services, or ports")
		}
		return validateLocalSources(rule.LocalSources)
	}
	if rule.SourceTailnet == "" {
		return fmt.Errorf("source_tailnet is required for non-local rules")
	}
	if len(rule.Ports) == 0 {
		return fmt.Errorf("ports is required for non-local rules")
	}
	if rule.SourceTag == "" && len(rule.SourceDevices) == 0 && len(rule.SourceServices) == 0 {
		return fmt.Errorf("either source_tag, source_devices, or source_services must be specified")
	}
	return nil
}

// validateLocalSources checks each LocalSourceSpec in isolation.
func validateLocalSources(sources []config.LocalSourceSpec) error {
	for i, src := range sources {
		host, portStr, err := net.SplitHostPort(src.Addr)
		if err != nil {
			return fmt.Errorf("local_sources[%d].addr %q is invalid: %w", i, src.Addr, err)
		}
		p, err := strconv.Atoi(portStr)
		if err != nil || p <= 0 || p > 65535 {
			return fmt.Errorf("local_sources[%d].addr %q has invalid port", i, src.Addr)
		}
		if src.ExposePort < 0 || src.ExposePort > 65535 {
			return fmt.Errorf("local_sources[%d].expose_port %d is out of range", i, src.ExposePort)
		}
		if isLocalHostServer(host) && src.DNSName == "" {
			return fmt.Errorf("local_sources[%d].addr %q requires dns_name (cannot derive from localhost/IP)", i, src.Addr)
		}
	}
	return nil
}

// isLocalHostServer mirrors bridge.isLocalHost for use in the server package.
func isLocalHostServer(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "0.0.0.0" {
		return true
	}
	_, err := netip.ParseAddr(h)
	return err == nil
}
```

- [ ] **Step 2: Add `net`, `net/netip`, `strconv`, `strings` to `server.go` imports if not already present**

At the top of `server.go`, ensure the import block includes:
```go
import (
    "net"
    "net/netip"
    "strconv"
    "strings"
    // ... all existing imports remain
)
```

- [ ] **Step 3: Replace inline validation in `handleBridgeRules` POST handler**

Find this block in `handleBridgeRules` (around line 317):
```go
	if rule.Name == "" || rule.SourceTailnet == "" || len(rule.DestTailnets) == 0 || len(rule.Ports) == 0 {
		http.Error(w, "name, source_tailnet, dest_tailnets, and ports are required", http.StatusBadRequest)
		return
	}
	if rule.SourceTag == "" && len(rule.SourceDevices) == 0 && len(rule.SourceServices) == 0 {
		http.Error(w, "either source_tag, source_devices, or source_services must be specified", http.StatusBadRequest)
		return
	}
```

Replace with:
```go
	if err := validateBridgeRule(rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
```

- [ ] **Step 4: Skip `source_tailnet` existence check for local rules in the `cfgStore.Update` callback**

In `handleBridgeRules`, find the `cfgStore.Update` callback. Replace:
```go
		if _, ok := cfg.Tailnets[rule.SourceTailnet]; !ok {
			return fmt.Errorf("source_tailnet %q not found", rule.SourceTailnet)
		}
```
With:
```go
		if len(rule.LocalSources) == 0 {
			if _, ok := cfg.Tailnets[rule.SourceTailnet]; !ok {
				return fmt.Errorf("source_tailnet %q not found", rule.SourceTailnet)
			}
		}
```

- [ ] **Step 5: Add validation to the PUT handler in `handleBridgeRuleByName`**

In `handleBridgeRuleByName`, in the `http.MethodPut` case, after `rule.Name = name`, add:
```go
		if err := validateBridgeRule(rule); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
```

- [ ] **Step 6: Extend `checkShortNameConflicts` to cover `LocalSources`**

In `checkShortNameConflicts`, in the first loop (collecting used short_names from existing rules), after the `SourceServices` block, add:
```go
			for _, spec := range b.LocalSources {
				if spec.ShortName != "" {
					if used[dest] == nil {
						used[dest] = map[string]bool{}
					}
					used[dest][spec.ShortName] = true
				}
			}
```

In the second loop (checking incoming rule), after the `SourceServices` check block, add:
```go
		for _, spec := range incoming.LocalSources {
			if spec.ShortName == "" {
				continue
			}
			if used[dest][spec.ShortName] {
				return fmt.Errorf("short_name %q already used in dest tailnet %q", spec.ShortName, dest)
			}
			if selfSeen[dest] == nil {
				selfSeen[dest] = map[string]bool{}
			}
			if selfSeen[dest][spec.ShortName] {
				return fmt.Errorf("short_name %q appears more than once for dest tailnet %q", spec.ShortName, dest)
			}
			selfSeen[dest][spec.ShortName] = true
		}
```

- [ ] **Step 7: Write server validation tests**

Create `internal/server/server_test.go`:

```go
package server

import (
	"testing"

	"github.com/rajsinghtech/tailnetlink/internal/config"
)

func TestValidateBridgeRule_LocalRequiresDNS(t *testing.T) {
	rule := config.BridgeRule{
		Name:         "test",
		DestTailnets: []string{"dest"},
		LocalSources: []config.LocalSourceSpec{
			{Addr: "localhost:8080"},
		},
	}
	if err := validateBridgeRule(rule); err == nil {
		t.Error("expected error for localhost without dns_name, got nil")
	}
}

func TestValidateBridgeRule_LocalFQDNNoError(t *testing.T) {
	rule := config.BridgeRule{
		Name:         "test",
		DestTailnets: []string{"dest"},
		LocalSources: []config.LocalSourceSpec{
			{Addr: "ai.local.ts.net:8080"},
		},
	}
	if err := validateBridgeRule(rule); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateBridgeRule_LocalWithExplicitDNS(t *testing.T) {
	rule := config.BridgeRule{
		Name:         "test",
		DestTailnets: []string{"dest"},
		LocalSources: []config.LocalSourceSpec{
			{Addr: "localhost:11434", DNSName: "ollama.dest.ts.net"},
		},
	}
	if err := validateBridgeRule(rule); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateBridgeRule_NonLocalMissingTailnet(t *testing.T) {
	rule := config.BridgeRule{
		Name:         "test",
		DestTailnets: []string{"dest"},
		Ports:        []int{8080},
		SourceTag:    "tag:api",
	}
	if err := validateBridgeRule(rule); err == nil {
		t.Error("expected error for missing source_tailnet, got nil")
	}
}

func TestValidateBridgeRule_LocalRejectsSourceTailnet(t *testing.T) {
	rule := config.BridgeRule{
		Name:          "test",
		DestTailnets:  []string{"dest"},
		SourceTailnet: "src",
		LocalSources:  []config.LocalSourceSpec{{Addr: "ai.ts.net:8080"}},
	}
	if err := validateBridgeRule(rule); err == nil {
		t.Error("expected error when local rule sets source_tailnet, got nil")
	}
}
```

- [ ] **Step 8: Run tests**

```
go test ./internal/server/...
```
Expected: `PASS`

- [ ] **Step 9: Build**

```
go build ./...
```
Expected: no output

- [ ] **Step 10: Commit**

```bash
git add internal/server/server.go internal/server/server_test.go
git commit -m "feat: validate local bridge rules in API server"
```

---

## Task 7: UI — Modal HTML/CSS for source type toggle and local endpoints

**Files:**
- Modify: `internal/server/web/index.html`

- [ ] **Step 1: Add CSS for source type toggle and local endpoint rows**

In `index.html`, find this CSS comment (around line 412):
```css
    /* ─── Source picker ──────────────────────────────────────────────────────── */
```

Add new CSS rules immediately after the closing brace of `.device-dns-input:focus` (around line 454). Insert before `/* ─── Setup wizard */`:

```css
    /* ─── Source type toggle ─────────────────────────────────────────────── */
    .src-type-toggle { display: flex; border: 1px solid var(--gray-200); border-radius: 8px; overflow: hidden; }
    .src-type-btn {
      flex: 1; padding: 7px 12px; font-size: 13px; font-weight: 500; color: var(--gray-500);
      border: none; background: white; cursor: pointer; transition: background .12s, color .12s;
    }
    .src-type-btn.active { background: var(--blue-0); color: var(--blue-600); }
    .src-type-btn:first-child { border-right: 1px solid var(--gray-200); }

    /* ─── Local endpoint rows ────────────────────────────────────────────── */
    .local-ep-list { display: flex; flex-direction: column; gap: 8px; }
    .local-ep-row {
      background: var(--gray-50); border: 1px solid var(--gray-200); border-radius: 8px;
      padding: 10px 12px; display: flex; gap: 8px; align-items: start;
    }
    .local-ep-fields { flex: 1; display: flex; flex-direction: column; gap: 6px; }
    .local-ep-row-line { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
    .local-ep-lbl { font-size: 11px; color: var(--gray-500); white-space: nowrap; flex-shrink: 0; min-width: 58px; }
    .local-ep-preview { font-size: 11px; color: var(--blue-500); font-family: "SFMono-Regular", Consolas, monospace; }
    .local-ep-err { font-size: 11px; color: var(--red-600); display: none; }
    .local-ep-err.visible { display: block; }
    .local-ep-add {
      display: flex; align-items: center; justify-content: center; gap: 6px;
      width: 100%; padding: 8px 12px; border-radius: 6px; border: 1px dashed var(--gray-300);
      font-size: 12px; font-weight: 500; color: var(--gray-500); background: white; cursor: pointer;
      transition: border-color .15s, background .15s, color .15s;
    }
    .local-ep-add:hover { border-color: var(--blue-200); background: var(--blue-0); color: var(--blue-600); }
```

- [ ] **Step 2: Replace the bridge modal `<div class="modal-body">` contents**

Find `<!-- Add / Edit Bridge Rule -->` (around line 822). Replace the entire `<div class="modal-body">` block (from `<div class="modal-body">` to its closing `</div>`) with:

```html
    <div class="modal-body">
      <div class="form-group">
        <label class="form-label">Source type</label>
        <div class="src-type-toggle">
          <button type="button" class="src-type-btn active" id="bridge-src-type-ts"
            onclick="setBridgeSrcType('tailscale')">Tailscale network</button>
          <button type="button" class="src-type-btn" id="bridge-src-type-local"
            onclick="setBridgeSrcType('local')">Local machine</button>
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">Rule name</label>
        <input class="form-input" id="bridge-name-input" placeholder="api-servers" required autocomplete="off">
        <div class="form-hint">A unique identifier for this bridge rule.</div>
      </div>
      <!-- Tailscale-mode fields -->
      <div id="bridge-ts-fields">
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Source network</label>
            <select class="form-select" id="bridge-source-select" onchange="loadSourcePicker('bridge')">
              <option value="">Select…</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Destination network(s)</label>
            <div class="dest-picker" id="bridge-dest-picker"><span class="dest-chip-empty">No networks configured</span></div>
            <div class="form-hint">Click to toggle. Select one or more destinations.</div>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Source — select by tag or specific devices</label>
          <div class="src-picker" id="bridge-src-picker">
            <div class="src-picker-loading">Select a source network first</div>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Ports (comma-separated)</label>
          <input class="form-input mono" id="bridge-ports-input" placeholder="8080, 8443" autocomplete="off">
          <div class="form-hint">TCP ports to forward from source devices.</div>
        </div>
      </div>
      <!-- Local machine fields -->
      <div id="bridge-local-fields" hidden>
        <div class="form-group">
          <label class="form-label">Destination network(s)</label>
          <div class="dest-picker" id="bridge-local-dest-picker"><span class="dest-chip-empty">No networks configured</span></div>
          <div class="form-hint">Click to toggle. Select one or more destinations.</div>
        </div>
        <div class="form-group">
          <label class="form-label">Local endpoints</label>
          <div class="local-ep-list" id="bridge-local-ep-list"></div>
          <button type="button" class="local-ep-add" onclick="addLocalEpRow('bridge-local-ep-list')">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            Add endpoint
          </button>
          <div class="form-hint">addr is host:port to dial. VIP port defaults to addr port.</div>
        </div>
      </div>
      <div class="wizard-error" id="add-bridge-error"></div>
    </div>
```

- [ ] **Step 3: Build**

```
go build ./...
```
Expected: no output

- [ ] **Step 4: Commit**

```bash
git add internal/server/web/index.html
git commit -m "feat: add source type toggle and local endpoint builder HTML/CSS"
```

---

## Task 8: UI — Modal JavaScript

**Files:**
- Modify: `internal/server/web/index.html`

- [ ] **Step 1: Add `bridge-local` to `destPickerSel`**

Find (around line 1322):
```js
const destPickerSel = { bridge: new Set(), w2: new Set() };
```
Replace with:
```js
const destPickerSel = { bridge: new Set(), w2: new Set(), 'bridge-local': new Set() };
```

- [ ] **Step 2: Update `renderDestPicker` to support `bridge-local` prefix**

Find (around line 1324):
```js
function renderDestPicker(prefix) {
  const el = document.getElementById(prefix === 'bridge' ? 'bridge-dest-picker' : 'w2-dest-picker');
```
Replace with:
```js
function renderDestPicker(prefix) {
  const idMap = { bridge: 'bridge-dest-picker', w2: 'w2-dest-picker', 'bridge-local': 'bridge-local-dest-picker' };
  const el = document.getElementById(idMap[prefix] || (prefix + '-dest-picker'));
```

- [ ] **Step 3: Add local endpoint JS functions before `openAddBridgeModal`**

Find `function openAddBridgeModal()` (around line 1059). Insert the following block immediately before it:

```js
// ── Local endpoint builder ────────────────────────────────────────────────────
let _epSeq = 0;

function setBridgeSrcType(type) {
  const isLocal = type === 'local';
  document.getElementById('bridge-src-type-ts').classList.toggle('active', !isLocal);
  document.getElementById('bridge-src-type-local').classList.toggle('active', isLocal);
  document.getElementById('bridge-ts-fields').hidden = isLocal;
  document.getElementById('bridge-local-fields').hidden = !isLocal;
  if (isLocal) renderDestPicker('bridge-local');
}

function addLocalEpRow(listId, initial) {
  const id = 'ep' + (++_epSeq);
  const row = document.createElement('div');
  row.className = 'local-ep-row';
  row.dataset.epid = id;
  row.innerHTML = `
    <div class="local-ep-fields">
      <div class="local-ep-row-line">
        <span class="local-ep-lbl">Address</span>
        <input class="form-input mono" style="flex:1;min-width:160px" placeholder="localhost:8080 or hostname:port"
          data-field="addr" value="${esc(initial && initial.addr || '')}" oninput="onEpChange('${id}')">
        <span class="local-ep-lbl" style="min-width:unset">VIP port</span>
        <input class="form-input mono" style="width:72px" placeholder="auto"
          data-field="expose_port" value="${initial && initial.expose_port > 0 ? initial.expose_port : ''}"
          oninput="onEpChange('${id}')">
      </div>
      <div class="local-ep-row-line">
        <span class="local-ep-lbl">DNS name</span>
        <input class="form-input mono" style="flex:1;min-width:160px" placeholder="auto from FQDN or required for localhost"
          data-field="dns_name" value="${esc(initial && initial.dns_name || '')}" oninput="onEpChange('${id}')">
        <span class="local-ep-lbl" style="min-width:unset">Short</span>
        <input class="form-input mono" style="width:84px" placeholder="optional"
          data-field="short_name" value="${esc(initial && initial.short_name || '')}" oninput="onEpChange('${id}')">
      </div>
      <div class="local-ep-preview" id="${id}-prev"></div>
      <div class="local-ep-err" id="${id}-err"></div>
    </div>
    <button type="button" class="btn-icon danger" style="align-self:start;margin-top:2px" title="Remove"
      onclick="document.querySelector('[data-epid=${id}]').remove()">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/></svg>
    </button>`;
  document.getElementById(listId).appendChild(row);
  if (initial && initial.addr) onEpChange(id);
}

function onEpChange(id) {
  const row = document.querySelector(`[data-epid="${id}"]`);
  if (!row) return;
  const addr = row.querySelector('[data-field=addr]').value.trim();
  const dnsName = row.querySelector('[data-field=dns_name]').value.trim();
  const shortName = row.querySelector('[data-field=short_name]').value.trim();
  const prev = document.getElementById(id + '-prev');
  const errEl = document.getElementById(id + '-err');
  errEl.textContent = ''; errEl.classList.remove('visible');
  prev.textContent = '';
  if (!addr) return;

  const lastColon = addr.lastIndexOf(':');
  const host = lastColon > 0 ? addr.slice(0, lastColon) : addr;
  const isLocal = host === 'localhost' || host === '127.0.0.1' || host === '::1' || /^[\d.]+$/.test(host) || /^[0-9a-fA-F:]+$/.test(host);

  const dnsInput = row.querySelector('[data-field=dns_name]');
  dnsInput.placeholder = isLocal ? 'required for localhost/IP' : (host.includes('.') ? host + ' (auto)' : 'optional');

  if (isLocal && !dnsName) {
    errEl.textContent = 'dns_name required for localhost/IP'; errEl.classList.add('visible'); return;
  }

  const effectiveDns = dnsName || (host.includes('.') ? host : '');
  if (effectiveDns) {
    const dot = effectiveDns.indexOf('.');
    const label = dot > 0 ? effectiveDns.slice(0, dot) : effectiveDns;
    prev.textContent = '→ svc:' + (shortName || ('tnl-local-' + label));
  }
}

function getLocalSources(listId) {
  const rows = document.querySelectorAll('#' + listId + ' [data-epid]');
  return Array.from(rows).reduce((acc, row) => {
    const addr = row.querySelector('[data-field=addr]').value.trim();
    if (!addr) return acc;
    const ep = { addr };
    const ep_str = row.querySelector('[data-field=expose_port]').value.trim();
    const dns = row.querySelector('[data-field=dns_name]').value.trim();
    const sn = row.querySelector('[data-field=short_name]').value.trim();
    if (ep_str) ep.expose_port = parseInt(ep_str, 10);
    if (dns) ep.dns_name = dns;
    if (sn) ep.short_name = sn;
    acc.push(ep);
    return acc;
  }, []);
}
```

- [ ] **Step 4: Update `openAddBridgeModal` to reset source type and local list**

Replace the existing `openAddBridgeModal` function:

```js
function openAddBridgeModal() {
  document.getElementById('bridge-modal-title').textContent = 'Add bridge rule';
  document.getElementById('bridge-modal-submit').textContent = 'Add bridge rule';
  document.getElementById('bridge-edit-name').value = '';
  document.getElementById('bridge-name-input').value = '';
  document.getElementById('bridge-name-input').disabled = false;
  document.getElementById('bridge-ports-input').value = '';
  document.getElementById('bridge-src-picker').innerHTML = '<div class="src-picker-loading">Select a source network first</div>';
  document.getElementById('bridge-local-ep-list').innerHTML = '';
  setBridgeSrcType('tailscale');
  populateBridgeSelects();
  document.getElementById('modal-add-bridge').hidden = false;
}
```

- [ ] **Step 5: Update `openEditBridgeModal` to restore local_sources**

Replace the existing `openEditBridgeModal` function:

```js
function openEditBridgeModal(ruleName) {
  const rule = (state.config.bridges || []).find(b => b.name === ruleName);
  if (!rule) return;
  document.getElementById('bridge-modal-title').textContent = 'Edit bridge rule';
  document.getElementById('bridge-modal-submit').textContent = 'Save changes';
  document.getElementById('bridge-edit-name').value = rule.name;
  document.getElementById('bridge-name-input').value = rule.name;
  document.getElementById('bridge-name-input').disabled = true;

  const isLocal = rule.local_sources && rule.local_sources.length > 0;

  if (isLocal) {
    setBridgeSrcType('local');
    document.getElementById('bridge-local-ep-list').innerHTML = '';
    destPickerSel['bridge-local'] = new Set(rule.dest_tailnets || []);
    renderDestPicker('bridge-local');
    for (const src of rule.local_sources) addLocalEpRow('bridge-local-ep-list', src);
  } else {
    setBridgeSrcType('tailscale');
    document.getElementById('bridge-ports-input').value = (rule.ports || []).join(', ');
    populateBridgeSelects(rule.source_tailnet, rule.dest_tailnets || []);
    loadSourcePicker('bridge').then(() => {
      const ps = pickerState['bridge'];
      if (!ps) return;
      if (rule.source_services && rule.source_services.length > 0) {
        ps.tab = 'service';
        rule.source_services.forEach(spec => ps.selServices.set(spec.name, { dns: spec.dns_name || '', short: spec.short_name || '' }));
      } else if (rule.source_devices && rule.source_devices.length > 0) {
        ps.tab = 'device';
        rule.source_devices.forEach(spec => ps.selDevices.set(spec.fqdn, { dns: spec.dns_name || '', short: spec.short_name || '' }));
      } else if (rule.source_tag) {
        ps.tab = 'tag';
        ps.selTag = rule.source_tag;
      }
      renderSourcePicker('bridge');
    });
  }
  document.getElementById('modal-add-bridge').hidden = false;
}
```

- [ ] **Step 6: Replace `submitAddBridge` to handle local mode**

Replace the entire `submitAddBridge` function:

```js
async function submitAddBridge(e) {
  e.preventDefault();
  const errEl = document.getElementById('add-bridge-error');
  errEl.classList.remove('visible');
  try {
    const editName = document.getElementById('bridge-edit-name').value;
    const name = document.getElementById('bridge-name-input').value.trim();
    if (!name) throw new Error('Rule name is required');

    const isLocal = document.getElementById('bridge-src-type-local').classList.contains('active');
    let payload;

    if (isLocal) {
      const dsts = getSelectedDests('bridge-local');
      if (dsts.length === 0) throw new Error('Select at least one destination network');
      const local_sources = getLocalSources('bridge-local-ep-list');
      if (local_sources.length === 0) throw new Error('Add at least one local endpoint');
      for (const src of local_sources) {
        const lastColon = src.addr.lastIndexOf(':');
        const host = lastColon > 0 ? src.addr.slice(0, lastColon) : src.addr;
        if ((host === 'localhost' || host === '127.0.0.1') && !src.dns_name)
          throw new Error(`Endpoint "${src.addr}" requires a dns_name`);
      }
      payload = { name, dest_tailnets: dsts, local_sources };
    } else {
      const src = document.getElementById('bridge-source-select').value;
      const dsts = getSelectedDests('bridge');
      const ports = parsePorts(document.getElementById('bridge-ports-input').value);
      if (!src || dsts.length === 0) throw new Error('Source and at least one destination network are required');
      if (dsts.includes(src)) throw new Error('Source and destination networks must be different');
      if (ports.length === 0) throw new Error('Enter at least one valid port number');
      const sel = getPickerSelection('bridge');
      if (!sel.source_tag && (!sel.source_devices || sel.source_devices.length === 0) && (!sel.source_services || sel.source_services.length === 0))
        throw new Error('Select a source tag, at least one machine, or at least one service');
      payload = { name, source_tailnet: src, dest_tailnets: dsts, ports, ...sel };
    }

    if (editName) {
      await apiPut(`/api/bridge-rules/${encodeURIComponent(editName)}`, payload);
    } else {
      await apiPost('/api/bridge-rules', payload);
    }
    closeModal('modal-add-bridge');
    await refreshConfig();
  } catch(err) {
    errEl.textContent = err.message; errEl.classList.add('visible');
  }
}
```

- [ ] **Step 7: Build**

```
go build ./...
```
Expected: no output

- [ ] **Step 8: Commit**

```bash
git add internal/server/web/index.html
git commit -m "feat: modal JS for local machine bridge rules (toggle, endpoint builder, submit)"
```

---

## Task 9: UI — Update rendering for local rules

**Files:**
- Modify: `internal/server/web/index.html`

- [ ] **Step 1: Update `renderTopology` for local rules**

In `renderTopology` (around line 1537), find:
```js
    const srcLabel  = (cfgNets[rule.source_tailnet] || {}).tailnet || rule.source_tailnet || '—';
```
Replace with:
```js
    const isLocalRule = rule.local_sources && rule.local_sources.length > 0;
    const srcLabel = isLocalRule ? 'local' : ((cfgNets[rule.source_tailnet] || {}).tailnet || rule.source_tailnet || '—');
```

Find:
```js
    const ports     = (rule.ports || []).map(p => `:${p}`).join(' ');
```
Replace with:
```js
    const ports = isLocalRule
      ? (rule.local_sources || []).map(s => ':' + (s.expose_port || s.addr.split(':').pop())).join(' ')
      : (rule.ports || []).map(p => `:${p}`).join(' ');
```

Find this block (the `filterHtml` assignment):
```js
    const filterHtml = rule.source_tag
      ? `<span class="tag-chip" style="font-size:11px">${esc(rule.source_tag)}</span>`
      : rule.source_devices && rule.source_devices.length > 0
        ? `<span class="mono" style="font-size:12px;color:var(--gray-700)">${esc(srcNames(rule.source_devices, d => d.short_name || d.fqdn.split('.')[0]))}</span>`
        : rule.source_services && rule.source_services.length > 0
          ? `<span class="mono" style="font-size:12px;color:var(--gray-700)">${esc(srcNames(rule.source_services, s => s.short_name || s.name))}</span>`
          : '<span style="font-size:12px;color:var(--gray-500)">—</span>';
```
Replace with:
```js
    const filterHtml = isLocalRule
      ? `<span class="badge neutral" style="font-size:11px">local machine</span>`
      : rule.source_tag
        ? `<span class="tag-chip" style="font-size:11px">${esc(rule.source_tag)}</span>`
        : rule.source_devices && rule.source_devices.length > 0
          ? `<span class="mono" style="font-size:12px;color:var(--gray-700)">${esc(srcNames(rule.source_devices, d => d.short_name || d.fqdn.split('.')[0]))}</span>`
          : rule.source_services && rule.source_services.length > 0
            ? `<span class="mono" style="font-size:12px;color:var(--gray-700)">${esc(srcNames(rule.source_services, s => s.short_name || s.name))}</span>`
            : '<span style="font-size:12px;color:var(--gray-500)">—</span>';
```

In the template literal for the bridge rule card, find the `brc-meta-net` span in the first row:
```js
          <span class="brc-meta-net" title="${esc(srcLabel)}">${esc(srcLabel)}</span>
```
Replace with:
```js
          <span class="brc-meta-net" title="${esc(srcLabel)}">${isLocalRule ? '<span class="badge neutral" style="font-size:10px;padding:1px 6px">local</span>' : esc(srcLabel)}</span>
```

- [ ] **Step 2: Update `renderBridges` (services table) for local rules**

In `renderBridges` (around line 1663), find:
```js
    const rule = (state.config.bridges || []).find(r => r.name === b.rule_name);
    const srcTailnet = rule ? rule.source_tailnet : '?';
    const dstTailnet = b.dest_tailnet || '?';
    const route = `<span style="white-space:nowrap;font-size:12px">
      <span class="badge src" style="font-size:10px">${esc(srcTailnet)}</span>
      <span style="color:var(--gray-400);margin:0 3px">→</span>
      <span class="badge dst" style="font-size:10px">${esc(dstTailnet)}</span>
    </span>`;
```
Replace with:
```js
    const rule = (state.config.bridges || []).find(r => r.name === b.rule_name);
    const isLocalRule = rule && rule.local_sources && rule.local_sources.length > 0;
    const srcLabel = isLocalRule ? 'local' : (rule ? rule.source_tailnet : '?');
    const srcBadgeCls = isLocalRule ? 'neutral' : 'src';
    const dstTailnet = b.dest_tailnet || '?';
    const route = `<span style="white-space:nowrap;font-size:12px">
      <span class="badge ${srcBadgeCls}" style="font-size:10px">${esc(srcLabel)}</span>
      <span style="color:var(--gray-400);margin:0 3px">→</span>
      <span class="badge dst" style="font-size:10px">${esc(dstTailnet)}</span>
    </span>`;
```

- [ ] **Step 3: Update `renderRules` (rules table) for local rules**

In `renderRules` (around line 1705), find:
```js
  tbody.innerHTML = rules.map(r => {
    const ports = (r.ports||[]).map(p=>`<span class="port-chip">${p}</span>`).join('');
    const ruleNames = (arr, fn) => {
```
Replace the mapping function with:
```js
  tbody.innerHTML = rules.map(r => {
    const isLocalR = r.local_sources && r.local_sources.length > 0;
    const ports = isLocalR
      ? (r.local_sources||[]).map(s=>`<span class="port-chip">${s.expose_port || s.addr.split(':').pop()}</span>`).join('')
      : (r.ports||[]).map(p=>`<span class="port-chip">${p}</span>`).join('');
    const ruleNames = (arr, fn) => {
```

Find:
```js
    return `<tr>
      <td>${esc(r.name)}</td>
      <td><span class="badge src" style="font-size:11px">↑ ${esc(r.source_tailnet)}</span></td>
      <td>${(r.dest_tailnets||[]).map(dt=>`<span class="badge dst" style="font-size:11px">↓ ${esc(dt)}</span>`).join(' ')}</td>
      <td><span class="mono" style="font-size:12px">${esc(srcLabel)}</span></td>
      <td><div class="port-chips">${ports}</div></td>
      <td style="display:flex;gap:6px">
        <button class="btn-icon" title="Edit rule" onclick="openEditBridgeModal('${esc(r.name)}')">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        </button>
        <button class="btn-icon danger" title="Delete rule" onclick="deleteBridgeRule('${esc(r.name)}')">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/></svg>
        </button>
      </td>
    </tr>`;
```
Replace with:
```js
    const srcBadge = isLocalR
      ? `<span class="badge neutral" style="font-size:11px">↑ local</span>`
      : `<span class="badge src" style="font-size:11px">↑ ${esc(r.source_tailnet)}</span>`;
    const srcDisplayLabel = isLocalR
      ? ((r.local_sources||[]).slice(0,2).map(s=>s.addr).join(', ') + (r.local_sources.length > 2 ? ` +${r.local_sources.length-2}` : ''))
      : srcLabel;
    return `<tr>
      <td>${esc(r.name)}</td>
      <td>${srcBadge}</td>
      <td>${(r.dest_tailnets||[]).map(dt=>`<span class="badge dst" style="font-size:11px">↓ ${esc(dt)}</span>`).join(' ')}</td>
      <td><span class="mono" style="font-size:12px" title="${esc(srcDisplayLabel)}">${esc(srcDisplayLabel)}</span></td>
      <td><div class="port-chips">${ports}</div></td>
      <td style="display:flex;gap:6px">
        <button class="btn-icon" title="Edit rule" onclick="openEditBridgeModal('${esc(r.name)}')">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        </button>
        <button class="btn-icon danger" title="Delete rule" onclick="deleteBridgeRule('${esc(r.name)}')">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/></svg>
        </button>
      </td>
    </tr>`;
```

- [ ] **Step 4: Update `renderConns` to show `local` for local rule connections**

In `renderConns` (around line 1806), find:
```js
    const backendTailnet = rule   ? rule.source_tailnet : '';
```
Replace with:
```js
    const backendTailnet = rule
      ? (rule.local_sources && rule.local_sources.length > 0 ? 'local' : rule.source_tailnet)
      : '';
```

- [ ] **Step 5: Build**

```
go build ./...
```
Expected: no output

- [ ] **Step 6: Commit**

```bash
git add internal/server/web/index.html
git commit -m "feat: render local machine rules in topology, services, rules, and connection tables"
```

---

## Task 10: Final integration verification

- [ ] **Step 1: Run all tests**

```
cd /Users/rajsingh/Documents/GitHub/tailnetlink
go test ./...
```
Expected: all packages pass

- [ ] **Step 2: Build production binary**

```
go build -o /tmp/tailnetlink-test ./cmd/tailnetlink/ && echo "BUILD OK"
```
Expected: `BUILD OK`

- [ ] **Step 3: Verify config JSON round-trip**

```
echo '{
  "tailnets": {
    "dest": {"oauth": {"client_id": "x", "client_secret": "y"}, "tailnet": "dest.ts.net", "tags": ["tag:tl"]}
  },
  "bridges": [{
    "name": "local-ai",
    "local_sources": [
      {"addr": "localhost:11434", "expose_port": 80, "dns_name": "ollama.dest.ts.net"},
      {"addr": "ai.local.ts.net:8080"}
    ],
    "dest_tailnets": ["dest"]
  }]
}' | go run ./cmd/tailnetlink/ -data /dev/stdin -listen :0 2>&1 | head -5 || true
```
Expected: process starts and attempts to connect (OAuth will fail with test creds, but config parsing should succeed — look for `connecting to tailnet` in output, not `parse config` errors)

- [ ] **Step 4: Verify `go vet` is clean**

```
go vet ./...
```
Expected: no output

- [ ] **Step 5: Commit**

```bash
git log --oneline -12
```
Verify the feature commits are clean, then done.
