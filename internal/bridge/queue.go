package bridge

import (
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	"tailscale.com/tsnet"
)

// reconcileWorkers is how many VIPs one rule provisions at once. Each worker
// runs one service name at a time, so this is also the cap on concurrent
// destination API calls from that rule.
const reconcileWorkers = 8

// retryDelay is the wait before a failed converge is tried again.
// Exponential in the attempt, capped, plus jitter. Tests replace it.
var retryDelay = func(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	shift := attempt - 1
	if shift > 9 {
		shift = 9
	}
	d := 100 * time.Millisecond << shift
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d + time.Duration(rand.Int64N(int64(d/2)+1))
}

// qItem is the desired state of one service name on one destination.
// present means the VIP should exist; otherwise it should be removed.
type qItem struct {
	dev      Device
	dest     string
	bridgeID string
	present  bool
	gen      uint64
	attempt  int
	created  time.Time
}

// reconcileQueue converges a set of service names. Work for one key never
// overlaps, and a failed key stays desired until it succeeds.
type reconcileQueue struct {
	workers int
	apply   func(context.Context, qItem) error

	mu      sync.Mutex
	desired map[string]*qItem
	settled map[string]uint64
	running map[string]bool
	ready   map[string]time.Time
	wake    chan struct{}
	wg      sync.WaitGroup
}

func newReconcileQueue(workers int, apply func(context.Context, qItem) error) *reconcileQueue {
	if workers < 1 {
		workers = 1
	}
	return &reconcileQueue{
		workers: workers,
		apply:   apply,
		desired: map[string]*qItem{},
		settled: map[string]uint64{},
		running: map[string]bool{},
		ready:   map[string]time.Time{},
		wake:    make(chan struct{}, 1),
	}
}

func (q *reconcileQueue) start(ctx context.Context) {
	for range q.workers {
		q.wg.Add(1)
		go func() {
			defer q.wg.Done()
			for {
				key, ok := q.claim(ctx)
				if !ok {
					return
				}
				q.runOne(ctx, key)
			}
		}()
	}
}

// Replace sets the desired services. Keys absent from want are removals.
// A key whose device did not change is left on its current schedule, so a
// poll does not restamp backoff for something already retrying.
func (q *reconcileQueue) Replace(want map[string]qItem) {
	q.mu.Lock()
	changed := false
	seen := make(map[string]bool, len(want))
	for key, sp := range want {
		seen[key] = true
		cur := q.desired[key]
		if cur != nil && cur.present && sameDevice(cur.dev, sp.dev) {
			continue
		}
		item := sp
		item.present = true
		item.gen = 1
		item.attempt = 0
		item.created = time.Now()
		if cur != nil {
			item.gen = cur.gen + 1
			item.created = cur.created
		}
		q.desired[key] = &item
		delete(q.settled, key)
		q.ready[key] = time.Time{}
		changed = true
	}
	for key, cur := range q.desired {
		if seen[key] || !cur.present {
			continue
		}
		cur.present = false
		cur.gen++
		cur.attempt = 0
		delete(q.settled, key)
		q.ready[key] = time.Time{}
		changed = true
	}
	q.mu.Unlock()
	if changed {
		q.kick()
	}
}

func (q *reconcileQueue) kick() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *reconcileQueue) claim(ctx context.Context) (string, bool) {
	for {
		if ctx.Err() != nil {
			return "", false
		}
		q.mu.Lock()
		now := time.Now()
		var next time.Time
		var key string
		for k, when := range q.ready {
			if q.running[k] {
				continue
			}
			if when.After(now) {
				if next.IsZero() || when.Before(next) {
					next = when
				}
				continue
			}
			key = k
			break
		}
		if key != "" {
			q.running[key] = true
			delete(q.ready, key)
			q.mu.Unlock()
			return key, true
		}
		q.mu.Unlock()

		if next.IsZero() {
			select {
			case <-ctx.Done():
				return "", false
			case <-q.wake:
			}
			continue
		}
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", false
		case <-q.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
		}
	}
}

func (q *reconcileQueue) runOne(ctx context.Context, key string) {
	defer func() {
		q.mu.Lock()
		delete(q.running, key)
		q.mu.Unlock()
		q.kick()
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		q.mu.Lock()
		item := q.desired[key]
		if item == nil {
			q.mu.Unlock()
			return
		}
		cur := *item
		settled := q.settled[key] == cur.gen
		q.mu.Unlock()
		if settled {
			return
		}
		err := q.apply(ctx, cur)
		q.mu.Lock()
		now := q.desired[key]
		if now == nil || now.gen != cur.gen {
			q.mu.Unlock()
			continue
		}
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) {
				q.mu.Unlock()
				return
			}
			now.attempt = cur.attempt + 1
			q.ready[key] = time.Now().Add(retryDelay(now.attempt))
			q.mu.Unlock()
			return
		}
		q.settled[key] = cur.gen
		if !cur.present {
			delete(q.desired, key)
		}
		q.mu.Unlock()
		return
	}
}

func sameDevice(a, b Device) bool {
	return a.FQDN == b.FQDN && a.Name == b.Name && a.IP == b.IP && slices.Equal(a.Tags, b.Tags)
}

func copyDevice(d Device) Device {
	d.Tags = slices.Clone(d.Tags)
	return d
}

// specsFor is the desired set for one discovery snapshot: one key per
// destination and service name.
func specsFor(rule config.BridgeRule, dests []destCtx, found map[string]Device) map[string]qItem {
	out := make(map[string]qItem, len(found)*len(dests))
	for _, dev := range found {
		dev = copyDevice(dev)
		svc := ServiceName(rule.SourceTailnet, dev.FQDN, shortNameFor(rule, dev.FQDN))
		for _, dest := range dests {
			out[dest.name+"/"+svc] = qItem{
				dev:      dev,
				dest:     dest.name,
				bridgeID: rule.Name + "/" + dest.name + "/" + dev.FQDN,
				present:  true,
			}
		}
	}
	return out
}

// converge makes one service name on one destination match item.present.
// A failure leaves the VIP in place so the queue can try again; the name
// stays desired until this returns nil.
func (m *Manager) converge(ctx context.Context, rule config.BridgeRule, dest destCtx, srcSrv *tsnet.Server, dialTimeout time.Duration, item qItem) error {
	dev := item.dev
	shortName := shortNameFor(rule, dev.FQDN)
	svcName := ServiceName(rule.SourceTailnet, dev.FQDN, shortName)
	if !item.present {
		m.mu.Lock()
		if fwd, ok := m.forwarders[item.bridgeID]; ok {
			fwd.Stop()
			delete(m.forwarders, item.bridgeID)
		}
		cleanup := m.dnsCleanups[item.bridgeID]
		delete(m.dnsCleanups, item.bridgeID)
		m.mu.Unlock()
		if cleanup != nil {
			cleanup(true)
		}
		m.forgetVIP(dest.name, svcName)
		if err := dest.rec.Delete(ctx, rule.SourceTailnet, dev, shortName); err != nil {
			m.logger.Error("reconciler: delete failed", "rule", rule.Name, "dest", dest.name, "device", dev.Name, "err", err)
			m.store.Log("error", "bridge cleanup failed for "+dev.Name+": "+err.Error(), nil)
			return err
		}
		m.store.DeleteBridge(item.bridgeID)
		m.store.Log("info", "["+rule.Name+"] bridge removed: "+dev.Name, nil)
		return nil
	}

	m.mu.Lock()
	running := m.forwarders[item.bridgeID]
	m.mu.Unlock()
	if running != nil && running.vip != nil && running.vip.SourceIP == dev.IP {
		return nil
	}

	base := state.BridgeEntry{
		ID: item.bridgeID, RuleName: rule.Name, DestTailnet: dest.name,
		ServiceName: svcName, SourceHost: dev.Name, SourceIP: dev.IP.String(),
		Ports: slices.Clone(rule.Ports), CreatedAt: item.created,
	}
	pending := base
	pending.Status = state.BridgeStatusPending
	m.store.UpsertBridge(pending)

	vip, err := dest.rec.Ensure(ctx, rule.SourceTailnet, dev, shortName)
	if err != nil {
		m.conflict(dest.name, err)
		m.logger.Error("reconciler: ensure failed", "rule", rule.Name, "dest", dest.name, "device", dev.Name, "err", err)
		failed := base
		failed.Status = state.BridgeStatusError
		failed.Error = err.Error()
		m.store.UpsertBridge(failed)
		m.store.Log("error", "["+rule.Name+"] bridge failed for "+dev.Name+": "+err.Error(), nil)
		return err
	}
	vip.SourceIP = dev.IP

	if running != nil {
		m.stopBridge(item.bridgeID, false)
	}

	fwd := NewForwarder(dest.srv, srcSrv, vip, item.bridgeID, dialTimeout, m.store, m.logger)
	fwd.rule, fwd.metrics, fwd.authz = rule.Name, m.metricsRef(), rule.Authz
	if err := startForwarder(fwd, ctx); err != nil {
		// Keep the VIP. The name stays desired and the queue tries again.
		m.dropAdvertised(dest.name, vip.ServiceName)
		m.logger.Error("forwarder: start failed", "rule", rule.Name, "dest", dest.name, "device", dev.Name, "err", err)
		failed := base
		failed.ServiceName = vip.ServiceName
		failed.Status = state.BridgeStatusError
		failed.Error = err.Error()
		m.store.UpsertBridge(failed)
		return err
	}

	active := base
	active.ServiceName = vip.ServiceName
	active.DestVIP = vip.VIP.String()
	active.Status = state.BridgeStatusActive
	m.store.UpsertBridge(active)
	m.store.Log("info", "["+rule.Name+"] bridge active: "+dev.Name, nil)

	if vip.VIP.IsValid() {
		m.mu.Lock()
		srcDomain := ""
		if m.cfg != nil {
			srcDomain = m.cfg.Tailnets[rule.SourceTailnet].Tailnet
		}
		m.mu.Unlock()
		m.startDeviceDNS(ctx, item.bridgeID, rule.Name, srcDomain, dev.FQDN, "", dnsNameFor(rule, dev.FQDN), dnsZoneFor(rule, dev.FQDN), vip.VIP, dest)
	}
	m.mu.Lock()
	m.forwarders[item.bridgeID] = fwd
	m.mu.Unlock()
	return nil
}
