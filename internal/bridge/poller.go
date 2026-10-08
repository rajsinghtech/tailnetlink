package bridge

import (
	"context"
	"maps"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	tsclient "tailscale.com/client/tailscale/v2"
)

// startJitter delays the first shared poll so borders that start together
// do not hit the API on the same tick. Tests set it to zero.
var startJitter = defaultStartJitter

func defaultStartJitter(interval time.Duration) time.Duration {
	span := interval / 5
	if span > 5*time.Second {
		span = 5 * time.Second
	}
	if span <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(span) + 1))
}

// nextInterval is the gap before the next shared poll: the base interval
// plus or minus 20 percent.
var nextInterval = defaultNextInterval

func defaultNextInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return interval
	}
	delta := interval / 5
	if delta <= 0 {
		return interval
	}
	j := time.Duration(rand.Int64N(int64(2*delta)+1)) - delta
	return interval + j
}

// sourcePoller lists devices and services once per interval for one tailnet
// and fans the lists out to every link subscribed to it.
type sourcePoller struct {
	m      *Manager
	name   string
	client *tsclient.Client
	base   time.Duration

	mu          sync.Mutex
	subs        map[*Discoverer]struct{}
	have        bool
	fetched     time.Time
	fetchedFull bool
	// fetchedServices is whether that poll listed VIP services. A later
	// tag or service link cannot reuse a device-only fetch.
	fetchedServices bool
	fetchedTags     []string
	devices         []tsclient.Device
	services        []tsclient.VIPService
	err             error
	dur             time.Duration

	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{} // closed when loop returns
	started   bool
	booting   bool
	polling   bool
	pollAgain bool
}

func (m *Manager) sharedPoller(name string, client *tsclient.Client, interval time.Duration) *sourcePoller {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pollers == nil {
		m.pollers = map[string]*sourcePoller{}
	}
	if p := m.pollers[name]; p != nil {
		return p
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &sourcePoller{
		m:      m,
		name:   name,
		client: client,
		base:   interval,
		subs:   map[*Discoverer]struct{}{},
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	m.pollers[name] = p
	return p
}

func (p *sourcePoller) subscribe(d *Discoverer) {
	p.mu.Lock()
	p.subs[d] = struct{}{}
	tags, full, _, needServices := p.planLocked()
	fresh := p.have && p.err == nil && time.Since(p.fetched) < p.base &&
		covers(p.fetchedTags, p.fetchedFull, tags, full) &&
		(!needServices || p.fetchedServices)
	devs, svcs, err, dur := p.devices, p.services, p.err, p.dur
	start := !p.started
	if start {
		p.started = true
		p.booting = true
	}
	p.mu.Unlock()
	if start {
		go p.loop()
	} else if !fresh {
		// While the first poll is booting, subscribers are already in the
		// set it will publish. An in-flight poll also refetches if its
		// result cannot satisfy whoever subscribed during the call.
		p.mu.Lock()
		booting, inFlight := p.booting, p.polling
		p.mu.Unlock()
		if !booting && !inFlight {
			go p.poll()
		}
	}
	if fresh {
		d.deliver(p.ctx, devs, svcs, err, dur)
	}
}

// covers reports whether a list fetched with fetchedTags (or the full list)
// is enough for a subscriber set that needs needTags or the full list.
func covers(fetchedTags []string, fetchedFull bool, needTags []string, needFull bool) bool {
	if needFull {
		return fetchedFull
	}
	if fetchedFull {
		return true
	}
	have := map[string]struct{}{}
	for _, t := range fetchedTags {
		have[t] = struct{}{}
	}
	for _, t := range needTags {
		if _, ok := have[t]; !ok {
			return false
		}
	}
	return true
}

func (p *sourcePoller) unsubscribe(d *Discoverer) {
	p.mu.Lock()
	delete(p.subs, d)
	empty := len(p.subs) == 0
	p.mu.Unlock()
	if !empty {
		return
	}
	p.cancel()
	// The loop reads startJitter and may still be inside a poll. Wait so a
	// caller that then swaps those hooks does not race the goroutine.
	if p.done != nil {
		<-p.done
	}
	p.m.mu.Lock()
	if p.m.pollers[p.name] == p {
		delete(p.m.pollers, p.name)
	}
	p.m.mu.Unlock()
}

func (p *sourcePoller) loop() {
	defer close(p.done)
	if d := startJitter(p.base); d > 0 {
		t := time.NewTimer(d)
		select {
		case <-p.ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
	p.poll()
	p.mu.Lock()
	p.booting = false
	p.mu.Unlock()
	for {
		t := time.NewTimer(nextInterval(p.base))
		select {
		case <-p.ctx.Done():
			t.Stop()
			return
		case <-t.C:
			p.poll()
		}
	}
}

func (p *sourcePoller) poll() {
	if p.ctx.Err() != nil {
		return
	}
	p.mu.Lock()
	if p.polling {
		p.pollAgain = true
		p.mu.Unlock()
		return
	}
	p.polling = true
	tags, fullDevices, needDevices, needServices := p.planLocked()
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.polling = false
		again := p.pollAgain
		p.pollAgain = false
		p.mu.Unlock()
		if again && p.ctx.Err() == nil {
			p.poll()
		}
	}()
	if !needDevices && !needServices {
		return
	}
	start := time.Now()
	var devs []tsclient.Device
	var svcs []tsclient.VIPService
	var err error
	if needDevices {
		if fullDevices {
			devs, err = p.client.Devices().List(p.ctx)
		} else {
			devs, err = p.client.Devices().List(p.ctx, tsclient.WithFilter("tags", tags))
		}
	}
	if err == nil && needServices {
		svcs, err = p.client.VIPServices().List(p.ctx)
	}
	dur := time.Since(start)
	p.mu.Lock()
	p.devices, p.services, p.err, p.dur, p.fetched, p.have = devs, svcs, err, dur, time.Now(), true
	p.fetchedFull, p.fetchedTags = fullDevices, append([]string(nil), tags...)
	p.fetchedServices = err == nil && needServices
	newTags, newFull, _, newServices := p.planLocked()
	if !covers(tags, fullDevices, newTags, newFull) || (newServices && !needServices) {
		p.pollAgain = true
	}
	subs := make([]*Discoverer, 0, len(p.subs))
	for d := range p.subs {
		subs = append(subs, d)
	}
	p.mu.Unlock()
	for _, d := range subs {
		d.deliver(p.ctx, devs, svcs, err, dur)
	}
}

// planLocked decides what this poll has to ask for. A server-side tag
// filter is used only when every subscriber selects devices by tag. The
// admin client documents tags as a device-list filter. A device-mode link,
// which matches by name, needs the unfiltered list.
func (p *sourcePoller) planLocked() (tags []string, fullDevices, needDevices, needServices bool) {
	tagset := map[string]struct{}{}
	for d := range p.subs {
		switch {
		case d.services != nil:
			needServices = true
		case d.devices != nil:
			needDevices = true
			fullDevices = true
		default:
			needDevices = true
			needServices = true
			if d.tag != "" {
				tagset[d.tag] = struct{}{}
			} else {
				fullDevices = true
			}
		}
	}
	if fullDevices || len(tagset) == 0 {
		return nil, fullDevices, needDevices, needServices
	}
	return slices.Sorted(maps.Keys(tagset)), false, needDevices, needServices
}
