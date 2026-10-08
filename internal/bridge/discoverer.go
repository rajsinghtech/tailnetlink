package bridge

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	tsclient "tailscale.com/client/tailscale/v2"
)

// Device is a discovered source-tailnet device.
type Device struct {
	Name string
	FQDN string
	IP   netip.Addr
	Tags []string
}

// Discoverer polls the Tailscale API to find devices matching a tag, explicit FQDN list,
// or explicit VIP service name list. When source_tag is set it always drives discovery;
// source_devices/source_services only act as DNS/name overrides in that case.
// Without a tag: source_services takes priority, then source_devices.
//
// Tag mode never picks up tailnetlink's own output: services carrying the
// tailnetlink/managed annotation and tailnetlink's own nodes are skipped,
// so two instances bridging A to B and B to A with the same tag don't loop.
//
// Every change is announced: sends block until the rule reads them or ctx
// is done, and a device only counts as seen once its add went out.
type Discoverer struct {
	client   *tsclient.Client
	tag      string
	devices  map[string]struct{} // explicit FQDNs (lower-cased); non-nil means device mode
	services map[string]struct{} // explicit VIP service names; non-nil means service mode
	poll     time.Duration
	logger   *slog.Logger
	warnFn   func(string)               // called with user-facing warning messages (e.g. "no match for tag")
	onPoll   func(time.Duration, error) // called after every poll, if set
	// onSnapshot, when set, receives the full desired set keyed by FQDN
	// after a poll that produced one. Add and remove events are not sent.
	// A name leaves that set only after it has been absent for
	// removeAfterPolls polls or removeAfter, and at most maxDeletes names
	// leave in one poll.
	onSnapshot func(map[string]Device)

	current map[string]Device // keyed by node ID or service name
	added   chan Device
	removed chan Device

	// Snapshot-mode memory. stable is the set last published. absent tracks
	// names that dropped out of a successful poll and are not yet removable.
	stable map[string]Device
	absent map[string]absenceRec

	// Zero values use the defaults below. Tests set them.
	removeAfterPolls int
	removeAfter      time.Duration
	maxDeletes       int
	nowFn            func() time.Time
}

// A name is removed only after this many missed polls or this long,
// whichever comes first, and a poll deletes at most defaultMaxDeletes names.
const (
	defaultRemoveAfterPolls = 3
	defaultRemoveAfter      = 2 * time.Minute
	defaultMaxDeletes       = 50
)

type absenceRec struct {
	since time.Time
	polls int
	dev   Device
}

func NewDiscoverer(client *tsclient.Client, tag string, deviceFQDNs []string, serviceNames []string, poll time.Duration, logger *slog.Logger) *Discoverer {
	d := &Discoverer{
		client:           client,
		tag:              tag,
		poll:             poll,
		logger:           logger,
		current:          make(map[string]Device),
		added:            make(chan Device, 16),
		removed:          make(chan Device, 16),
		stable:           map[string]Device{},
		absent:           map[string]absenceRec{},
		removeAfterPolls: defaultRemoveAfterPolls,
		removeAfter:      defaultRemoveAfter,
		maxDeletes:       defaultMaxDeletes,
	}
	// When source_tag is present, tag-mode drives discovery and explicit lists
	// are only consulted for DNS/name overrides — don't switch modes.
	if tag == "" {
		if len(serviceNames) > 0 {
			d.services = make(map[string]struct{}, len(serviceNames))
			for _, name := range serviceNames {
				d.services[name] = struct{}{}
			}
		} else if len(deviceFQDNs) > 0 {
			d.devices = make(map[string]struct{}, len(deviceFQDNs))
			for _, fqdn := range deviceFQDNs {
				d.devices[strings.ToLower(fqdn)] = struct{}{}
			}
		}
	}
	return d
}

func (d *Discoverer) OnWarn(fn func(string)) { d.warnFn = fn }

func (d *Discoverer) Added() <-chan Device   { return d.added }
func (d *Discoverer) Removed() <-chan Device { return d.removed }

func (d *Discoverer) Run(ctx context.Context) {
	d.poll1(ctx)
	ticker := time.NewTicker(d.poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.poll1(ctx)
		}
	}
}

func (d *Discoverer) poll1(ctx context.Context) {
	start := time.Now()
	var err error
	if d.services != nil {
		err = d.pollServices(ctx)
	} else {
		err = d.pollDevices(ctx)
	}
	if d.onPoll != nil && ctx.Err() == nil {
		d.onPoll(time.Since(start), err)
	}
}

func (d *Discoverer) pollDevices(ctx context.Context) error {
	devices, err := d.client.Devices().List(ctx)
	if err != nil {
		d.logger.Warn("discoverer: list devices failed", "err", err)
		return err
	}

	found := make(map[string]Device)
	allTags := make(map[string]struct{})
	var noIPNames []string

	for _, dev := range devices {
		if d.devices != nil {
			// device mode: match by FQDN
			if _, ok := d.devices[strings.ToLower(dev.Name)]; !ok {
				continue
			}
		} else {
			// tag mode: collect all seen tags for diagnostic messages
			for _, t := range dev.Tags {
				allTags[t] = struct{}{}
			}
			if !hasTag(dev.Tags, d.tag) || isTailnetlinkNode(dev.Hostname) {
				continue
			}
		}

		ip, ok := firstIP(dev.Addresses)
		if !ok {
			d.logger.Debug("discoverer: device has no routable IP, skipping", "device", dev.Name, "addrs", dev.Addresses)
			if d.devices == nil {
				noIPNames = append(noIPNames, dev.Hostname)
			}
			continue
		}
		found[dev.NodeID] = Device{
			Name: dev.Hostname,
			FQDN: dev.Name,
			IP:   ip,
			Tags: dev.Tags,
		}
	}

	// In tag mode, also discover VIP services with the same tag.
	var matchedSvcs int
	if d.devices == nil && d.tag != "" {
		svcs, err := d.client.VIPServices().List(ctx)
		if err != nil {
			// A device list succeeded and the service list did not. Publishing
			// that partial set would look like every service disappeared.
			d.logger.Warn("discoverer: list vip services failed (tag mode)", "err", err)
			return err
		}
		for _, svc := range svcs {
			if !hasTag(svc.Tags, d.tag) || svc.Annotations[annotationManaged] == "true" {
				continue
			}
			ip, ok := firstIP(svc.Addrs)
			if !ok {
				d.logger.Debug("discoverer: vip service has no routable IP, skipping", "service", svc.Name)
				continue
			}
			found[svc.Name] = Device{
				Name: svc.Name,
				FQDN: svc.Name,
				IP:   ip,
				Tags: svc.Tags,
			}
			matchedSvcs++
		}
	}

	if d.devices != nil {
		d.logger.Info("discoverer: poll (device mode)", "wanted", len(d.devices), "online", len(found))
	} else if len(devices) > 0 && len(found) == 0 {
		var msg string
		if len(noIPNames) > 0 {
			msg = fmt.Sprintf("devices with tag %q have no routable IP address (devices: %v)", d.tag, noIPNames)
		} else {
			tags := make([]string, 0, len(allTags))
			for t := range allTags {
				tags = append(tags, t)
			}
			msg = fmt.Sprintf("no devices or services with tag %q in source tailnet (available tags: %v)", d.tag, tags)
		}
		d.logger.Warn("discoverer: " + msg)
		if d.warnFn != nil {
			d.warnFn(msg)
		}
	} else {
		d.logger.Info("discoverer: poll", "tag", d.tag, "total_devices", len(devices), "matched_devices", len(found)-matchedSvcs, "matched_services", matchedSvcs)
	}

	d.commit(ctx, found, "device/service")
	return nil
}

func (d *Discoverer) pollServices(ctx context.Context) error {
	svcs, err := d.client.VIPServices().List(ctx)
	if err != nil {
		d.logger.Warn("discoverer: list vip services failed", "err", err)
		return err
	}

	found := make(map[string]Device)
	for _, svc := range svcs {
		if _, ok := d.services[svc.Name]; !ok {
			continue
		}
		ip, ok := firstIP(svc.Addrs)
		if !ok {
			d.logger.Debug("discoverer: vip service has no routable IP, skipping", "service", svc.Name, "addrs", svc.Addrs)
			continue
		}
		found[svc.Name] = Device{
			Name: svc.Name,
			FQDN: svc.Name,
			IP:   ip,
			Tags: svc.Tags,
		}
	}

	d.logger.Info("discoverer: poll (service mode)", "wanted", len(d.services), "online", len(found))
	d.commit(ctx, found, "vip service")
	return nil
}

// commit publishes found. With a snapshot consumer the whole set is the
// desired state, keyed by FQDN so a re-registered node (new id, same name)
// is an update rather than a removal plus an add. Without one, the
// per-event channels are used and tests can read them.
func (d *Discoverer) commit(ctx context.Context, found map[string]Device, kind string) {
	if d.onSnapshot == nil {
		d.diffAndNotify(ctx, found, kind)
		return
	}
	if ctx.Err() != nil {
		return
	}
	live := make(map[string]Device, len(found))
	for _, dev := range found {
		live[dev.FQDN] = copyDevice(dev)
	}
	d.onSnapshot(d.retain(live))
}

// retain keeps a name that disappeared until it has been gone for enough
// polls or long enough, and lets at most maxDeletes names go in one poll.
// The input and the result are keyed by FQDN.
func (d *Discoverer) retain(live map[string]Device) map[string]Device {
	if d.absent == nil {
		d.absent = map[string]absenceRec{}
	}
	if d.stable == nil {
		d.stable = map[string]Device{}
	}
	pollsN := d.removeAfterPolls
	if pollsN <= 0 {
		pollsN = defaultRemoveAfterPolls
	}
	wait := d.removeAfter
	if wait <= 0 {
		wait = defaultRemoveAfter
	}
	capN := d.maxDeletes
	if capN <= 0 {
		capN = defaultMaxDeletes
	}
	now := time.Now()
	if d.nowFn != nil {
		now = d.nowFn()
	}
	for fqdn := range live {
		delete(d.absent, fqdn)
	}
	for fqdn, dev := range d.stable {
		if _, ok := live[fqdn]; ok {
			continue
		}
		rec := d.absent[fqdn]
		if rec.since.IsZero() {
			rec.since = now
		}
		rec.polls++
		rec.dev = dev
		d.absent[fqdn] = rec
	}
	eligible := make([]string, 0, len(d.absent))
	for fqdn, rec := range d.absent {
		if rec.polls >= pollsN || now.Sub(rec.since) >= wait {
			eligible = append(eligible, fqdn)
		}
	}
	sort.Strings(eligible)
	if len(eligible) > capN {
		eligible = eligible[:capN]
	}
	for _, fqdn := range eligible {
		delete(d.absent, fqdn)
	}
	out := make(map[string]Device, len(live)+len(d.absent))
	for fqdn, dev := range live {
		out[fqdn] = dev
	}
	for fqdn, rec := range d.absent {
		out[fqdn] = rec.dev
	}
	d.stable = out
	return out
}

// diffAndNotify announces what changed between the last poll and found. It
// blocks until each event is taken or ctx is done. d.current only changes
// for events that went out, so anything not announced before ctx ended is
// still a difference next time.
func (d *Discoverer) diffAndNotify(ctx context.Context, found map[string]Device, kind string) {
	for id, dev := range found {
		if _, seen := d.current[id]; seen {
			continue
		}
		d.logger.Info("discoverer: "+kind+" added", "name", dev.Name, "ip", dev.IP)
		select {
		case d.added <- dev:
			d.current[id] = dev
		case <-ctx.Done():
			return
		}
	}
	for id, dev := range d.current {
		if _, still := found[id]; still {
			continue
		}
		d.logger.Info("discoverer: "+kind+" removed", "name", dev.Name)
		select {
		case d.removed <- dev:
			delete(d.current, id)
		case <-ctx.Done():
			return
		}
	}
}

// isTailnetlinkNode reports whether a device is one of tailnetlink's own
// nodes, which are named tailnetlink-<tailnet>.
func isTailnetlinkNode(hostname string) bool {
	return strings.HasPrefix(hostname, "tailnetlink-")
}

func hasTag(tags []string, want string) bool {
	return slices.Contains(tags, want)
}
