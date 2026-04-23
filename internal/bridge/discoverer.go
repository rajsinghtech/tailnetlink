package bridge

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
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
type Discoverer struct {
	client   *tsclient.Client
	tag      string
	devices  map[string]struct{} // explicit FQDNs (lower-cased); non-nil means device mode
	services map[string]struct{} // explicit VIP service names; non-nil means service mode
	poll     time.Duration
	logger   *slog.Logger
	warnFn   func(string) // called with user-facing warning messages (e.g. "no match for tag")

	current map[string]Device // keyed by node ID or service name
	added   chan Device
	removed chan Device
}

func NewDiscoverer(client *tsclient.Client, tag string, deviceFQDNs []string, serviceNames []string, poll time.Duration, logger *slog.Logger) *Discoverer {
	d := &Discoverer{
		client:  client,
		tag:     tag,
		poll:    poll,
		logger:  logger,
		current: make(map[string]Device),
		added:   make(chan Device, 16),
		removed: make(chan Device, 16),
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
	if d.services != nil {
		d.pollServices(ctx)
		return
	}
	devices, err := d.client.Devices().List(ctx)
	if err != nil {
		d.logger.Warn("discoverer: list devices failed", "err", err)
		return
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
			if !hasTag(dev.Tags, d.tag) {
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
			d.logger.Warn("discoverer: list vip services failed (tag mode)", "err", err)
		} else {
			for _, svc := range svcs {
				if !hasTag(svc.Tags, d.tag) {
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

	d.diffAndNotify(found, "device/service")
}

func (d *Discoverer) pollServices(ctx context.Context) {
	svcs, err := d.client.VIPServices().List(ctx)
	if err != nil {
		d.logger.Warn("discoverer: list vip services failed", "err", err)
		return
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
	d.diffAndNotify(found, "vip service")
}

func (d *Discoverer) diffAndNotify(found map[string]Device, kind string) {
	for id, dev := range found {
		if _, seen := d.current[id]; !seen {
			d.logger.Info("discoverer: "+kind+" added", "name", dev.Name, "ip", dev.IP)
			select {
			case d.added <- dev:
			default:
			}
		}
	}
	for id, dev := range d.current {
		if _, still := found[id]; !still {
			d.logger.Info("discoverer: "+kind+" removed", "name", dev.Name)
			select {
			case d.removed <- dev:
			default:
			}
		}
	}
	d.current = found
}

func hasTag(tags []string, want string) bool {
	return slices.Contains(tags, want)
}
