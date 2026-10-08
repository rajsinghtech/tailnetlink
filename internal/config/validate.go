package config

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// validateBridges checks each bridge rule on its own, then that no two
// rules give the same short_name to services in one destination tailnet.
func (c *Config) validateBridges() error {
	seenRule := map[string]bool{}
	used := map[string]map[string]string{} // dest -> short_name -> rule
	for _, r := range c.Bridges {
		if err := r.validate(); err != nil {
			if r.Name == "" {
				return fmt.Errorf("bridge rule: %w", err)
			}
			return fmt.Errorf("bridge rule %q: %w", r.Name, err)
		}
		if seenRule[r.Name] {
			return fmt.Errorf("bridge rule %q is defined more than once", r.Name)
		}
		seenRule[r.Name] = true
		for _, dest := range r.DestTailnets {
			if _, ok := c.Tailnets[dest]; !ok {
				return fmt.Errorf("bridge rule %q: dest tailnet %q is not configured", r.Name, dest)
			}
			if used[dest] == nil {
				used[dest] = map[string]string{}
			}
			for _, sn := range r.shortNames() {
				if !shortNameRe.MatchString(sn) {
					return fmt.Errorf("bridge rule %q: short_name %q must be 1 to 63 lowercase letters, digits or dashes, starting and ending with a letter or digit", r.Name, sn)
				}
				if other, ok := used[dest][sn]; ok {
					if other == r.Name {
						return fmt.Errorf("bridge rule %q: short_name %q appears more than once for dest tailnet %q", r.Name, sn, dest)
					}
					return fmt.Errorf("bridge rule %q: short_name %q is already used by rule %q in dest tailnet %q", r.Name, sn, other, dest)
				}
				used[dest][sn] = r.Name
			}
		}
		if r.SourceTailnet != "" {
			if _, ok := c.Tailnets[r.SourceTailnet]; !ok {
				return fmt.Errorf("bridge rule %q: source tailnet %q is not configured", r.Name, r.SourceTailnet)
			}
		}
	}
	return nil
}

// shortNameRe is one DNS label, so svc:<short_name> is a valid service name.
var shortNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func (r BridgeRule) shortNames() []string {
	var out []string
	for _, d := range r.SourceDevices {
		if d.ShortName != "" {
			out = append(out, d.ShortName)
		}
	}
	for _, s := range r.SourceServices {
		if s.ShortName != "" {
			out = append(out, s.ShortName)
		}
	}
	for _, l := range r.LocalSources {
		if sn := l.EffectiveShortName(); sn != "" {
			out = append(out, sn)
		}
	}
	return out
}

func (r BridgeRule) validate() error {
	if r.Name == "" {
		return fmt.Errorf("name is required")
	}
	if len(r.DestTailnets) == 0 {
		return fmt.Errorf("dest_tailnets is required")
	}
	if len(r.LocalSources) > 0 {
		if r.SourceTailnet != "" || r.SourceTag != "" || len(r.SourceDevices) > 0 || len(r.SourceServices) > 0 || len(r.Ports) > 0 {
			return fmt.Errorf("local rules must not set source_tailnet, source_tag, source_devices, source_services, or ports")
		}
		return validateLocalSources(r.LocalSources)
	}
	if r.SourceTailnet == "" {
		return fmt.Errorf("source_tailnet is required for non-local rules")
	}
	if len(r.Ports) == 0 {
		return fmt.Errorf("ports is required for non-local rules")
	}
	for _, p := range r.Ports {
		if p <= 0 || p > 65535 {
			return fmt.Errorf("port %d is out of range", p)
		}
	}
	if r.SourceTag == "" && len(r.SourceDevices) == 0 && len(r.SourceServices) == 0 {
		return fmt.Errorf("either source_tag, source_devices, or source_services must be specified")
	}
	for i, d := range r.SourceDevices {
		if err := checkDNSZone(d.DNSName, d.DNSZone, fmt.Sprintf("source_devices[%d]", i)); err != nil {
			return err
		}
	}
	for i, s := range r.SourceServices {
		if err := checkDNSZone(s.DNSName, s.DNSZone, fmt.Sprintf("source_services[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

// checkDNSZone checks an optional split-DNS zone. With no zone the name is
// published under its parent, as before. A zone requires dns_name, and that
// name must be the zone or a name inside it.
func checkDNSZone(name, zone, where string) error {
	if strings.TrimSpace(zone) == "" {
		return nil
	}
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("%s: dns_zone requires dns_name", where)
	}
	if _, _, err := SplitHost(name, zone); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	return nil
}

func validateLocalSources(sources []LocalSourceSpec) error {
	for i, src := range sources {
		host, portStr, err := net.SplitHostPort(src.Addr)
		if err != nil {
			return fmt.Errorf("local_sources[%d].addr %q is invalid: %w", i, src.Addr, err)
		}
		if host == "" {
			return fmt.Errorf("local_sources[%d].addr %q has no host", i, src.Addr)
		}
		p, err := strconv.Atoi(portStr)
		if err != nil || p <= 0 || p > 65535 {
			return fmt.Errorf("local_sources[%d].addr %q has invalid port", i, src.Addr)
		}
		if src.ExposePort < 0 || src.ExposePort > 65535 {
			return fmt.Errorf("local_sources[%d].expose_port %d is out of range", i, src.ExposePort)
		}
		if isLocalOrIP(host) && src.DNSName == "" {
			return fmt.Errorf("local_sources[%d].addr %q requires dns_name (cannot derive from localhost/IP)", i, src.Addr)
		}
		if err := checkDNSZone(src.DNSName, src.DNSZone, fmt.Sprintf("local_sources[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

// isLocalOrIP reports whether host is localhost or a bare IP, which can't
// be turned into a service name.
func isLocalOrIP(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" {
		return true
	}
	_, err := netip.ParseAddr(h)
	return err == nil
}

// EffectiveDNSName is the name a local source is published under in the
// destination tailnet: dns_name, or else the host in addr. A localhost or
// bare-IP addr needs dns_name.
func (l LocalSourceSpec) EffectiveDNSName() (string, error) {
	if l.DNSName != "" {
		return l.DNSName, nil
	}
	host, _, err := net.SplitHostPort(l.Addr)
	if err != nil {
		return "", fmt.Errorf("invalid addr %q: %w", l.Addr, err)
	}
	if isLocalOrIP(host) {
		return "", fmt.Errorf("addr %q requires dns_name (cannot derive from localhost/IP)", l.Addr)
	}
	return host, nil
}

// EffectiveShortName is the bare service name for a local source:
// short_name, or else the first label of its DNS name, lower-cased.
func (l LocalSourceSpec) EffectiveShortName() string {
	if l.ShortName != "" {
		return l.ShortName
	}
	name, err := l.EffectiveDNSName()
	if err != nil {
		return ""
	}
	if dot := strings.IndexByte(name, '.'); dot > 0 {
		name = name[:dot]
	}
	return strings.ToLower(name)
}

// EffectivePort is the port the service listens on in the destination
// tailnet: expose_port, or else the port in addr.
func (l LocalSourceSpec) EffectivePort() (int, error) {
	if l.ExposePort < 0 || l.ExposePort > 65535 {
		return 0, fmt.Errorf("expose_port %d out of range", l.ExposePort)
	}
	if l.ExposePort > 0 {
		return l.ExposePort, nil
	}
	_, portStr, err := net.SplitHostPort(l.Addr)
	if err != nil {
		return 0, fmt.Errorf("invalid addr %q: %w", l.Addr, err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return 0, fmt.Errorf("invalid port in addr %q", l.Addr)
	}
	return p, nil
}
