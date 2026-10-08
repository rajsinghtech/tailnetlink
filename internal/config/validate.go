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
		host, _, err := src.Forwards()
		if err != nil {
			return fmt.Errorf("local_sources[%d]: %w", i, err)
		}
		if isLocalOrIP(host) && src.DNSName == "" {
			return fmt.Errorf("local_sources[%d]: addr %q requires dns_name (cannot derive from localhost/IP)", i, src.Addr)
		}
		if err := checkDNSZone(src.DNSName, src.DNSZone, fmt.Sprintf("local_sources[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

// splitLocalAddr parses a classic "host:port" addr. hasPort is true when
// addr has a port separator, even if that port is not a valid number.
func splitLocalAddr(addr string) (host string, port int, hasPort bool, err error) {
	h, p, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return "", 0, false, splitErr
	}
	n, convErr := strconv.Atoi(p)
	if convErr != nil || n <= 0 || n > 65535 {
		return h, 0, true, fmt.Errorf("addr %q has invalid port", addr)
	}
	return h, n, true, nil
}

// hostOnly accepts an addr with no port: a hostname, an IP, or a bracketed IP.
func hostOnly(addr string) (string, error) {
	host := addr
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") && len(host) >= 2 {
		inner := host[1 : len(host)-1]
		if _, err := netip.ParseAddr(inner); err != nil {
			return "", fmt.Errorf("missing port in address %s", addr)
		}
		host = inner
	}
	if strings.TrimSpace(host) == "" || strings.ContainsAny(host, " \t") {
		return "", fmt.Errorf("missing host")
	}
	if strings.Contains(host, ":") {
		if _, err := netip.ParseAddr(host); err != nil {
			return "", fmt.Errorf("missing port in address %s", addr)
		}
	}
	return host, nil
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
	host, _, err := l.Forwards()
	if err != nil {
		return "", err
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
// tailnet when the target exposes exactly one port: expose_port, or else
// the port in addr.
func (l LocalSourceSpec) EffectivePort() (int, error) {
	_, fw, err := l.Forwards()
	if err != nil {
		return 0, err
	}
	if len(fw) != 1 {
		return 0, fmt.Errorf("addr %q exposes %d ports", l.Addr, len(fw))
	}
	return fw[0].Expose, nil
}

// Forwards is the host to dial and each exposed VIP port with its backend
// port. A host:port addr yields one pair. A host plus ports yields one pair
// per configured port. expose_port, when set, is the single VIP port and the
// backend stays the port in addr.
func (l LocalSourceSpec) Forwards() (string, []LocalForward, error) {
	host, port, hasPort, splitErr := splitLocalAddr(l.Addr)
	if l.Ports.Configured() {
		fw, err := l.Ports.validated()
		if err != nil {
			return "", nil, err
		}
		if l.ExposePort != 0 {
			return "", nil, fmt.Errorf("expose_port cannot be combined with ports")
		}
		if hasPort {
			return "", nil, fmt.Errorf("addr %q has a port and also sets ports", l.Addr)
		}
		if splitErr != nil {
			var herr error
			host, herr = hostOnly(l.Addr)
			if herr != nil {
				return "", nil, fmt.Errorf("addr %q is invalid: %w", l.Addr, herr)
			}
		}
		if host == "" {
			return "", nil, fmt.Errorf("addr %q has no host", l.Addr)
		}
		return host, fw, nil
	}
	if splitErr != nil {
		if !hasPort {
			return "", nil, fmt.Errorf("addr %q is invalid: %w", l.Addr, splitErr)
		}
		return "", nil, splitErr
	}
	if host == "" {
		return "", nil, fmt.Errorf("addr %q has no host", l.Addr)
	}
	if l.ExposePort < 0 || l.ExposePort > 65535 {
		return "", nil, fmt.Errorf("expose_port %d is out of range", l.ExposePort)
	}
	expose := port
	if l.ExposePort > 0 {
		expose = l.ExposePort
	}
	return host, []LocalForward{{Expose: expose, Backend: port}}, nil
}
