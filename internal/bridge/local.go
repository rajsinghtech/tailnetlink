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
	if spec.ExposePort > 0 && spec.ExposePort <= 65535 {
		return spec.ExposePort, nil
	}
	if spec.ExposePort != 0 {
		return 0, fmt.Errorf("expose_port %d out of range", spec.ExposePort)
	}
	_, portStr, err := net.SplitHostPort(spec.Addr)
	if err != nil {
		return 0, fmt.Errorf("invalid addr %q: %w", spec.Addr, err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return 0, fmt.Errorf("invalid port in addr %q", spec.Addr)
	}
	return p, nil
}
