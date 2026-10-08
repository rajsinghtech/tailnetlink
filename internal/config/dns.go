package config

import (
	"errors"
	"fmt"
	"strings"
)

// SplitHost returns the split-DNS zone for name and the label of name inside
// that zone. An empty zone keeps the historical split: the zone is the parent
// of name and the label is its first component ("app.corp.example.com" is
// label "app" in zone "corp.example.com"). A bare name is its own zone, with
// the label "@".
//
// A set zone must be name itself or a parent of name. When they are equal the
// label is "@", so the record sits at the apex and split-DNS is registered
// for that name only.
func SplitHost(name, zone string) (zoneName, label string, err error) {
	name, err = normalizeDNS(name)
	if err != nil {
		return "", "", fmt.Errorf("dns_name: %w", err)
	}
	if zone == "" {
		if dot := strings.IndexByte(name, '.'); dot >= 0 {
			return name[dot+1:], name[:dot], nil
		}
		return name, "@", nil
	}
	zone, err = normalizeDNS(zone)
	if err != nil {
		return "", "", fmt.Errorf("dns_zone: %w", err)
	}
	if err := validDNSName(name); err != nil {
		return "", "", fmt.Errorf("dns_name: %w", err)
	}
	if err := validDNSName(zone); err != nil {
		return "", "", fmt.Errorf("dns_zone: %w", err)
	}
	if strings.EqualFold(name, zone) {
		return zone, "@", nil
	}
	if strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(zone)) {
		rel := name[:len(name)-len(zone)-1]
		if rel == "" || strings.Contains(rel, "..") {
			return "", "", fmt.Errorf("dns_name %q is not inside dns_zone %q", name, zone)
		}
		return zone, rel, nil
	}
	return "", "", fmt.Errorf("dns_name %q must equal dns_zone %q or be a name inside it", name, zone)
}

func normalizeDNS(s string) (string, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", errors.New("empty name")
	}
	return s, nil
}

func validDNSName(s string) error {
	if len(s) > 253 {
		return fmt.Errorf("%q is too long", s)
	}
	for _, label := range strings.Split(s, ".") {
		if err := validDNSLabel(label); err != nil {
			return fmt.Errorf("%q: %w", s, err)
		}
	}
	return nil
}

func validDNSLabel(label string) error {
	if label == "" {
		return errors.New("empty label")
	}
	if len(label) > 63 {
		return fmt.Errorf("label %q is too long", label)
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' && i > 0 && i < len(label)-1:
		default:
			return fmt.Errorf("label %q has an invalid character", label)
		}
	}
	return nil
}
