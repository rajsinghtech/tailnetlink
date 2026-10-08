package config

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
)

// Mesh is one process that joins each named tailnet once and bridges them
// in any direction. The same node dials for bridges that leave a tailnet
// and hosts VIP services for bridges that arrive there.
//
// Tailnet keys are the node names. Two keys may not name the same tailnet.
// bridges list the directions: from one key, to one or more other keys,
// with the same link fields a border uses.
type Mesh struct {
	// Name identifies this process. It is the owner written to every VIP
	// service it creates, and part of its node hostnames.
	Name string `json:"name"`

	Tailnets map[string]MeshTailnet `json:"tailnets"`
	Bridges  []MeshBridge           `json:"bridges"`

	Node    NodeConfig    `json:"node,omitzero"`
	DNS     DNSConfig     `json:"dns,omitzero"`
	UI      BorderUI      `json:"ui,omitzero"`
	Metrics MetricsConfig `json:"metrics,omitzero"`

	PollInterval  *Duration `json:"poll_interval,omitempty"`
	DialTimeout   *Duration `json:"dial_timeout,omitempty"`
	AuthKeyExpiry *Duration `json:"auth_key_expiry,omitempty"`

	// Authz is the default authorization for every link. A link or a
	// destination tailnet may set its own.
	Authz AuthzConfig `json:"authz,omitzero"`
}

// MeshTailnet is one tailnet the process joins. node.ephemeral on a tailnet
// turns that node ephemeral. node.state_dir is not per tailnet: the process
// has one state directory, and each node lives in a subdirectory named for
// its key. dns.enabled false turns split-DNS off for services published
// into this tailnet. A top-level dns.enabled false wins over a per-tailnet
// true, because the process-wide switch is off.
type MeshTailnet struct {
	Side
	Node  NodeConfig  `json:"node,omitzero"`
	DNS   *DNSConfig  `json:"dns,omitempty"`
	Authz AuthzConfig `json:"authz,omitzero"`
}

// MeshBridge is every link from one tailnet key to one or more others.
// Links use the same fields as a border link.
type MeshBridge struct {
	From  string   `json:"from"`
	To    []string `json:"to"`
	Links []Link   `json:"links"`
}

// Compile checks the mesh and turns it into a Config. One tailnet key is
// one node. Each link becomes a bridge rule named from/link, published to
// every key in to. An empty bridges list is allowed: the nodes still join.
func (m *Mesh) Compile() (*Config, error) {
	if m.Name == "" {
		return nil, errors.New("name is required: pick a short name for this mesh, for example \"home-work\"")
	}
	if !borderNameRe.MatchString(m.Name) {
		return nil, fmt.Errorf("name %q must be 1 to 40 lowercase letters, digits or dashes, starting and ending with a letter or digit", m.Name)
	}
	if len(m.Tailnets) == 0 {
		return nil, errors.New("tailnets is required")
	}
	if err := m.Authz.validate(); err != nil {
		return nil, err
	}

	cfg := defaults()
	cfg.InstanceID = m.Name
	cfg.SharedNodes = true
	cfg.StateDir = m.Node.StateDir
	cfg.DNSDisabled = m.DNS.Enabled != nil && !*m.DNS.Enabled
	cfg.UI = UIConfig{ServiceName: m.UI.ServiceName, Enabled: m.UI.Enabled}
	if m.UI.ListenAddr != "" {
		cfg.ListenAddr = m.UI.ListenAddr
	}
	if m.Metrics.ListenAddr != "" {
		cfg.MetricsAddr = m.Metrics.ListenAddr
	}
	for _, d := range []struct {
		name string
		in   *Duration
		out  *Duration
		min  time.Duration
	}{
		{"poll_interval", m.PollInterval, &cfg.PollInterval, 100 * time.Millisecond},
		{"dial_timeout", m.DialTimeout, &cfg.DialTimeout, 100 * time.Millisecond},
		{"auth_key_expiry", m.AuthKeyExpiry, &cfg.AuthKeyExpiry, time.Minute},
	} {
		if d.in == nil {
			continue
		}
		if d.in.Duration < d.min {
			return nil, fmt.Errorf("%s %s is too short (minimum %s)", d.name, d.in.Duration, d.min)
		}
		*d.out = *d.in
	}

	seenTailnet := map[string]string{}
	for _, key := range slices.Sorted(maps.Keys(m.Tailnets)) {
		tn := m.Tailnets[key]
		if !borderNameRe.MatchString(key) {
			return nil, fmt.Errorf("tailnet key %q must be 1 to 40 lowercase letters, digits or dashes, starting and ending with a letter or digit", key)
		}
		if tn.Node.StateDir != "" {
			return nil, fmt.Errorf("tailnet %q: set node.state_dir once, on the top-level node", key)
		}
		if err := tn.check(); err != nil {
			return nil, fmt.Errorf("tailnet %q: %w", key, err)
		}
		if err := tn.Authz.validate(); err != nil {
			return nil, fmt.Errorf("tailnet %q: %w", key, err)
		}
		id := strings.ToLower(strings.TrimSpace(tn.Tailnet))
		if other, ok := seenTailnet[id]; ok {
			return nil, fmt.Errorf("tailnet %q is configured more than once (keys %q and %q)", tn.Tailnet, other, key)
		}
		seenTailnet[id] = key
		tc := tn.tailnet(m.Node.Ephemeral || tn.Node.Ephemeral)
		tc.Role = "node"
		tc.Authz = tn.Authz
		tc.DNSDisabled = cfg.DNSDisabled || (tn.DNS != nil && tn.DNS.Enabled != nil && !*tn.DNS.Enabled)
		cfg.Tailnets[key] = tc
	}

	linkSeen := map[string]map[string]bool{}
	for i, b := range m.Bridges {
		if b.From == "" {
			return nil, fmt.Errorf("bridges[%d]: from is required", i)
		}
		if _, ok := m.Tailnets[b.From]; !ok {
			return nil, fmt.Errorf("bridges[%d]: from %q is not a tailnet key", i, b.From)
		}
		if len(b.To) == 0 {
			return nil, fmt.Errorf("bridge from %q: to is required", b.From)
		}
		if len(b.Links) == 0 {
			return nil, fmt.Errorf("bridge from %q: links is empty", b.From)
		}
		seenTo := map[string]bool{}
		for _, to := range b.To {
			if to == b.From {
				return nil, fmt.Errorf("bridge from %q: to includes itself", b.From)
			}
			if _, ok := m.Tailnets[to]; !ok {
				return nil, fmt.Errorf("bridge from %q: to %q is not a tailnet key", b.From, to)
			}
			if seenTo[to] {
				return nil, fmt.Errorf("bridge from %q: to %q is duplicated", b.From, to)
			}
			seenTo[to] = true
		}
		if linkSeen[b.From] == nil {
			linkSeen[b.From] = map[string]bool{}
		}
		for j, l := range b.Links {
			rule, err := l.rule(b.From, b.To, m.Authz)
			if err != nil {
				where := l.Name
				if where == "" {
					return nil, fmt.Errorf("bridge from %q links[%d]: %w", b.From, j, err)
				}
				return nil, fmt.Errorf("bridge from %q link %q: %w", b.From, where, err)
			}
			if linkSeen[b.From][l.Name] {
				return nil, fmt.Errorf("bridge from %q: link %q is defined more than once", b.From, l.Name)
			}
			linkSeen[b.From][l.Name] = true
			rule.Name = b.From + "/" + l.Name
			rule.From = b.From
			rule.Link = l.Name
			cfg.Bridges = append(cfg.Bridges, rule)
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}
