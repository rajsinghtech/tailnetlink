package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
)

// LocalPorts is the set of TCP ports one local target exposes on its VIP.
//
// A JSON array means the backend port equals the exposed port:
//
//	"ports": [80, 443]
//
// A JSON object maps each exposed VIP port to the backend port to dial.
// Keys are decimal port numbers:
//
//	"ports": {"80": 8080, "443": 8443}
//
// The zero value means the target uses addr's host:port form instead.
type LocalPorts struct {
	set     bool
	entries []LocalForward
}

// LocalForward is one exposed VIP port and the backend port it dials.
type LocalForward struct {
	Expose  int
	Backend int
}

// IsZero reports whether ports was left unset. Encoding/json uses it for
// the omitzero tag so the classic host:port form stays free of a ports field.
func (p LocalPorts) IsZero() bool { return !p.set }

// Configured reports whether the config set ports, including an empty list.
func (p LocalPorts) Configured() bool { return p.set }

// LocalPortList builds a ports value where each exposed port dials itself.
func LocalPortList(ports ...int) LocalPorts {
	p := LocalPorts{set: true, entries: make([]LocalForward, len(ports))}
	for i, n := range ports {
		p.entries[i] = LocalForward{Expose: n, Backend: n}
	}
	return p
}

// LocalPortMap builds a ports value from exposed VIP port to backend port.
// The pairs are stored in ascending exposed-port order.
func LocalPortMap(m map[int]int) LocalPorts {
	p := LocalPorts{set: true, entries: make([]LocalForward, 0, len(m))}
	for _, expose := range slices.Sorted(maps.Keys(m)) {
		p.entries = append(p.entries, LocalForward{Expose: expose, Backend: m[expose]})
	}
	return p
}

func (p LocalPorts) validated() ([]LocalForward, error) {
	if len(p.entries) == 0 {
		return nil, fmt.Errorf("ports is empty")
	}
	seen := make(map[int]bool, len(p.entries))
	for _, e := range p.entries {
		if e.Expose < 1 || e.Expose > 65535 {
			return nil, fmt.Errorf("port %d is out of range", e.Expose)
		}
		if e.Backend < 1 || e.Backend > 65535 {
			return nil, fmt.Errorf("backend port %d is out of range", e.Backend)
		}
		if seen[e.Expose] {
			return nil, fmt.Errorf("duplicate exposed port %d", e.Expose)
		}
		seen[e.Expose] = true
	}
	return slices.Clone(p.entries), nil
}

func (p LocalPorts) MarshalJSON() ([]byte, error) {
	if !p.set {
		return []byte("null"), nil
	}
	identity := true
	for _, e := range p.entries {
		if e.Expose != e.Backend {
			identity = false
			break
		}
	}
	if identity {
		nums := make([]int, len(p.entries))
		for i, e := range p.entries {
			nums[i] = e.Expose
		}
		return json.Marshal(nums)
	}
	obj := make(map[string]int, len(p.entries))
	for _, e := range p.entries {
		obj[strconv.Itoa(e.Expose)] = e.Backend
	}
	return json.Marshal(obj)
}

func (p *LocalPorts) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if bytes.Equal(b, []byte("null")) {
		*p = LocalPorts{}
		return nil
	}
	if len(b) == 0 {
		return fmt.Errorf("ports is empty")
	}
	switch b[0] {
	case '[':
		var list []int
		if err := json.Unmarshal(b, &list); err != nil {
			return fmt.Errorf("ports: %w", err)
		}
		entries := make([]LocalForward, len(list))
		for i, n := range list {
			entries[i] = LocalForward{Expose: n, Backend: n}
		}
		*p = LocalPorts{set: true, entries: entries}
		return nil
	case '{':
		var raw map[string]int
		if err := json.Unmarshal(b, &raw); err != nil {
			return fmt.Errorf("ports: %w", err)
		}
		entries := make([]LocalForward, 0, len(raw))
		for k, backend := range raw {
			n, err := strconv.Atoi(k)
			if err != nil || strconv.Itoa(n) != k {
				return fmt.Errorf("ports: invalid exposed port %q", k)
			}
			entries = append(entries, LocalForward{Expose: n, Backend: backend})
		}
		slices.SortFunc(entries, func(a, b LocalForward) int { return a.Expose - b.Expose })
		*p = LocalPorts{set: true, entries: entries}
		return nil
	default:
		return fmt.Errorf("ports must be an array of ports or an object mapping an exposed port to a backend port")
	}
}
