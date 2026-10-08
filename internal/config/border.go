package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Border is the config file: one tailnetlink process bridging one source
// tailnet into one destination tailnet. Run one process per border.
//
// The file is parsed into a Border and then compiled into a Config, which
// is what the rest of tailnetlink works with.
type Border struct {
	// Name identifies this border. It is the owner written to every VIP
	// service the border creates, and part of its node hostnames.
	Name string `json:"name"`

	Source Side `json:"source"`
	Dest   Side `json:"dest"`

	Node    NodeConfig    `json:"node,omitzero"`
	DNS     DNSConfig     `json:"dns,omitzero"`
	UI      BorderUI      `json:"ui,omitzero"`
	Metrics MetricsConfig `json:"metrics,omitzero"`

	PollInterval  *Duration `json:"poll_interval,omitempty"`
	DialTimeout   *Duration `json:"dial_timeout,omitempty"`
	AuthKeyExpiry *Duration `json:"auth_key_expiry,omitempty"`

	// Authz is the default authorization for every link. A link may set its
	// own authz to override this.
	Authz AuthzConfig `json:"authz,omitzero"`

	Links []Link `json:"links"`
}

// Side is one of the border's two tailnets.
type Side struct {
	Tailnet string     `json:"tailnet"`
	OAuth   OAuthCreds `json:"oauth"`
	Tags    []string   `json:"tags"`

	// ControlURL and APIBaseURL point at something other than the hosted
	// control plane; the e2e tests use them for testcontrol.
	ControlURL string `json:"control_url,omitempty"`
	APIBaseURL string `json:"api_base_url,omitempty"`
}

// NodeConfig controls the two tsnet nodes.
type NodeConfig struct {
	// StateDir holds node state. Default: tailnetlink-state next to the
	// config file. Borders must not share one.
	StateDir string `json:"state_dir,omitempty"`
	// Ephemeral nodes keep no state and get a new identity every start.
	Ephemeral bool `json:"ephemeral,omitempty"`
}

// DNSConfig controls split-DNS in the destination tailnet.
type DNSConfig struct {
	Enabled *bool `json:"enabled,omitempty"` // default true
}

// BorderUI controls the read-only web UI.
type BorderUI struct {
	Enabled     *bool  `json:"enabled,omitempty"` // default true
	ServiceName string `json:"service_name,omitempty"`
	ListenAddr  string `json:"listen_addr,omitempty"`
}

// MetricsConfig controls the health and metrics listener.
type MetricsConfig struct {
	ListenAddr string `json:"listen_addr,omitempty"` // "off" disables it
}

// Link is one thing bridged across the border. A tailnet link picks
// devices or services in the source tailnet with exactly one of tag,
// devices or services; a local link has local targets instead.
type Link struct {
	Name     string            `json:"name"`
	Tag      string            `json:"tag,omitempty"`
	Devices  []DeviceSpec      `json:"devices,omitempty"`
	Services []ServiceSpec     `json:"services,omitempty"`
	Local    []LocalSourceSpec `json:"local,omitempty"`
	Ports    []int             `json:"ports,omitempty"`
	Authz    AuthzConfig       `json:"authz,omitzero"`
}

// Authz modes. Empty Mode is AuthzOff.
const (
	AuthzOff         = "off"
	AuthzRequireCap  = "require_cap"
	AuthzAllowLogins = "allow_logins"
	AuthzAllowTags   = "allow_tags"
)

// AuthzConfig controls who may dial a link. Mode off (the default) allows
// every peer. require_cap needs the PeerCapability CapName with this link
// (or "*") in its links list. allow_logins and allow_tags match the peer's
// WhoIs login or tags against the lists below.
type AuthzConfig struct {
	Mode        string   `json:"mode,omitempty"`
	AllowLogins []string `json:"allow_logins,omitempty"`
	AllowTags   []string `json:"allow_tags,omitempty"`
}

// Effective returns az if it sets a mode, otherwise the border default.
func (az AuthzConfig) Effective(border AuthzConfig) AuthzConfig {
	if az.Mode != "" {
		return az
	}
	return border
}

func (az AuthzConfig) validate() error {
	switch az.Mode {
	case "", AuthzOff:
		return nil
	case AuthzRequireCap:
		return nil
	case AuthzAllowLogins:
		if len(az.AllowLogins) == 0 {
			return fmt.Errorf("authz.mode %q needs at least one allow_logins entry", az.Mode)
		}
		return nil
	case AuthzAllowTags:
		if len(az.AllowTags) == 0 {
			return fmt.Errorf("authz.mode %q needs at least one allow_tags entry", az.Mode)
		}
		return nil
	default:
		return fmt.Errorf("authz.mode %q is not one of off, require_cap, allow_logins, allow_tags", az.Mode)
	}
}

var borderNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)

// v1Keys are top-level fields only the old multi-tailnet format had.
var v1Keys = []string{"tailnets", "bridges", "instance_id"}

// errV1 is what a v1 file gets: there is no reader or converter for it.
var errV1 = errors.New("this is a v1 config (it has tailnets/bridges), which is no longer supported; " +
	"tailnetlink now takes one border per file. See the Configuration section of the README for the new format")

// Parse reads a border config and compiles it.
func Parse(data []byte) (*Config, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	for _, k := range v1Keys {
		if _, ok := probe[k]; ok {
			return nil, errV1
		}
	}
	var b Border
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return b.Compile()
}

// Tailnet keys a compiled border uses: "<name>-src" and "<name>-dst". They
// name the node state directories and node hostnames
// (tailnetlink-<name>-src), so two borders on one machine or in one
// tailnet don't collide.
func (b *Border) srcKey() string { return b.Name + "-src" }
func (b *Border) dstKey() string { return b.Name + "-dst" }

// Compile checks the border and turns it into a Config with defaults
// filled in.
func (b *Border) Compile() (*Config, error) {
	if b.Name == "" {
		return nil, errors.New("name is required: pick a short name for this border, for example \"home-to-work\"")
	}
	if !borderNameRe.MatchString(b.Name) {
		return nil, fmt.Errorf("name %q must be 1 to 40 lowercase letters, digits or dashes, starting and ending with a letter or digit", b.Name)
	}
	for role, s := range map[string]Side{"source": b.Source, "dest": b.Dest} {
		if err := s.check(); err != nil {
			return nil, fmt.Errorf("%s: %w", role, err)
		}
	}
	// links may be empty. The process still joins both tailnets; add a
	// link later and the file watch picks it up.
	if err := b.Authz.validate(); err != nil {
		return nil, err
	}

	cfg := defaults()
	cfg.InstanceID = b.Name
	cfg.StateDir = b.Node.StateDir
	cfg.DNSDisabled = b.DNS.Enabled != nil && !*b.DNS.Enabled
	cfg.UI = UIConfig{ServiceName: b.UI.ServiceName, Enabled: b.UI.Enabled}
	if b.UI.ListenAddr != "" {
		cfg.ListenAddr = b.UI.ListenAddr
	}
	if b.Metrics.ListenAddr != "" {
		cfg.MetricsAddr = b.Metrics.ListenAddr
	}
	for _, d := range []struct {
		name string
		in   *Duration
		out  *Duration
		min  time.Duration
	}{
		{"poll_interval", b.PollInterval, &cfg.PollInterval, 100 * time.Millisecond},
		{"dial_timeout", b.DialTimeout, &cfg.DialTimeout, 100 * time.Millisecond},
		{"auth_key_expiry", b.AuthKeyExpiry, &cfg.AuthKeyExpiry, time.Minute},
	} {
		if d.in == nil {
			continue
		}
		if d.in.Duration < d.min {
			return nil, fmt.Errorf("%s %s is too short (minimum %s)", d.name, d.in.Duration, d.min)
		}
		*d.out = *d.in
	}

	src, dst := b.srcKey(), b.dstKey()
	cfg.Tailnets[src] = b.Source.tailnet(b.Node.Ephemeral)
	cfg.Tailnets[dst] = b.Dest.tailnet(b.Node.Ephemeral)
	for i, l := range b.Links {
		rule, err := l.rule(src, dst, b.Authz)
		if err != nil {
			if l.Name == "" {
				return nil, fmt.Errorf("links[%d]: %w", i, err)
			}
			return nil, fmt.Errorf("link %q: %w", l.Name, err)
		}
		cfg.Bridges = append(cfg.Bridges, rule)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (s Side) check() error {
	if s.Tailnet == "" {
		return errors.New("tailnet is required (the tailnet name, e.g. example.ts.net, or \"-\" for the OAuth client's own tailnet)")
	}
	if s.OAuth.ClientID == "" {
		return errors.New("oauth.client_id is required")
	}
	if err := s.OAuth.validate(); err != nil {
		return err
	}
	if s.OAuth.credentialCount() == 0 {
		return errors.New("oauth needs one of client_secret_file, client_secret_env, id_token_file or id_token_env")
	}
	if len(s.Tags) == 0 {
		return errors.New("tags is required: the ACL tags tailnetlink's node and services get, e.g. [\"tag:tailnetlink\"]")
	}
	return nil
}

func (s Side) tailnet(ephemeral bool) TailnetConfig {
	return TailnetConfig{
		OAuth: s.OAuth, Tags: append([]string(nil), s.Tags...), Tailnet: s.Tailnet,
		Ephemeral: ephemeral, ControlURL: s.ControlURL, APIBaseURL: s.APIBaseURL,
	}
}

func localNeedsTailnet(sources []LocalSourceSpec) bool {
	for _, src := range sources {
		if src.DialVia() == ViaTailnet {
			return true
		}
	}
	return false
}

func (l Link) rule(src, dst string, borderAuthz AuthzConfig) (BridgeRule, error) {
	if l.Name == "" {
		return BridgeRule{}, errors.New("name is required")
	}
	if err := l.Authz.validate(); err != nil {
		return BridgeRule{}, err
	}
	selectors := 0
	for _, set := range []bool{l.Tag != "", len(l.Devices) > 0, len(l.Services) > 0, len(l.Local) > 0} {
		if set {
			selectors++
		}
	}
	switch {
	case selectors == 0:
		return BridgeRule{}, errors.New("needs one of tag, devices, services or local")
	case selectors > 1:
		return BridgeRule{}, errors.New("set only one of tag, devices, services or local")
	}
	r := BridgeRule{Name: l.Name, DestTailnets: []string{dst}, Authz: l.Authz.Effective(borderAuthz)}
	if len(l.Local) > 0 {
		if len(l.Ports) > 0 {
			return BridgeRule{}, errors.New("ports doesn't apply to a local link; set addr and ports on each target")
		}
		r.LocalSources = append([]LocalSourceSpec(nil), l.Local...)
		if localNeedsTailnet(r.LocalSources) {
			// The source node is where via:tailnet dials. Pod entries on the
			// same link still dial the host network.
			r.SourceTailnet = src
		}
		return r, nil
	}
	if len(l.Ports) == 0 {
		return BridgeRule{}, errors.New("ports is required")
	}
	r.SourceTailnet = src
	r.SourceTag = l.Tag
	r.SourceDevices = append([]DeviceSpec(nil), l.Devices...)
	r.SourceServices = append([]ServiceSpec(nil), l.Services...)
	r.Ports = append([]int(nil), l.Ports...)
	return r, nil
}
