package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Border is the config file for one direction: a source tailnet bridged
// into one destination, or into several with dests. A file that names
// several tailnets and the bridges between them is a Mesh instead. Parse
// accepts either shape and compiles both into a Config.
type Border struct {
	// Name identifies this border. It is the owner written to every VIP
	// service the border creates, and part of its node hostnames.
	Name string `json:"name"`

	Source Side   `json:"source"`
	Dest   Side   `json:"dest"`
	Dests  []Dest `json:"dests,omitempty"`

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

// Dest is one destination tailnet. Authz and DNS, when set, apply only
// there and override the border defaults.
type Dest struct {
	Side
	Authz AuthzConfig `json:"authz,omitzero"`
	DNS   *DNSConfig  `json:"dns,omitempty"`
}

// Side is one tailnet the border joins.
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

// errV1 is what a leftover v1 file gets: there is no reader or converter
// for it. A v1 file sets instance_id, or bridges without tailnets. A mesh
// sets tailnets and bridges and does not set instance_id.
var errV1 = errors.New("this is a v1 config (it has tailnets/bridges), which is no longer supported; " +
	"tailnetlink now takes one border per file, or a mesh of tailnets and bridges. See the Configuration section of the README for the new format")

// Parse reads a border or a mesh and compiles it.
//
// A border has source and dest (or dests). A mesh has tailnets and bridges
// and no instance_id. A file that sets instance_id, or bridges without
// tailnets, is the old format and is rejected. The two current shapes are
// not mixed.
func Parse(data []byte) (*Config, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	_, hasTailnets := probe["tailnets"]
	_, hasBridges := probe["bridges"]
	_, hasInstance := probe["instance_id"]
	if hasInstance || (hasBridges && !hasTailnets) {
		return nil, errV1
	}
	_, hasSource := probe["source"]
	_, hasDest := probe["dest"]
	_, hasDests := probe["dests"]
	if hasTailnets && (hasSource || hasDest || hasDests) {
		return nil, errors.New("set tailnets and bridges, or source and dest, not both")
	}
	if hasTailnets {
		var m Mesh
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
		return m.Compile()
	}
	var b Border
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return b.Compile()
}

// Tailnet keys a compiled border uses. The source is "<name>-src". A single
// dest keeps "<name>-dst", so an existing state directory is reused. Every
// entry in dests, including a list of one, is "<name>-dst-" plus a short
// hash of the tailnet name. Those keys stay the same when destinations are
// added or removed, and they do not collide with the single-dest path.
func (b *Border) srcKey() string { return b.Name + "-src" }

func destKey(borderName, tailnet string, fromDests bool) string {
	if !fromDests {
		return borderName + "-dst"
	}
	sum := sha256.Sum256([]byte(strings.ToLower(tailnet)))
	return borderName + "-dst-" + hex.EncodeToString(sum[:2])
}

// Compile checks the border and turns it into a Config with defaults
// filled in.
func (b *Border) Compile() (*Config, error) {
	if b.Name == "" {
		return nil, errors.New("name is required: pick a short name for this border, for example \"home-to-work\"")
	}
	if !borderNameRe.MatchString(b.Name) {
		return nil, fmt.Errorf("name %q must be 1 to 40 lowercase letters, digits or dashes, starting and ending with a letter or digit", b.Name)
	}
	if err := b.Source.check(); err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}
	dests, err := b.destList()
	if err != nil {
		return nil, err
	}
	// links may be empty. The process still joins the tailnets; add a
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

	src := b.srcKey()
	srcTC := b.Source.tailnet(b.Node.Ephemeral)
	srcTC.Role = "source"
	cfg.Tailnets[src] = srcTC
	fromDests := b.Dests != nil
	dstKeys := make([]string, len(dests))
	seenKey := map[string]string{}
	for i, d := range dests {
		k := destKey(b.Name, d.Tailnet, fromDests)
		if other, ok := seenKey[k]; ok {
			return nil, fmt.Errorf("dests %q and %q would share node state %q", other, d.Tailnet, k)
		}
		seenKey[k] = d.Tailnet
		dstKeys[i] = k
		tc := d.Side.tailnet(b.Node.Ephemeral)
		tc.Role = "dest"
		tc.Authz = d.Authz
		tc.DNSDisabled = cfg.DNSDisabled || (d.DNS != nil && d.DNS.Enabled != nil && !*d.DNS.Enabled)
		cfg.Tailnets[k] = tc
	}
	for i, l := range b.Links {
		rule, err := l.rule(src, dstKeys, b.Authz)
		if err != nil {
			if l.Name == "" {
				return nil, fmt.Errorf("links[%d]: %w", i, err)
			}
			return nil, fmt.Errorf("link %q: %w", l.Name, err)
		}
		// Local links do not dial through the source, but the source node is
		// the one that would accept subnet routes for their addresses.
		if len(l.Local) > 0 {
			rule.From = src
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

// destList is the destinations to join. A single dest keeps the historical
// state path. Entries in dests each get their own.
func (b *Border) destList() ([]Dest, error) {
	hasDest := sideConfigured(b.Dest)
	hasDests := b.Dests != nil
	switch {
	case hasDest && hasDests:
		return nil, errors.New("set dest or dests, not both")
	case hasDests && len(b.Dests) == 0:
		return nil, errors.New("dests is empty")
	case !hasDest && !hasDests:
		return nil, errors.New("dest or dests is required")
	case hasDest:
		if err := b.Dest.check(); err != nil {
			return nil, fmt.Errorf("dest: %w", err)
		}
		return []Dest{{Side: b.Dest}}, nil
	}
	seen := map[string]bool{}
	for i, d := range b.Dests {
		if err := d.Side.check(); err != nil {
			return nil, fmt.Errorf("dests[%d]: %w", i, err)
		}
		if err := d.Authz.validate(); err != nil {
			return nil, fmt.Errorf("dests[%d]: %w", i, err)
		}
		key := strings.ToLower(strings.TrimSpace(d.Tailnet))
		if seen[key] {
			return nil, fmt.Errorf("dests[%d]: tailnet %q is duplicated", i, d.Tailnet)
		}
		seen[key] = true
	}
	return b.Dests, nil
}

func sideConfigured(s Side) bool {
	return s.Tailnet != "" || s.OAuth.ClientID != "" || s.OAuth.credentialCount() > 0 || len(s.Tags) > 0
}

func (s Side) tailnet(ephemeral bool) TailnetConfig {
	return TailnetConfig{
		OAuth: s.OAuth, Tags: append([]string(nil), s.Tags...), Tailnet: s.Tailnet,
		Ephemeral: ephemeral, ControlURL: s.ControlURL, APIBaseURL: s.APIBaseURL,
	}
}

func (l Link) rule(src string, dsts []string, borderAuthz AuthzConfig) (BridgeRule, error) {
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
	r := BridgeRule{Name: l.Name, DestTailnets: append([]string(nil), dsts...), Authz: l.Authz.Effective(borderAuthz)}
	if len(l.Local) > 0 {
		if len(l.Ports) > 0 {
			return BridgeRule{}, errors.New("ports doesn't apply to a local link; set addr (and expose_port) on each target")
		}
		r.LocalSources = append([]LocalSourceSpec(nil), l.Local...)
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
