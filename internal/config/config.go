package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"tailscale.com/tailcfg"
)

// Duration is a time.Duration that marshals/unmarshals as a human-readable string ("30s").
type Duration struct{ time.Duration }

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = dur
	return nil
}

type Config struct {
	// InstanceID names this tailnetlink instance. It is written to the
	// tailnetlink/owner annotation of every VIP service the instance creates,
	// and the instance never changes or deletes a service without it.
	// Required once any tailnet is configured.
	InstanceID string `json:"instance_id,omitempty"`

	UI UIConfig `json:"ui,omitzero"`

	// StateDir holds each tailnet's node state so nodes keep their identity
	// across restarts. Empty means a tailnetlink-state directory next to the
	// config file.
	StateDir string `json:"state_dir,omitempty"`

	Tailnets     map[string]TailnetConfig `json:"tailnets"`
	Bridges      []BridgeRule             `json:"bridges"`
	PollInterval Duration                 `json:"poll_interval"`
	DialTimeout  Duration                 `json:"dial_timeout"`
	ListenAddr   string                   `json:"listen_addr"`
	// MetricsAddr is where /healthz, /readyz and /metrics are served,
	// separate from the UI. "off" turns the listener off.
	MetricsAddr string `json:"metrics_addr,omitempty"`

	// DNSDisabled turns off the DNS VIP and split-DNS (border dns.enabled
	// false).
	DNSDisabled bool `json:"dns_disabled,omitempty"`
	// AuthKeyExpiry is how long the auth keys minted for new nodes last.
	AuthKeyExpiry Duration `json:"auth_key_expiry"`
}

// DefaultUIServiceName is the VIP service the web UI is published as.
const DefaultUIServiceName = "svc:tailnetlink"

// UIConfig controls the web UI.
type UIConfig struct {
	// ServiceName is the VIP service the UI is published as in each tailnet.
	// Two instances that share a tailnet need different names.
	ServiceName string `json:"service_name,omitempty"`

	// Enabled turns the UI on or off: both the local listener and the VIP
	// service. Unset means on.
	Enabled *bool `json:"enabled,omitempty"`
}

// UIEnabled reports whether the UI is on. It is unless ui.enabled is false.
func (c *Config) UIEnabled() bool {
	return c.UI.Enabled == nil || *c.UI.Enabled
}

// UIServiceName returns the UI service name, or the default.
func (c *Config) UIServiceName() string {
	if c.UI.ServiceName != "" {
		return c.UI.ServiceName
	}
	return DefaultUIServiceName
}

var instanceIDRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Validate checks the fields the bridge relies on for safety.
func (c *Config) Validate() error {
	if c.InstanceID == "" {
		if len(c.Tailnets) > 0 {
			return errors.New("instance_id is required: pick a short name for this tailnetlink instance, for example \"home-to-work\"")
		}
	} else if !instanceIDRe.MatchString(c.InstanceID) {
		return fmt.Errorf("instance_id %q must be 1 to 63 lowercase letters, digits or dashes, starting and ending with a letter or digit", c.InstanceID)
	}
	if err := tailcfg.ServiceName(c.UIServiceName()).Validate(); err != nil {
		return fmt.Errorf("ui.service_name: %w", err)
	}
	for _, name := range slices.Sorted(maps.Keys(c.Tailnets)) {
		if err := c.Tailnets[name].OAuth.validate(); err != nil {
			return fmt.Errorf("tailnet %q: %w", name, err)
		}
	}
	return c.validateBridges()
}

type TailnetConfig struct {
	OAuth   OAuthCreds `json:"oauth,omitzero"`
	Tags    []string   `json:"tags,omitempty"`
	Tailnet string     `json:"tailnet"`

	// Ephemeral makes this tailnet's node ephemeral: no saved state, a new
	// node on every start, and the control plane removes it when it goes
	// offline. The default is a persistent node.
	Ephemeral bool `json:"ephemeral,omitempty"`

	// ControlURL and APIBaseURL point the node and the API client at
	// something other than the hosted control plane. Empty means the
	// default. The e2e tests use them to run against testcontrol.
	ControlURL string `json:"control_url,omitempty"`
	APIBaseURL string `json:"api_base_url,omitempty"`

	// Authz, when it sets a mode, overrides the link authz for services
	// published into this tailnet. A single-dest border file does not set
	// it; multi-dest compile writes one mode per destination.
	Authz AuthzConfig `json:"authz,omitzero"`
}

func (tc TailnetConfig) HasAuth() bool {
	return tc.OAuth.ClientID != "" && tc.OAuth.credentialCount() > 0
}

// OAuthCreds says how to authenticate to a tailnet's admin API. The
// credential itself is never part of the config: a client secret or an OIDC
// JWT is read from a file or an environment variable each time a token is
// needed, so a rotated file is picked up without a restart.
type OAuthCreds struct {
	ClientID         string `json:"client_id"`
	ClientSecretFile string `json:"client_secret_file,omitempty"`
	ClientSecretEnv  string `json:"client_secret_env,omitempty"`
	// IDTokenFile is a path to an OIDC JWT for workload identity federation.
	// It is re-read on every token exchange and not cached.
	IDTokenFile string `json:"id_token_file,omitempty"`
	// IDTokenEnv is the name of an environment variable holding that JWT.
	IDTokenEnv string `json:"id_token_env,omitempty"`

	inline bool // the JSON had a client_secret field; Validate rejects it
}

// UnmarshalJSON notes an inline client_secret so Validate can reject it
// without the value ever being kept.
func (o *OAuthCreds) UnmarshalJSON(b []byte) error {
	type plain OAuthCreds
	var aux struct {
		plain
		ClientSecret *json.RawMessage `json:"client_secret"`
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*o = OAuthCreds(aux.plain)
	o.inline = aux.ClientSecret != nil
	return nil
}

// Secret reads the client secret from client_secret_file or
// client_secret_env.
func (o OAuthCreds) Secret() (string, error) {
	switch {
	case o.ClientSecretFile != "":
		b, err := os.ReadFile(o.ClientSecretFile)
		if err != nil {
			return "", fmt.Errorf("client_secret_file: %w", err)
		}
		s := strings.TrimSpace(string(b))
		if s == "" {
			return "", fmt.Errorf("client_secret_file %s is empty", o.ClientSecretFile)
		}
		return s, nil
	case o.ClientSecretEnv != "":
		s := strings.TrimSpace(os.Getenv(o.ClientSecretEnv))
		if s == "" {
			return "", fmt.Errorf("client_secret_env: $%s is not set", o.ClientSecretEnv)
		}
		return s, nil
	default:
		return "", errors.New("no client secret: set oauth.client_secret_file or oauth.client_secret_env")
	}
}

// IDToken reads the OIDC JWT from id_token_file or id_token_env. Callers
// must not store the result: the file is rotated externally and the next
// exchange has to see the new contents.
func (o OAuthCreds) IDToken() (string, error) {
	switch {
	case o.IDTokenFile != "":
		b, err := os.ReadFile(o.IDTokenFile)
		if err != nil {
			return "", fmt.Errorf("id_token_file: %w", err)
		}
		s := strings.TrimSpace(string(b))
		if s == "" {
			return "", fmt.Errorf("id_token_file %s is empty", o.IDTokenFile)
		}
		return s, nil
	case o.IDTokenEnv != "":
		s := strings.TrimSpace(os.Getenv(o.IDTokenEnv))
		if s == "" {
			return "", fmt.Errorf("id_token_env: $%s is not set", o.IDTokenEnv)
		}
		return s, nil
	default:
		return "", errors.New("no id token: set oauth.id_token_file or oauth.id_token_env")
	}
}

// UsesIDToken reports whether this side authenticates by exchanging an OIDC
// JWT instead of an OAuth client secret.
func (o OAuthCreds) UsesIDToken() bool {
	return o.IDTokenFile != "" || o.IDTokenEnv != ""
}

func (o OAuthCreds) credentialCount() int {
	n := 0
	for _, s := range []string{o.ClientSecretFile, o.ClientSecretEnv, o.IDTokenFile, o.IDTokenEnv} {
		if s != "" {
			n++
		}
	}
	return n
}

func (o OAuthCreds) validate() error {
	if o.inline {
		return errors.New("oauth.client_secret is not supported: put the secret in a file and set oauth.client_secret_file, or in an environment variable and set oauth.client_secret_env")
	}
	if o.credentialCount() > 1 {
		return errors.New("set only one of oauth.client_secret_file, oauth.client_secret_env, oauth.id_token_file and oauth.id_token_env")
	}
	return nil
}

// DeviceSpec identifies an explicit source device with optional DNS config.
type DeviceSpec struct {
	FQDN      string `json:"fqdn"`
	DNSName   string `json:"dns_name,omitempty"`   // full desired hostname, e.g. "ai.example.ts.net"
	DNSZone   string `json:"dns_zone,omitempty"`   // split-DNS zone; empty means the parent of dns_name
	ShortName string `json:"short_name,omitempty"` // bare VIP service name, e.g. "ai" → svc:ai
}

// ServiceSpec identifies an explicit source VIP service with optional DNS config.
type ServiceSpec struct {
	Name      string `json:"name"`
	DNSName   string `json:"dns_name,omitempty"`   // full desired hostname
	DNSZone   string `json:"dns_zone,omitempty"`   // split-DNS zone; empty means the parent of dns_name
	ShortName string `json:"short_name,omitempty"` // bare VIP service name → svc:shortName
}

// LocalSourceSpec identifies a service on the local machine (or host-reachable network)
// to proxy into a destination tailnet. One spec is one VIP service: one DNS name
// and one short name.
//
// Addr is either "host:port" or a host with no port. The host:port form dials
// that address; ExposePort is the VIP listen port and defaults to addr's port.
// A host with no port uses Ports: a list (exposed port equals backend port) or
// a map of exposed port to backend port. DNSName is required when host is
// localhost or a bare IP; it is taken from the addr hostname otherwise.
//
// Via chooses the dial path. Empty and "pod" (the default) use the host
// network and the process's system resolver, which is what existing configs
// do and what an in-cluster name such as a Kubernetes Service needs.
// "tailnet" dials through the source tsnet node: names are resolved with
// that tailnet's MagicDNS and split DNS, and subnet addresses use only the
// advertised routes that cover the configured targets.
type LocalSourceSpec struct {
	Addr       string     `json:"addr"`
	ExposePort int        `json:"expose_port,omitempty"`
	Ports      LocalPorts `json:"ports,omitzero"`
	Via        string     `json:"via,omitempty"`
	DNSName    string     `json:"dns_name,omitempty"`
	DNSZone    string     `json:"dns_zone,omitempty"` // split-DNS zone; empty means the parent of dns_name
	ShortName  string     `json:"short_name,omitempty"`
}

// ViaPod dials from the host network. ViaTailnet dials through the source node.
const (
	ViaPod     = "pod"
	ViaTailnet = "tailnet"
)

// DialVia returns pod or tailnet. Empty means pod, so older configs keep
// dialing the host network.
func (l LocalSourceSpec) DialVia() string {
	if l.Via == "" {
		return ViaPod
	}
	return l.Via
}

type BridgeRule struct {
	Name           string            `json:"name"`
	SourceTailnet  string            `json:"source_tailnet,omitempty"`
	DestTailnets   []string          `json:"dest_tailnets"`
	SourceTag      string            `json:"source_tag,omitempty"`
	SourceDevices  []DeviceSpec      `json:"source_devices,omitempty"`
	SourceServices []ServiceSpec     `json:"source_services,omitempty"`
	LocalSources   []LocalSourceSpec `json:"local_sources,omitempty"`
	Ports          []int             `json:"ports,omitempty"`
	Authz          AuthzConfig       `json:"authz,omitzero"`
	// From is the tailnet key this rule leaves. Border compile sets it on
	// local links. Mesh compile sets it on every rule to the bridge's from
	// key. Non-local border rules leave it empty and use SourceTailnet.
	From string `json:"from,omitempty"`
	// Link is the link name inside a mesh bridge. The rule Name there is
	// from/link, so Link keeps the short name for the ownership id. A
	// border leaves it empty and BridgeRef uses Name.
	Link string `json:"link,omitempty"`
}

// FromTailnet is the tailnet key this rule leaves: From, or else
// SourceTailnet. Local border links have From set to the source key.
func (r BridgeRule) FromTailnet() string {
	if r.From != "" {
		return r.From
	}
	return r.SourceTailnet
}

// BridgeRef identifies the bridge that owns VIP services this rule publishes
// into dest. It is from/dest/link, so two bridges that want the same name
// in one tailnet conflict instead of overwriting each other.
func (r BridgeRule) BridgeRef(dest string) string {
	from := r.FromTailnet()
	if from == "" {
		from = "local"
	}
	link := r.Link
	if link == "" {
		link = r.Name
	}
	return from + "/" + dest + "/" + link
}

// DefaultListenAddr is where the web UI listens unless the config or
// -listen says otherwise. Loopback only: the UI is reachable from the
// tailnets through its VIP service, not from the local network.
const DefaultListenAddr = "127.0.0.1:8888"

// DefaultMetricsAddr is where the metrics and health endpoints listen
// unless the config or -metrics-listen says otherwise. In a container set
// it to ":9090" so probes can reach it.
const DefaultMetricsAddr = "127.0.0.1:9090"

func defaults() *Config {
	return &Config{
		Tailnets:     make(map[string]TailnetConfig),
		Bridges:      []BridgeRule{},
		PollInterval: Duration{30 * time.Second},
		DialTimeout:  Duration{10 * time.Second},
		ListenAddr:   DefaultListenAddr,
		MetricsAddr:  DefaultMetricsAddr,
		// The defaults below match what a border without these fields gets.
		AuthKeyExpiry: Duration{time.Hour},
	}
}

// Load reads the border config at path. A missing file gives an empty
// config with defaults and nothing to bridge, so the UI can still start;
// any other problem is an error.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return defaults(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Store holds the config loaded from a file. The file is the only way to
// change it: Watch reloads it when it changes and tells the OnChange
// listeners. Nothing writes the file back.
type Store struct {
	mu       sync.RWMutex
	path     string
	cfg      *Config
	onChange []func(*Config)
	interval time.Duration
	modTime  time.Time // of the file when cfg was loaded
}

// NewStore loads config from path (or starts empty) and returns a Store.
func NewStore(path string) (*Store, error) {
	var modTime time.Time
	if fi, err := os.Stat(path); err == nil {
		modTime = fi.ModTime()
	}
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	return &Store{path: path, cfg: cfg, interval: 3 * time.Second, modTime: modTime}, nil
}

// Get returns a deep copy of the current config, so callers can't change
// what other callers see.
func (s *Store) Get() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Clone()
}

// SetWatchInterval sets how often Watch checks the file. The default is
// 3 s. Call it before Watch.
func (s *Store) SetWatchInterval(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.interval = d
}

// Watch polls the config file for external edits (e.g. direct JSON edits) and
// fires OnChange callbacks when the mtime advances. Runs until ctx is cancelled.
func (s *Store) Watch(ctx context.Context, logger interface {
	Info(string, ...any)
	Warn(string, ...any)
}) {
	s.mu.RLock()
	interval := s.interval
	lastMod := s.modTime // so an edit made before Watch starts is not missed
	s.mu.RUnlock()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fi, err := os.Stat(s.path)
			if err != nil || !fi.ModTime().After(lastMod) {
				continue
			}
			lastMod = fi.ModTime()
			cfg, err := Load(s.path)
			if err != nil {
				logger.Warn("config file changed but failed to parse", "err", err)
				continue
			}
			s.mu.Lock()
			s.cfg = cfg
			listeners := s.onChange
			s.mu.Unlock()
			logger.Info("config reloaded from file")
			for _, cb := range listeners {
				go cb(cfg.Clone())
			}
		}
	}
}

// OnChange registers a callback, run in its own goroutine with its own copy
// of the config, after each reload from the file.
func (s *Store) OnChange(fn func(*Config)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChange = append(s.onChange, fn)
}

// Clone returns a deep copy of c.
func (c *Config) Clone() *Config {
	cp := *c
	if c.UI.Enabled != nil {
		v := *c.UI.Enabled
		cp.UI.Enabled = &v
	}
	if c.Tailnets != nil {
		cp.Tailnets = make(map[string]TailnetConfig, len(c.Tailnets))
		for k, tc := range c.Tailnets {
			tc.Tags = slices.Clone(tc.Tags)
			tc.Authz.AllowLogins = slices.Clone(tc.Authz.AllowLogins)
			tc.Authz.AllowTags = slices.Clone(tc.Authz.AllowTags)
			cp.Tailnets[k] = tc
		}
	}
	if c.Bridges != nil {
		cp.Bridges = make([]BridgeRule, len(c.Bridges))
		for i, b := range c.Bridges {
			b.DestTailnets = slices.Clone(b.DestTailnets)
			b.SourceDevices = slices.Clone(b.SourceDevices)
			b.SourceServices = slices.Clone(b.SourceServices)
			b.LocalSources = cloneLocalSources(b.LocalSources)
			b.Ports = slices.Clone(b.Ports)
			b.Authz.AllowLogins = slices.Clone(b.Authz.AllowLogins)
			b.Authz.AllowTags = slices.Clone(b.Authz.AllowTags)
			cp.Bridges[i] = b
		}
	}
	return &cp
}

func cloneLocalSources(in []LocalSourceSpec) []LocalSourceSpec {
	out := slices.Clone(in)
	for i := range out {
		out[i].Ports.entries = slices.Clone(out[i].Ports.entries)
	}
	return out
}

// PublicJSON returns the config as indented JSON with every tailnet's oauth
// block left out. It is what the read-only UI shows. The config never holds
// a secret anyway, only where to read one, but the UI is published in every
// connected tailnet and has no use for client IDs or file paths.
func (c *Config) PublicJSON() []byte {
	cp := c.Clone()
	for k, tc := range cp.Tailnets {
		tc.OAuth = OAuthCreds{}
		cp.Tailnets[k] = tc
	}
	data, _ := json.MarshalIndent(cp, "", "  ")
	return data
}
