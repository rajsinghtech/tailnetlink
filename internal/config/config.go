package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
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
}

// DefaultUIServiceName is the VIP service the web UI is published as.
const DefaultUIServiceName = "svc:tailnetlink"

// UIConfig controls the web UI.
type UIConfig struct {
	// ServiceName is the VIP service the UI is published as in each tailnet.
	// Two instances that share a tailnet need different names.
	ServiceName string `json:"service_name,omitempty"`
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
	return nil
}

type TailnetConfig struct {
	OAuth   OAuthCreds `json:"oauth"`
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
}

func (tc TailnetConfig) HasAuth() bool {
	return tc.OAuth.ClientID != "" && tc.OAuth.ClientSecret != ""
}

type OAuthCreds struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// DeviceSpec identifies an explicit source device with optional DNS config.
type DeviceSpec struct {
	FQDN      string `json:"fqdn"`
	DNSName   string `json:"dns_name,omitempty"`   // full desired hostname, e.g. "ai.example.ts.net"
	ShortName string `json:"short_name,omitempty"` // bare VIP service name, e.g. "ai" → svc:ai
}

// ServiceSpec identifies an explicit source VIP service with optional DNS config.
type ServiceSpec struct {
	Name      string `json:"name"`
	DNSName   string `json:"dns_name,omitempty"`   // full desired hostname
	ShortName string `json:"short_name,omitempty"` // bare VIP service name → svc:shortName
}

// LocalSourceSpec identifies a service on the local machine (or host-reachable network)
// to proxy into a destination tailnet. Addr is "host:port" dialed directly via net.DialContext.
// ExposePort is the VIP-side listen port (defaults to addr's port if zero). DNSName is required
// when host is localhost or a bare IP; auto-derived from addr hostname otherwise.
type LocalSourceSpec struct {
	Addr       string `json:"addr"`
	ExposePort int    `json:"expose_port,omitempty"`
	DNSName    string `json:"dns_name,omitempty"`
	ShortName  string `json:"short_name,omitempty"`
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
}

// DefaultListenAddr is where the web UI listens unless the config or
// -listen says otherwise. Loopback only: the UI is reachable from the
// tailnets through its VIP service, not from the local network.
const DefaultListenAddr = "127.0.0.1:8888"

func defaults() *Config {
	return &Config{
		Tailnets:     make(map[string]TailnetConfig),
		Bridges:      []BridgeRule{},
		PollInterval: Duration{30 * time.Second},
		DialTimeout:  Duration{10 * time.Second},
		ListenAddr:   DefaultListenAddr,
	}
}

// Load reads the config JSON at path. If the file does not exist, it returns
// a valid empty config — no error. That's the "first run" case.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return defaults(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := defaults()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

func save(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// Store is a thread-safe config holder that persists to a JSON file and
// notifies listeners on change.
type Store struct {
	mu       sync.RWMutex
	path     string
	cfg      *Config
	onChange []func(*Config)
}

// NewStore loads config from path (or starts empty) and returns a Store.
func NewStore(path string) (*Store, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	return &Store{path: path, cfg: cfg}, nil
}

// Get returns a shallow copy of the current config. Safe for concurrent use.
func (s *Store) Get() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := *s.cfg
	return &cp
}

// Watch polls the config file for external edits (e.g. direct JSON edits) and
// fires OnChange callbacks when the mtime advances. Runs until ctx is cancelled.
func (s *Store) Watch(ctx context.Context, logger interface {
	Info(string, ...any)
	Warn(string, ...any)
}) {
	s.mu.RLock()
	lastMod := time.Time{}
	if fi, err := os.Stat(s.path); err == nil {
		lastMod = fi.ModTime()
	}
	s.mu.RUnlock()

	ticker := time.NewTicker(3 * time.Second)
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
				go cb(cfg)
			}
		}
	}
}

// OnChange registers a callback invoked (in a goroutine) after each successful Update.
func (s *Store) OnChange(fn func(*Config)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChange = append(s.onChange, fn)
}

// Update applies fn to a copy of the config, persists it, and notifies listeners.
// fn must not retain a reference to cfg after returning.
func (s *Store) Update(fn func(*Config) error) error {
	s.mu.Lock()

	cp := *s.cfg
	if cp.Tailnets == nil {
		cp.Tailnets = make(map[string]TailnetConfig)
	}
	if cp.Bridges == nil {
		cp.Bridges = []BridgeRule{}
	}
	if err := fn(&cp); err != nil {
		s.mu.Unlock()
		return err
	}
	if err := cp.Validate(); err != nil {
		s.mu.Unlock()
		return err
	}
	if err := save(s.path, &cp); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("persist config: %w", err)
	}
	s.cfg = &cp
	listeners := s.onChange
	s.mu.Unlock()

	for _, cb := range listeners {
		go cb(&cp)
	}
	return nil
}

// RedactedSecret stands in for a secret in anything served over HTTP.
const RedactedSecret = "[redacted]"

// Redacted returns a copy of c with every secret replaced by
// RedactedSecret. The copy has its own Tailnets map.
func (c *Config) Redacted() *Config {
	cp := *c
	cp.Tailnets = make(map[string]TailnetConfig, len(c.Tailnets))
	for name, tc := range c.Tailnets {
		if tc.OAuth.ClientSecret != "" {
			tc.OAuth.ClientSecret = RedactedSecret
		}
		cp.Tailnets[name] = tc
	}
	return &cp
}

// RedactedJSON returns the current config as indented JSON with secrets
// redacted. It backs GET /api/config and the SSE init event.
func (s *Store) RedactedJSON() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, _ := json.MarshalIndent(s.cfg.Redacted(), "", "  ")
	return data
}
