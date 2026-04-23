package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Duration is a time.Duration that marshals/unmarshals as a human-readable string ("30s").
type Duration struct{ time.Duration }

func (d Duration) MarshalJSON() ([]byte, error)  { return json.Marshal(d.String()) }
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
	Tailnets     map[string]TailnetConfig `json:"tailnets"`
	Bridges      []BridgeRule             `json:"bridges"`
	PollInterval Duration                 `json:"poll_interval"`
	DialTimeout  Duration                 `json:"dial_timeout"`
	ListenAddr   string                   `json:"listen_addr"`
}

type TailnetConfig struct {
	OAuth   OAuthCreds `json:"oauth"`
	Tags    []string   `json:"tags,omitempty"`
	Tailnet string     `json:"tailnet"`
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

type BridgeRule struct {
	Name           string        `json:"name"`
	SourceTailnet  string        `json:"source_tailnet"`
	DestTailnets   []string      `json:"dest_tailnets"`
	SourceTag      string        `json:"source_tag,omitempty"`
	SourceDevices  []DeviceSpec  `json:"source_devices,omitempty"`
	SourceServices []ServiceSpec `json:"source_services,omitempty"`
	Ports          []int         `json:"ports"`
}

func defaults() *Config {
	return &Config{
		Tailnets:     make(map[string]TailnetConfig),
		Bridges:      []BridgeRule{},
		PollInterval: Duration{30 * time.Second},
		DialTimeout:  Duration{10 * time.Second},
		ListenAddr:   ":8888",
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

// RawJSON returns the current config serialized as indented JSON.
func (s *Store) RawJSON() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, _ := json.MarshalIndent(s.cfg, "", "  ")
	return data
}
