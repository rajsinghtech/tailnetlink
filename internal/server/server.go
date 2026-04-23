package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	tsclient "tailscale.com/client/tailscale/v2"
)

//go:embed web
var webFS embed.FS

type Server struct {
	store    *state.Store
	cfgStore *config.Store
	logger   *slog.Logger
	addr     string
}

func New(addr string, store *state.Store, cfgStore *config.Store, logger *slog.Logger) *Server {
	return &Server{addr: addr, store: store, cfgStore: cfgStore, logger: logger}
}

func (s *Server) Run() error {
	mux := http.NewServeMux()

	webRoot, err := fs.Sub(webFS, "web")
	if err != nil {
		return err
	}
	mux.Handle("/", http.FileServer(http.FS(webRoot)))

	// Read-only status / data
	mux.HandleFunc("/api/status", s.withCORS(s.handleStatus))
	mux.HandleFunc("/api/bridges", s.withCORS(s.handleBridges))
	mux.HandleFunc("/api/connections", s.withCORS(s.handleConns))
	mux.HandleFunc("/api/logs", s.withCORS(s.handleLogs))
	mux.HandleFunc("/api/config", s.withCORS(s.handleConfig))

	// Tailnet CRUD: /api/tailnets  /api/tailnets/{name}
	mux.HandleFunc("/api/tailnets/detect", s.withCORS(s.handleTailnetDetect))
	mux.HandleFunc("/api/tailnets/", s.withCORS(s.handleTailnetByName))
	mux.HandleFunc("/api/tailnets", s.withCORS(s.handleTailnets))

	// Bridge CRUD: /api/bridge-rules  /api/bridge-rules/{name}
	mux.HandleFunc("/api/bridge-rules/", s.withCORS(s.handleBridgeRuleByName))
	mux.HandleFunc("/api/bridge-rules", s.withCORS(s.handleBridgeRules))

	// Settings
	mux.HandleFunc("/api/settings", s.withCORS(s.handleSettings))

	// SSE
	mux.HandleFunc("/api/events", s.handleSSE)

	s.logger.Info("web UI available", "addr", "http://localhost"+s.addr)
	return http.ListenAndServe(s.addr, mux)
}

// ── Status / data handlers ────────────────────────────────────────────────────

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.store.GetStatus())
}

func (s *Server) handleBridges(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.store.GetBridges())
}

func (s *Server) handleConns(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.store.GetConns())
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.store.GetLogs(100))
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(s.cfgStore.RawJSON())
}

// ── Tailnet CRUD ──────────────────────────────────────────────────────────────

// POST /api/tailnets/detect — probe OAuth creds and return the resolved tailnet name.
// Uses Tailnet: "-" which the API resolves to the token's tailnet, then reads a device
// name to infer the ts.net domain.
func (s *Server) handleTailnetDetect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ClientID == "" {
		http.Error(w, "client_id and client_secret required", http.StatusBadRequest)
		return
	}

	c := clientForTailnet(config.TailnetConfig{
		OAuth: config.OAuthCreds{ClientID: body.ClientID, ClientSecret: body.ClientSecret},
	})
	devices, err := c.Devices().List(r.Context())
	if err != nil {
		http.Error(w, "credentials rejected or insufficient scope: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Extract tailnet domain from the first device FQDN (e.g. "host.org.ts.net" → "org.ts.net").
	tailnet := ""
	for _, d := range devices {
		if idx := strings.Index(d.Name, "."); idx >= 0 {
			tailnet = d.Name[idx+1:]
			break
		}
	}
	if tailnet == "" {
		http.Error(w, "unable to detect tailnet domain: no devices found in tailnet", http.StatusBadRequest)
		return
	}

	writeJSON(w, map[string]string{"tailnet": tailnet})
}

// POST /api/tailnets — add a tailnet
func (s *Server) handleTailnets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Name    string            `json:"name"`
		Tailnet string            `json:"tailnet"`
		OAuth   config.OAuthCreds `json:"oauth"`
		Tags    []string          `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.Name == "" || body.Tailnet == "" || body.OAuth.ClientID == "" || body.OAuth.ClientSecret == "" {
		http.Error(w, "name, tailnet, oauth.client_id, and oauth.client_secret are required", http.StatusBadRequest)
		return
	}

	if err := s.cfgStore.Update(func(cfg *config.Config) error {
		if _, exists := cfg.Tailnets[body.Name]; exists {
			return fmt.Errorf("tailnet %q already exists", body.Name)
		}
		cfg.Tailnets[body.Name] = config.TailnetConfig{
			OAuth:   body.OAuth,
			Tailnet: body.Tailnet,
			Tags:    body.Tags,
		}
		return nil
	}); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(s.cfgStore.RawJSON())
}

// GET /api/tailnets/{name}/devices — list live devices from the tailnet's API
func (s *Server) handleTailnetDevices(w http.ResponseWriter, name string, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tc, ok := s.cfgStore.Get().Tailnets[name]
	if !ok {
		http.Error(w, fmt.Sprintf("tailnet %q not found", name), http.StatusNotFound)
		return
	}
	devices, err := clientForTailnet(tc).Devices().List(r.Context())
	if err != nil {
		http.Error(w, "failed to list devices: "+err.Error(), http.StatusBadGateway)
		return
	}

	type devInfo struct {
		Name     string   `json:"name"`
		Hostname string   `json:"hostname"`
		IP       string   `json:"ip"`
		Tags     []string `json:"tags"`
	}
	out := make([]devInfo, 0, len(devices))
	for _, d := range devices {
		var ip string
		for _, a := range d.Addresses {
			if len(a) > 0 {
				ip = a
				break
			}
		}
		out = append(out, devInfo{Name: d.Name, Hostname: d.Hostname, IP: ip, Tags: d.Tags})
	}
	writeJSON(w, out)
}

// GET /api/tailnets/{name}/services — list VIP services from the tailnet API
func (s *Server) handleTailnetServices(w http.ResponseWriter, name string, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tc, ok := s.cfgStore.Get().Tailnets[name]
	if !ok {
		http.Error(w, fmt.Sprintf("tailnet %q not found", name), http.StatusNotFound)
		return
	}
	svcs, err := clientForTailnet(tc).VIPServices().List(r.Context())
	if err != nil {
		http.Error(w, "failed to list services: "+err.Error(), http.StatusBadGateway)
		return
	}

	type svcInfo struct {
		Name  string   `json:"name"`
		Addrs []string `json:"addrs"`
		Ports []string `json:"ports"`
		Tags  []string `json:"tags"`
	}
	out := make([]svcInfo, 0, len(svcs))
	for _, svc := range svcs {
		out = append(out, svcInfo{Name: svc.Name, Addrs: svc.Addrs, Ports: svc.Ports, Tags: svc.Tags})
	}
	writeJSON(w, out)
}

// DELETE/PUT /api/tailnets/{name}
func (s *Server) handleTailnetByName(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/tailnets/")
	if rest == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	// Sub-resource: /api/tailnets/{name}/devices or /api/tailnets/{name}/services
	if name, sub, ok := strings.Cut(rest, "/"); ok {
		switch sub {
		case "devices":
			s.handleTailnetDevices(w, name, r)
		case "services":
			s.handleTailnetServices(w, name, r)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
		return
	}
	name := rest

	switch r.Method {
	case http.MethodDelete:
		if err := s.cfgStore.Update(func(cfg *config.Config) error {
			if _, ok := cfg.Tailnets[name]; !ok {
				return fmt.Errorf("tailnet %q not found", name)
			}
			delete(cfg.Tailnets, name)
			return nil
		}); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	case http.MethodPut:
		var body config.TailnetConfig
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.cfgStore.Update(func(cfg *config.Config) error {
			cfg.Tailnets[name] = body
			return nil
		}); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(s.cfgStore.RawJSON())

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── Bridge rule CRUD ──────────────────────────────────────────────────────────

// POST /api/bridge-rules — add a bridge rule
func (s *Server) handleBridgeRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var rule config.BridgeRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if rule.Name == "" || rule.SourceTailnet == "" || len(rule.DestTailnets) == 0 || len(rule.Ports) == 0 {
		http.Error(w, "name, source_tailnet, dest_tailnets, and ports are required", http.StatusBadRequest)
		return
	}
	if rule.SourceTag == "" && len(rule.SourceDevices) == 0 && len(rule.SourceServices) == 0 {
		http.Error(w, "either source_tag, source_devices, or source_services must be specified", http.StatusBadRequest)
		return
	}

	if err := s.cfgStore.Update(func(cfg *config.Config) error {
		for _, b := range cfg.Bridges {
			if b.Name == rule.Name {
				return fmt.Errorf("bridge rule %q already exists", rule.Name)
			}
		}
		if _, ok := cfg.Tailnets[rule.SourceTailnet]; !ok {
			return fmt.Errorf("source_tailnet %q not found", rule.SourceTailnet)
		}
		for _, dt := range rule.DestTailnets {
			if _, ok := cfg.Tailnets[dt]; !ok {
				return fmt.Errorf("dest_tailnet %q not found", dt)
			}
		}
		if err := checkShortNameConflicts(cfg, rule, ""); err != nil {
			return err
		}
		cfg.Bridges = append(cfg.Bridges, rule)
		return nil
	}); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(s.cfgStore.RawJSON())
}

// PUT /api/bridge-rules/{name}  DELETE /api/bridge-rules/{name}
func (s *Server) handleBridgeRuleByName(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/bridge-rules/")
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		if err := s.cfgStore.Update(func(cfg *config.Config) error {
			out := make([]config.BridgeRule, 0, len(cfg.Bridges))
			found := false
			for _, b := range cfg.Bridges {
				if b.Name == name {
					found = true
					continue
				}
				out = append(out, b)
			}
			if !found {
				return fmt.Errorf("bridge rule %q not found", name)
			}
			cfg.Bridges = out
			return nil
		}); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	case http.MethodPut:
		var rule config.BridgeRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		rule.Name = name
		if err := s.cfgStore.Update(func(cfg *config.Config) error {
			for i, b := range cfg.Bridges {
				if b.Name == name {
					if err := checkShortNameConflicts(cfg, rule, name); err != nil {
						return err
					}
					cfg.Bridges[i] = rule
					return nil
				}
			}
			return fmt.Errorf("bridge rule %q not found", name)
		}); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(s.cfgStore.RawJSON())

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── Settings ──────────────────────────────────────────────────────────────────

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		PollInterval string `json:"poll_interval"`
		DialTimeout  string `json:"dial_timeout"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.cfgStore.Update(func(cfg *config.Config) error {
		if body.PollInterval != "" {
			d, err := time.ParseDuration(body.PollInterval)
			if err != nil {
				return fmt.Errorf("invalid poll_interval: %w", err)
			}
			cfg.PollInterval = config.Duration{Duration: d}
		}
		if body.DialTimeout != "" {
			d, err := time.ParseDuration(body.DialTimeout)
			if err != nil {
				return fmt.Errorf("invalid dial_timeout: %w", err)
			}
			cfg.DialTimeout = config.Duration{Duration: d}
		}
		return nil
	}); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(s.cfgStore.RawJSON())
}

// ── SSE ───────────────────────────────────────────────────────────────────────

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	type initPayload struct {
		Status      state.StatusSnapshot  `json:"status"`
		Bridges     []*state.BridgeEntry  `json:"bridges"`
		Connections []*state.ConnEntry    `json:"connections"`
		Logs        []state.LogEntry      `json:"logs"`
		Config      json.RawMessage       `json:"config"`
	}
	init := initPayload{
		Status:      s.store.GetStatus(),
		Bridges:     s.store.GetBridges(),
		Connections: s.store.GetConns(),
		Logs:        s.store.GetLogs(50),
		Config:      s.cfgStore.RawJSON(),
	}
	writeSSEEvent(w, state.EventInit, init)
	flusher.Flush()

	ch := s.store.Subscribe()
	defer s.store.Unsubscribe(ch)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprint(w, ": heartbeat\n\n")
			flusher.Flush()
		case event, ok := <-ch:
			if !ok {
				return
			}
			writeSSEEvent(w, event.Type, event.Payload)
			flusher.Flush()
		}
	}
}

func (s *Server) withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h(w, r)
	}
}

func clientForTailnet(tc config.TailnetConfig) *tsclient.Client {
	tailnet := tc.Tailnet
	if tailnet == "" {
		tailnet = "-"
	}
	return &tsclient.Client{
		Tailnet: tailnet,
		Auth:    &tsclient.OAuth{ClientID: tc.OAuth.ClientID, ClientSecret: tc.OAuth.ClientSecret},
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeSSEEvent(w http.ResponseWriter, eventType string, payload any) {
	data, _ := json.Marshal(payload)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, data)
}

// checkShortNameConflicts returns an error if the incoming rule has a short_name
// that already exists in any other rule for the same dest tailnet. Pass skipRule=""
// on create, or the rule's own name on update (to exclude self from the check).
func checkShortNameConflicts(cfg *config.Config, incoming config.BridgeRule, skipRule string) error {
	// Collect short_names already in use per dest tailnet (excluding skipRule).
	used := map[string]map[string]bool{} // dest → set of short_names
	for _, b := range cfg.Bridges {
		if b.Name == skipRule {
			continue
		}
		for _, dest := range b.DestTailnets {
			for _, spec := range b.SourceDevices {
				if spec.ShortName != "" {
					if used[dest] == nil {
						used[dest] = map[string]bool{}
					}
					used[dest][spec.ShortName] = true
				}
			}
			for _, spec := range b.SourceServices {
				if spec.ShortName != "" {
					if used[dest] == nil {
						used[dest] = map[string]bool{}
					}
					used[dest][spec.ShortName] = true
				}
			}
		}
	}

	// Check incoming rule against collected set, and also within itself.
	selfSeen := map[string]map[string]bool{} // dest → set within incoming rule
	for _, dest := range incoming.DestTailnets {
		for _, spec := range incoming.SourceDevices {
			if spec.ShortName == "" {
				continue
			}
			if used[dest][spec.ShortName] {
				return fmt.Errorf("short_name %q already used in dest tailnet %q", spec.ShortName, dest)
			}
			if selfSeen[dest] == nil {
				selfSeen[dest] = map[string]bool{}
			}
			if selfSeen[dest][spec.ShortName] {
				return fmt.Errorf("short_name %q appears more than once for dest tailnet %q", spec.ShortName, dest)
			}
			selfSeen[dest][spec.ShortName] = true
		}
		for _, spec := range incoming.SourceServices {
			if spec.ShortName == "" {
				continue
			}
			if used[dest][spec.ShortName] {
				return fmt.Errorf("short_name %q already used in dest tailnet %q", spec.ShortName, dest)
			}
			if selfSeen[dest] == nil {
				selfSeen[dest] = map[string]bool{}
			}
			if selfSeen[dest][spec.ShortName] {
				return fmt.Errorf("short_name %q appears more than once for dest tailnet %q", spec.ShortName, dest)
			}
			selfSeen[dest][spec.ShortName] = true
		}
	}
	return nil
}
