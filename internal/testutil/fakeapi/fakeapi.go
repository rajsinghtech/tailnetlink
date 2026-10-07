// Package fakeapi is an in-memory stand-in for the parts of the Tailscale
// control API that tailnetlink uses. It is only meant for tests.
//
// It serves VIP services, split-DNS, device listing and auth key creation
// for a single tailnet, and records every request so tests can assert which
// writes happened.
package fakeapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"sync"
	"testing"

	tsclient "tailscale.com/client/tailscale/v2"
)

// Call is one request the fake received.
type Call struct {
	Method string
	Path   string // path relative to /api/v2/tailnet/{tailnet}, e.g. "/vip-services/svc:foo"
}

func (c Call) String() string { return c.Method + " " + c.Path }

// Server is a fake control API for one tailnet.
type Server struct {
	// Tailnet is the tailnet name clients must use in request paths.
	Tailnet string

	// AssignAddrs controls whether a newly created VIP service with no
	// addresses gets one assigned, like the real API does. Tests that drive
	// code paths which would start a DNS listener on a real tsnet node can
	// turn this off so the VIP stays invalid and DNS setup is skipped.
	AssignAddrs bool

	srv *httptest.Server

	mu       sync.Mutex
	fail     map[Call]int
	calls    []Call
	devices  []tsclient.Device
	services map[string]tsclient.VIPService
	splitDNS map[string][]string
	nextIP   int
}

// New starts a fake API server and stops it when the test ends.
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{
		Tailnet:     "example.ts.net",
		AssignAddrs: true,
		services:    map[string]tsclient.VIPService{},
		splitDNS:    map[string][]string{},
		nextIP:      1,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v2/tailnet/{tn}/vip-services", s.listServices)
	mux.HandleFunc("GET /api/v2/tailnet/{tn}/vip-services/{name}", s.getService)
	mux.HandleFunc("PUT /api/v2/tailnet/{tn}/vip-services/{name}", s.putService)
	mux.HandleFunc("DELETE /api/v2/tailnet/{tn}/vip-services/{name}", s.deleteService)
	mux.HandleFunc("GET /api/v2/tailnet/{tn}/dns/split-dns", s.getSplitDNS)
	mux.HandleFunc("PATCH /api/v2/tailnet/{tn}/dns/split-dns", s.patchSplitDNS)
	mux.HandleFunc("GET /api/v2/tailnet/{tn}/devices", s.listDevices)
	mux.HandleFunc("POST /api/v2/tailnet/{tn}/keys", s.createKey)
	mux.HandleFunc("POST /api/v2/oauth/token", s.token)
	mux.HandleFunc("POST /api/v2/oauth/token-exchange", s.token)
	s.srv = httptest.NewServer(s.record(mux))
	t.Cleanup(s.srv.Close)
	return s
}

// Client returns an API client pointed at the fake.
func (s *Server) Client() *tsclient.Client {
	u, _ := url.Parse(s.srv.URL)
	return &tsclient.Client{BaseURL: u, APIKey: "fake-key", Tailnet: s.Tailnet}
}

// URL is the base URL of the fake.
func (s *Server) URL() string { return s.srv.URL }

// AddDevice adds a device to the device list.
func (s *Server) AddDevice(d tsclient.Device) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices = append(s.devices, d)
}

// SetDevices replaces the device list.
func (s *Server) SetDevices(ds []tsclient.Device) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices = append([]tsclient.Device(nil), ds...)
}

// PutService seeds a VIP service directly, without recording a call.
func (s *Server) PutService(svc tsclient.VIPService) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.services[svc.Name] = svc
}

// Service returns a VIP service and whether it exists.
func (s *Server) Service(name string) (tsclient.VIPService, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	svc, ok := s.services[name]
	return svc, ok
}

// ServiceNames returns the names of all VIP services, sorted.
func (s *Server) ServiceNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.services))
	for n := range s.services {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// SetSplitDNS seeds the split-DNS config directly, without recording a call.
func (s *Server) SetSplitDNS(zone string, resolvers []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.splitDNS[zone] = append([]string(nil), resolvers...)
}

// SplitDNS returns the resolvers for a zone, or nil if the zone is not set.
func (s *Server) SplitDNS(zone string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.splitDNS[zone]...)
}

// HasZone reports whether the zone has a split-DNS entry.
func (s *Server) HasZone(zone string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.splitDNS[zone]
	return ok
}

// Calls returns every request received so far.
func (s *Server) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Call(nil), s.calls...)
}

// Writes returns every non-GET request received so far, leaving out OAuth
// token requests.
func (s *Server) Writes() []Call {
	var out []Call
	for _, c := range s.Calls() {
		if c.Method != http.MethodGet && c.Path != "/api/v2/oauth/token" && c.Path != "/api/v2/oauth/token-exchange" {
			out = append(out, c)
		}
	}
	return out
}

// Fail makes every request matching method and path (relative, as in Call)
// answer with the given HTTP status until the test ends.
func (s *Server) Fail(method, path string, code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail == nil {
		s.fail = map[Call]int{}
	}
	s.fail[Call{Method: method, Path: path}] = code
}

// ResetCalls clears the recorded calls.
func (s *Server) ResetCalls() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = nil
}

func (s *Server) record(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := "/api/v2/tailnet/" + s.Tailnet
		path := r.URL.Path
		if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
			path = path[len(prefix):]
		}
		s.mu.Lock()
		call := Call{Method: r.Method, Path: path}
		s.calls = append(s.calls, call)
		code, fail := s.fail[call]
		s.mu.Unlock()
		if fail {
			writeErr(w, code, "injected failure")
			return
		}
		if r.Header.Get("Authorization") == "" && r.URL.Path != "/api/v2/oauth/token" && r.URL.Path != "/api/v2/oauth/token-exchange" {
			writeErr(w, http.StatusUnauthorized, "missing auth")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) checkTailnet(w http.ResponseWriter, r *http.Request) bool {
	if tn := r.PathValue("tn"); tn != s.Tailnet {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("unknown tailnet %q", tn))
		return false
	}
	return true
}

func (s *Server) listServices(w http.ResponseWriter, r *http.Request) {
	if !s.checkTailnet(w, r) {
		return
	}
	s.mu.Lock()
	out := make([]tsclient.VIPService, 0, len(s.services))
	for _, n := range sortedKeys(s.services) {
		out = append(out, s.services[n])
	}
	s.mu.Unlock()
	writeJSON(w, map[string]any{"vipServices": out})
}

func (s *Server) getService(w http.ResponseWriter, r *http.Request) {
	if !s.checkTailnet(w, r) {
		return
	}
	s.mu.Lock()
	svc, ok := s.services[r.PathValue("name")]
	s.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, svc)
}

func (s *Server) putService(w http.ResponseWriter, r *http.Request) {
	if !s.checkTailnet(w, r) {
		return
	}
	var svc tsclient.VIPService
	if err := json.NewDecoder(r.Body).Decode(&svc); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	svc.Name = r.PathValue("name")
	s.mu.Lock()
	if len(svc.Addrs) == 0 && s.AssignAddrs {
		svc.Addrs = []string{fmt.Sprintf("100.100.0.%d", s.nextIP)}
		s.nextIP++
	}
	s.services[svc.Name] = svc
	s.mu.Unlock()
	writeJSON(w, map[string]any{})
}

func (s *Server) deleteService(w http.ResponseWriter, r *http.Request) {
	if !s.checkTailnet(w, r) {
		return
	}
	name := r.PathValue("name")
	s.mu.Lock()
	_, ok := s.services[name]
	delete(s.services, name)
	s.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, map[string]any{})
}

func (s *Server) getSplitDNS(w http.ResponseWriter, r *http.Request) {
	if !s.checkTailnet(w, r) {
		return
	}
	s.mu.Lock()
	out := make(map[string][]string, len(s.splitDNS))
	for k, v := range s.splitDNS {
		out[k] = append([]string(nil), v...)
	}
	s.mu.Unlock()
	writeJSON(w, out)
}

// patchSplitDNS follows the real API: keys with a null or empty value are
// removed, other keys are replaced, and keys not mentioned are left alone.
func (s *Server) patchSplitDNS(w http.ResponseWriter, r *http.Request) {
	if !s.checkTailnet(w, r) {
		return
	}
	var req map[string][]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	for zone, resolvers := range req {
		if len(resolvers) == 0 {
			delete(s.splitDNS, zone)
			continue
		}
		s.splitDNS[zone] = append([]string(nil), resolvers...)
	}
	out := make(map[string][]string, len(s.splitDNS))
	for k, v := range s.splitDNS {
		out[k] = append([]string(nil), v...)
	}
	s.mu.Unlock()
	writeJSON(w, out)
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	if !s.checkTailnet(w, r) {
		return
	}
	s.mu.Lock()
	out := append([]tsclient.Device(nil), s.devices...)
	s.mu.Unlock()
	writeJSON(w, map[string]any{"devices": out})
}

func (s *Server) createKey(w http.ResponseWriter, r *http.Request) {
	if !s.checkTailnet(w, r) {
		return
	}
	writeJSON(w, map[string]any{"id": "kfake", "key": "tskey-auth-fake"})
}

// token accepts either an OAuth client secret or a workload-identity JWT.
// Any client is accepted.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"access_token": "fake-token", "token_type": "Bearer", "expires_in": 3600})
}

func sortedKeys(m map[string]tsclient.VIPService) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": msg})
}
