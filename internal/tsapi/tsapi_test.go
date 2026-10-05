package tsapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/rajsinghtech/tailnetlink/internal/config"
)

// tokenServer accepts the secret currently in want and counts token
// requests. Tokens expire at once so every API call mints a new one.
type tokenServer struct {
	mu     sync.Mutex
	want   string
	tokens int
	seen   []string
}

func (s *tokenServer) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path == "/api/v2/oauth/token" {
		_ = r.ParseForm()
		secret := r.PostForm.Get("client_secret")
		if _, p, ok := r.BasicAuth(); ok {
			secret = p
		}
		s.seen = append(s.seen, secret)
		if secret != s.want {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		s.tokens++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "token_type": "Bearer", "expires_in": 1})
		return
	}
	if r.Header.Get("Authorization") != "Bearer tok" {
		http.Error(w, "no", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"devices":[]}`))
}

func TestClientReadsRotatedSecretFile(t *testing.T) {
	ts := &tokenServer{want: "first"}
	srv := httptest.NewServer(http.HandlerFunc(ts.handler))
	defer srv.Close()
	f := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(f, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewClient(config.TailnetConfig{Tailnet: "t.example", APIBaseURL: srv.URL, OAuth: config.OAuthCreds{ClientID: "id", ClientSecretFile: f}}, nil)
	ctx := context.Background()
	if _, err := c.Devices().List(ctx); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Rotate: the old secret stops working and the file gets the new one.
	ts.mu.Lock()
	ts.want = "second"
	ts.mu.Unlock()
	if err := os.WriteFile(f, []byte("second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Devices().List(ctx); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.tokens != 2 {
		t.Errorf("tokens = %d, want 2", ts.tokens)
	}
}

func TestClientSecretFromEnv(t *testing.T) {
	ts := &tokenServer{want: "from-env"}
	srv := httptest.NewServer(http.HandlerFunc(ts.handler))
	defer srv.Close()
	t.Setenv("TSAPI_TEST_SECRET", "from-env")
	c := NewClient(config.TailnetConfig{APIBaseURL: srv.URL, OAuth: config.OAuthCreds{ClientID: "id", ClientSecretEnv: "TSAPI_TEST_SECRET"}}, nil)
	if c.Tailnet != "-" {
		t.Errorf("Tailnet = %q, want -", c.Tailnet)
	}
	if _, err := c.Devices().List(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// A missing secret fails the call with a clear error and never reaches
// the token endpoint.
func TestClientMissingSecret(t *testing.T) {
	ts := &tokenServer{want: "x"}
	srv := httptest.NewServer(http.HandlerFunc(ts.handler))
	defer srv.Close()
	c := NewClient(config.TailnetConfig{APIBaseURL: srv.URL, OAuth: config.OAuthCreds{ClientID: "id", ClientSecretFile: filepath.Join(t.TempDir(), "missing")}}, nil)
	_, err := c.Devices().List(context.Background())
	if err == nil || !strings.Contains(err.Error(), "client_secret_file") {
		t.Fatalf("err = %v", err)
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if len(ts.seen) != 0 {
		t.Errorf("token endpoint called %d times", len(ts.seen))
	}
}

func TestNewClientBadBaseURL(t *testing.T) {
	c := NewClient(config.TailnetConfig{Tailnet: "t", APIBaseURL: "://bad"}, nil)
	if c.BaseURL != nil {
		t.Errorf("BaseURL = %v, want the default", c.BaseURL)
	}
}

type countRT struct {
	mu    sync.Mutex
	paths []string
}

func (c *countRT) RoundTrip(r *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.paths = append(c.paths, r.URL.Path)
	c.mu.Unlock()
	return http.DefaultTransport.RoundTrip(r)
}

// A transport given to NewClient sees token requests as well as API calls.
func TestClientUsesGivenTransport(t *testing.T) {
	ts := &tokenServer{want: "s"}
	srv := httptest.NewServer(http.HandlerFunc(ts.handler))
	defer srv.Close()
	t.Setenv("TSAPI_RT_SECRET", "s")
	rt := &countRT{}
	c := NewClient(config.TailnetConfig{APIBaseURL: srv.URL, OAuth: config.OAuthCreds{ClientID: "id", ClientSecretEnv: "TSAPI_RT_SECRET"}}, rt)
	if _, err := c.Devices().List(context.Background()); err != nil {
		t.Fatal(err)
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if !slices.Contains(rt.paths, "/api/v2/oauth/token") || !slices.Contains(rt.paths, "/api/v2/tailnet/-/devices") {
		t.Errorf("transport saw %v", rt.paths)
	}
}
