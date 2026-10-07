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
	"github.com/rajsinghtech/tailnetlink/internal/testutil/fakeapi"
	tsclient "tailscale.com/client/tailscale/v2"
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

// exchangeServer is a stand-in for the Tailscale API. It exchanges whatever
// JWT is posted for an access token named after that JWT, and can expire
// the token immediately or reject it once with 401.
type exchangeServer struct {
	mu         sync.Mutex
	expiresIn  int
	jwts       []string
	clientIDs  []string
	auths      []string
	rejectOnce bool
	rejected   bool
	jwtFile    string
	nextJWT    string
}

func (s *exchangeServer) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path == "/api/v2/oauth/token-exchange" {
		_ = r.ParseForm()
		s.clientIDs = append(s.clientIDs, r.PostForm.Get("client_id"))
		jwt := r.PostForm.Get("jwt")
		s.jwts = append(s.jwts, jwt)
		if r.PostForm.Get("client_id") == "" || jwt == "" {
			http.Error(w, `{"message":"missing client_id or jwt"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok-" + jwt,
			"token_type":   "Bearer",
			"expires_in":   s.expiresIn,
		})
		return
	}
	auth := r.Header.Get("Authorization")
	s.auths = append(s.auths, auth)
	if s.rejectOnce && !s.rejected {
		s.rejected = true
		if s.jwtFile != "" {
			_ = os.WriteFile(s.jwtFile, []byte(s.nextJWT+"\n"), 0o600)
		}
		http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if !strings.HasPrefix(auth, "Bearer tok-") {
		http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/keys"):
		_, _ = w.Write([]byte(`{"id":"k1","key":"tskey-auth-from-wif"}`))
	default:
		_, _ = w.Write([]byte(`{"devices":[]}`))
	}
}

func TestClientIDTokenFromEnvMintsKey(t *testing.T) {
	es := &exchangeServer{expiresIn: 3600}
	srv := httptest.NewServer(http.HandlerFunc(es.handler))
	defer srv.Close()
	t.Setenv("TSAPI_TEST_ID_TOKEN", "jwt-env")
	c := NewClient(config.TailnetConfig{
		APIBaseURL: srv.URL,
		OAuth:      config.OAuthCreds{ClientID: "fed-client", IDTokenEnv: "TSAPI_TEST_ID_TOKEN"},
	}, nil)
	ctx := context.Background()
	if _, err := c.Devices().List(ctx); err != nil {
		t.Fatal(err)
	}
	var req tsclient.CreateKeyRequest
	req.ExpirySeconds = 3600
	req.Capabilities.Devices.Create.Ephemeral = true
	req.Capabilities.Devices.Create.Preauthorized = true
	req.Capabilities.Devices.Create.Tags = []string{"tag:tailnetlink"}
	key, err := c.Keys().CreateAuthKey(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if key.Key != "tskey-auth-from-wif" {
		t.Fatalf("key = %+v", key)
	}
	es.mu.Lock()
	defer es.mu.Unlock()
	if len(es.jwts) != 1 || es.jwts[0] != "jwt-env" || es.clientIDs[0] != "fed-client" {
		t.Fatalf("exchanges = %#v client ids = %#v", es.jwts, es.clientIDs)
	}
	if es.auths[0] != "Bearer tok-jwt-env" || es.auths[1] != "Bearer tok-jwt-env" {
		t.Fatalf("api auth = %#v", es.auths)
	}
}

// The access token expires, the file is replaced, and the next call exchanges
// the new JWT. The old JWT is not reused.
func TestClientIDTokenRereadAfterExpiry(t *testing.T) {
	es := &exchangeServer{expiresIn: 1}
	srv := httptest.NewServer(http.HandlerFunc(es.handler))
	defer srv.Close()
	f := filepath.Join(t.TempDir(), "id-token")
	if err := os.WriteFile(f, []byte("jwt-a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewClient(config.TailnetConfig{
		Tailnet:    "t.example",
		APIBaseURL: srv.URL,
		OAuth:      config.OAuthCreds{ClientID: "fed", IDTokenFile: f},
	}, nil)
	ctx := context.Background()
	if _, err := c.Devices().List(ctx); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := os.WriteFile(f, []byte("jwt-b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Devices().List(ctx); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	es.mu.Lock()
	defer es.mu.Unlock()
	if len(es.jwts) != 2 || es.jwts[0] != "jwt-a" || es.jwts[1] != "jwt-b" {
		t.Fatalf("exchanged JWTs = %#v, want [jwt-a jwt-b]", es.jwts)
	}
	if es.auths[0] != "Bearer tok-jwt-a" || es.auths[1] != "Bearer tok-jwt-b" {
		t.Fatalf("api auth = %#v", es.auths)
	}
}

// A 401 drops the cached API token and exchanges once more, reading the file
// again, then retries the call.
func TestClientIDTokenRetries401(t *testing.T) {
	f := filepath.Join(t.TempDir(), "id-token")
	if err := os.WriteFile(f, []byte("jwt-a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	es := &exchangeServer{expiresIn: 3600, rejectOnce: true, jwtFile: f, nextJWT: "jwt-b"}
	srv := httptest.NewServer(http.HandlerFunc(es.handler))
	defer srv.Close()
	rt := &countRT{}
	c := NewClient(config.TailnetConfig{
		APIBaseURL: srv.URL,
		OAuth:      config.OAuthCreds{ClientID: "fed", IDTokenFile: f},
	}, rt)
	if _, err := c.Devices().List(context.Background()); err != nil {
		t.Fatal(err)
	}
	es.mu.Lock()
	defer es.mu.Unlock()
	if len(es.jwts) != 2 || es.jwts[0] != "jwt-a" || es.jwts[1] != "jwt-b" {
		t.Fatalf("exchanged JWTs = %#v", es.jwts)
	}
	if len(es.auths) != 2 || es.auths[1] != "Bearer tok-jwt-b" {
		t.Fatalf("api auth = %#v", es.auths)
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if !slices.Contains(rt.paths, "/api/v2/oauth/token-exchange") || !slices.Contains(rt.paths, "/api/v2/tailnet/-/devices") {
		t.Errorf("transport saw %v", rt.paths)
	}
}

func TestClientIDTokenFakeAPI(t *testing.T) {
	api := fakeapi.New(t)
	f := filepath.Join(t.TempDir(), "id-token")
	if err := os.WriteFile(f, []byte("jwt-fake\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewClient(config.TailnetConfig{
		Tailnet:    api.Tailnet,
		APIBaseURL: api.URL(),
		OAuth:      config.OAuthCreds{ClientID: "fed", IDTokenFile: f},
	}, nil)
	if _, err := c.Devices().List(context.Background()); err != nil {
		t.Fatal(err)
	}
	var req tsclient.CreateKeyRequest
	req.Capabilities.Devices.Create.Tags = []string{"tag:tailnetlink"}
	key, err := c.Keys().CreateAuthKey(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if key.Key != "tskey-auth-fake" {
		t.Fatalf("key = %+v", key)
	}
	for _, call := range api.Writes() {
		if strings.Contains(call.Path, "token-exchange") || strings.Contains(call.Path, "oauth/token") {
			t.Errorf("token exchange recorded as an API write: %s", call)
		}
	}
}

func TestClientIDTokenMissingFile(t *testing.T) {
	es := &exchangeServer{expiresIn: 3600}
	srv := httptest.NewServer(http.HandlerFunc(es.handler))
	defer srv.Close()
	c := NewClient(config.TailnetConfig{
		APIBaseURL: srv.URL,
		OAuth:      config.OAuthCreds{ClientID: "fed", IDTokenFile: filepath.Join(t.TempDir(), "missing")},
	}, nil)
	_, err := c.Devices().List(context.Background())
	if err == nil || !strings.Contains(err.Error(), "id_token_file") {
		t.Fatalf("err = %v", err)
	}
	es.mu.Lock()
	defer es.mu.Unlock()
	if len(es.jwts) != 0 {
		t.Errorf("token endpoint called with %#v", es.jwts)
	}
}

func TestClientIDTokenExchangeRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()
	t.Setenv("TSAPI_TEST_BAD_ID_TOKEN", "not-a-jwt")
	c := NewClient(config.TailnetConfig{
		APIBaseURL: srv.URL,
		OAuth:      config.OAuthCreds{ClientID: "fed", IDTokenEnv: "TSAPI_TEST_BAD_ID_TOKEN"},
	}, nil)
	_, err := c.Devices().List(context.Background())
	if err == nil || !strings.Contains(err.Error(), "token exchange") || strings.Contains(err.Error(), "not-a-jwt") {
		t.Fatalf("err = %v", err)
	}
}
