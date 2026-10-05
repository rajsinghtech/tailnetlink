package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	"github.com/rajsinghtech/tailnetlink/internal/testutil/fakeapi"
	tsclient "tailscale.com/client/tailscale/v2"
)

var testSecrets = []string{"alpha-secret-0001", "beta-secret-0002"}

// newTestServer serves the UI for a config with two tailnets whose admin
// API is a fake, and returns its URL and config store.
func newTestServer(t *testing.T) (string, *config.Store, *fakeapi.Server) {
	t.Helper()
	api := fakeapi.New(t)
	dir := t.TempDir()
	files := make([]string, len(testSecrets))
	for i, sec := range testSecrets {
		files[i] = filepath.Join(dir, fmt.Sprintf("secret-%d", i))
		if err := os.WriteFile(files[i], []byte(sec+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	api.SetDevices([]tsclient.Device{{NodeID: "n1", Name: "web.a.example", Hostname: "web", Addresses: []string{"100.64.0.1"}}})
	cfg := config.Config{
		InstanceID: "test",
		Tailnets: map[string]config.TailnetConfig{
			"a": {Tailnet: api.Tailnet, APIBaseURL: api.URL(), OAuth: config.OAuthCreds{ClientID: "id-a", ClientSecretFile: files[0]}},
			"b": {Tailnet: api.Tailnet, APIBaseURL: api.URL(), OAuth: config.OAuthCreds{ClientID: "id-b", ClientSecretFile: files[1]}},
		},
		Bridges: []config.BridgeRule{{Name: "r", SourceTailnet: "a", DestTailnets: []string{"b"}, SourceTag: "tag:web", Ports: []int{80}}},
	}
	path := filepath.Join(dir, "c.json")
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cs, err := config.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	st := state.New()
	st.Log("info", "hello", nil)
	srv := httptest.NewServer(New("", st, cs, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	t.Cleanup(srv.Close)
	return srv.URL, cs, api
}

// leaks returns the secrets found in s, in plain form or base64 encoded.
func leaks(s string) []string {
	var out []string
	for _, sec := range testSecrets {
		for _, form := range []string{
			sec,
			base64.StdEncoding.EncodeToString([]byte(sec)),
			base64.RawStdEncoding.EncodeToString([]byte(sec)),
			base64.URLEncoding.EncodeToString([]byte(sec)),
		} {
			if strings.Contains(s, form) {
				out = append(out, form)
			}
		}
	}
	return out
}

func do(t *testing.T, method, url, ctype, body string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func dumpHeaders(h http.Header) string {
	var b strings.Builder
	_ = h.Write(&b)
	return b.String()
}

// No route hands out a client secret, there is no CORS header anywhere,
// and the SSE init event is redacted too.
func TestNoRouteServesSecrets(t *testing.T) {
	base, _, _ := newTestServer(t)
	reqs := []struct{ method, path, body string }{
		{"GET", "/", ""},
		{"GET", "/api/status", ""},
		{"GET", "/api/bridges", ""},
		{"GET", "/api/connections", ""},
		{"GET", "/api/logs", ""},
		{"GET", "/api/config", ""},
		{"GET", "/api/tailnets/a/devices", ""},
		{"GET", "/api/tailnets/b/services", ""},
		{"OPTIONS", "/api/config", ""},
		{"PUT", "/api/settings", `{"poll_interval":"45s"}`},
		{"PUT", "/api/tailnets/b", `{"tailnet":"x.example","oauth":{"client_id":"id-b","client_secret_env":"B_SECRET"}}`},
		{"POST", "/api/bridge-rules", `{"name":"r2","source_tailnet":"a","dest_tailnets":["b"],"source_tag":"tag:x","ports":[81]}`},
		{"PUT", "/api/bridge-rules/r2", `{"source_tailnet":"a","dest_tailnets":["b"],"source_tag":"tag:x","ports":[82]}`},
		{"POST", "/api/tailnets", `{"name":"c","tailnet":"c.example","oauth":{"client_id":"id-c","client_secret_file":"/run/c"}}`},
		{"DELETE", "/api/bridge-rules/r2", ""},
		{"DELETE", "/api/tailnets/c", ""},
		{"GET", "/api/nope", ""},
	}
	for _, r := range reqs {
		resp, body := do(t, r.method, base+r.path, "application/json", r.body)
		if l := leaks(body + dumpHeaders(resp.Header)); len(l) != 0 {
			t.Errorf("%s %s (%d) leaked %v:\n%s", r.method, r.path, resp.StatusCode, l, body)
		}
		if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "" {
			t.Errorf("%s %s: Access-Control-Allow-Origin = %q", r.method, r.path, v)
		}
		if r.method != "GET" && r.method != "OPTIONS" && resp.StatusCode >= 400 {
			t.Errorf("%s %s = %d: %s", r.method, r.path, resp.StatusCode, body)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", base+"/api/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "" {
		t.Errorf("SSE Access-Control-Allow-Origin = %q", v)
	}
	var init string
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "data: ") {
			init = sc.Text()
			break
		}
	}
	if !strings.Contains(init, `"config"`) || !strings.Contains(init, "client_secret_file") {
		t.Fatalf("SSE init event missing the config: %s", init)
	}
	if l := leaks(init); len(l) != 0 {
		t.Errorf("SSE init leaked %v", l)
	}
}

// Writes need Content-Type: application/json, so a cross-site form or a
// no-cors fetch can't change the config.
func TestWritesRequireJSON(t *testing.T) {
	base, cs, _ := newTestServer(t)
	before := string(cs.JSON())
	cases := []struct{ method, path, ctype, body string }{
		{"POST", "/api/bridge-rules", "text/plain", `{"name":"x","source_tailnet":"a","dest_tailnets":["b"],"source_tag":"tag:x","ports":[1]}`},
		{"POST", "/api/bridge-rules", "application/x-www-form-urlencoded", `name=x`},
		{"POST", "/api/bridge-rules", "multipart/form-data; boundary=x", `--x--`},
		{"POST", "/api/bridge-rules", "", `{}`},
		{"PUT", "/api/settings", "text/plain", `{"poll_interval":"1s"}`},
		{"DELETE", "/api/bridge-rules/r", "", ""},
		{"DELETE", "/api/tailnets/a", "text/plain", ""},
		{"POST", "/api/tailnets/detect", "text/plain", `{"client_id":"x","client_secret":"y"}`},
	}
	for _, c := range cases {
		resp, _ := do(t, c.method, base+c.path, c.ctype, c.body)
		if resp.StatusCode != http.StatusUnsupportedMediaType {
			t.Errorf("%s %s with %q = %d, want 415", c.method, c.path, c.ctype, resp.StatusCode)
		}
	}
	if after := string(cs.JSON()); after != before {
		t.Errorf("config changed:\n%s", after)
	}

	resp, body := do(t, "DELETE", base+"/api/bridge-rules/r", "application/json; charset=utf-8", "")
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE with JSON content type = %d: %s", resp.StatusCode, body)
	}
}

// The API takes only client_secret_file or client_secret_env. An inline
// secret is refused and never stored.
func TestTailnetAPIRejectsInlineSecret(t *testing.T) {
	base, cs, _ := newTestServer(t)
	before := string(cs.JSON())
	cases := []struct{ method, path, body string }{
		{"POST", "/api/tailnets", `{"name":"n","tailnet":"n.example","oauth":{"client_id":"x","client_secret":"inline-value"}}`},
		{"PUT", "/api/tailnets/a", `{"tailnet":"a.example","oauth":{"client_id":"x","client_secret":"inline-value"}}`},
		{"PUT", "/api/tailnets/a", `{"tailnet":"a.example","oauth":{"client_id":"x"}}`},
		{"POST", "/api/tailnets", `{"name":"n","tailnet":"n.example","oauth":{"client_id":"x","client_secret_file":"/f","client_secret_env":"E"}}`},
		{"POST", "/api/tailnets/detect", `{"client_id":"x","client_secret":"inline-value"}`},
		{"POST", "/api/tailnets/detect", `{"client_id":"x"}`},
	}
	for _, c := range cases {
		resp, body := do(t, c.method, base+c.path, "application/json", c.body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s %s %s = %d: %s", c.method, c.path, c.body, resp.StatusCode, body)
		}
		if strings.Contains(body, "inline-value") {
			t.Errorf("error echoes the secret: %s", body)
		}
	}
	if after := string(cs.JSON()); after != before {
		t.Errorf("config changed:\n%s", after)
	}

	resp, body := do(t, "PUT", base+"/api/tailnets/a", "application/json", `{"tailnet":"a.example","oauth":{"client_id":"id-a","client_secret_env":"A_SECRET"}}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT with client_secret_env = %d: %s", resp.StatusCode, body)
	}
	if got := cs.Get().Tailnets["a"].OAuth; got.ClientSecretEnv != "A_SECRET" || got.ClientSecretFile != "" {
		t.Errorf("oauth = %+v", got)
	}
}

func TestUIDefaultListenIsLoopback(t *testing.T) {
	cfg, err := config.Load(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != "127.0.0.1:8888" {
		t.Errorf("default listen = %q", cfg.ListenAddr)
	}
}
