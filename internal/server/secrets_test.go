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
)

var testSecrets = []string{"alpha-secret-0001", "beta-secret-0002"}

// newTestServer serves the UI for a config with two tailnets and a rule,
// and returns its URL and config store.
func newTestServer(t *testing.T) (string, *config.Store) {
	t.Helper()
	dir := t.TempDir()
	files := make([]string, len(testSecrets))
	for i, sec := range testSecrets {
		files[i] = filepath.Join(dir, fmt.Sprintf("secret-%d", i))
		if err := os.WriteFile(files[i], []byte(sec+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	b := config.File{
		Name: "test",
		Tailnets: map[string]config.TailnetSpec{
			"a": {Tailnet: "a.example", Tags: []string{"tag:tnl"}, Auth: config.OAuthCreds{ClientID: "id-a", ClientSecretFile: files[0]}},
			"b": {Tailnet: "b.example", Tags: []string{"tag:tnl"}, Auth: config.OAuthCreds{ClientID: "id-b", ClientSecretFile: files[1]}},
		},
		Targets: map[string]config.TargetSpec{
			"r": {In: "a", Tag: "tag:web", Ports: config.LocalPortList(80)},
		},
		Exports: []config.ExportSpec{{Target: "r", To: []string{"b"}}},
	}
	path := filepath.Join(dir, "c.json")
	data, _ := json.Marshal(b)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cs, err := config.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	st := state.New()
	st.Log("info", "hello", nil)
	srv := httptest.NewServer(New("", st, cs.Get, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	t.Cleanup(srv.Close)
	return srv.URL, cs
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

// sensitive is everything the UI must never show: the secrets, plus the
// client IDs and secret file paths, which the public config view leaves
// out along with the rest of each oauth block.
func sensitive(t *testing.T, s string) []string {
	out := leaks(s)
	for _, v := range []string{"id-a", "id-b", "secret-0", "secret-1", "client_secret", "oauth"} {
		if strings.Contains(s, v) {
			out = append(out, v)
		}
	}
	return out
}

// readRoutes are the only routes the read-only UI serves.
var readRoutes = []string{"/", "/index.html", "/api/status", "/api/bridges", "/api/connections", "/api/logs"}

// removedRoutes are the old write and config routes. They are all gone.
var removedRoutes = []string{
	"/api/config", "/api/settings", "/api/tailnets", "/api/tailnets/a", "/api/tailnets/detect",
	"/api/tailnets/a/devices", "/api/tailnets/b/services", "/api/bridge-rules", "/api/bridge-rules/r",
}

// No route hands out a secret or the oauth settings, there is no CORS header
// anywhere, and the SSE init event carries only the public config.
func TestNoRouteServesSecrets(t *testing.T) {
	base, _ := newTestServer(t)
	for _, path := range append(append([]string{"/api/nope"}, readRoutes...), removedRoutes...) {
		for _, method := range []string{"GET", "HEAD", "OPTIONS", "POST"} {
			resp, body := do(t, method, base+path, "application/json", `{}`)
			if l := sensitive(t, body+dumpHeaders(resp.Header)); len(l) != 0 {
				t.Errorf("%s %s (%d) leaked %v:\n%s", method, path, resp.StatusCode, l, body)
			}
			if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "" {
				t.Errorf("%s %s: Access-Control-Allow-Origin = %q", method, path, v)
			}
		}
	}

	init := sseInit(t, base)
	if !strings.Contains(init, `"config"`) || !strings.Contains(init, "a.example") || !strings.Contains(init, "tag:web") {
		t.Fatalf("SSE init event missing the public config: %s", init)
	}
	if l := sensitive(t, init); len(l) != 0 {
		t.Errorf("SSE init leaked %v", l)
	}
}

func sseInit(t *testing.T, base string) string {
	t.Helper()
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
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "data: ") {
			return sc.Text()
		}
	}
	t.Fatal("no SSE init event")
	return ""
}

// The UI is read-only: every method but GET and HEAD gets 405 on every
// path, whatever the content type, and the config is never touched.
func TestEveryWriteIsRejected(t *testing.T) {
	base, cs := newTestServer(t)
	before := string(cs.Get().PublicJSON())
	paths := append(append([]string{"/api/events", "/api/nope"}, readRoutes...), removedRoutes...)
	for _, path := range paths {
		for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"} {
			for _, ctype := range []string{"application/json", "text/plain", ""} {
				resp, _ := do(t, method, base+path, ctype, `{"name":"x","poll_interval":"1s"}`)
				if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotFound {
					t.Errorf("%s %s (%q) = %d, want 405 or 404", method, path, ctype, resp.StatusCode)
				}
			}
		}
	}
	if after := string(cs.Get().PublicJSON()); after != before {
		t.Errorf("config changed:\n%s", after)
	}
}

// The old config and CRUD routes don't exist any more.
func TestRemovedRoutesAreGone(t *testing.T) {
	base, _ := newTestServer(t)
	for _, path := range removedRoutes {
		resp, _ := do(t, "GET", base+path, "", "")
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, resp.StatusCode)
		}
	}
	for _, path := range readRoutes {
		resp, body := do(t, "GET", base+path, "", "")
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d: %s", path, resp.StatusCode, body)
		}
	}
}

// The page has no forms or calls to write routes left.
func TestPageHasNoWriteControls(t *testing.T) {
	base, _ := newTestServer(t)
	_, page := do(t, "GET", base+"/", "", "")
	for _, bad := range []string{"<form", "method: 'POST'", "method:'POST'", "method: 'PUT'", "method:'DELETE'", "/api/tailnets", "/api/bridge-rules", "/api/settings", "client_secret"} {
		if strings.Contains(page, bad) {
			t.Errorf("page still has %q", bad)
		}
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
