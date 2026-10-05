package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/server"
)

// freeAddr returns a free loopback address.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// startUI writes cfg to a file and serves the web UI for it on webAddr.
func startUI(t *testing.T, r *running, cfg *config.Config, webAddr string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tailnetlink.json")
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cs, err := config.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	go server.New(webAddr, r.store, cs, r.logger).Run(r.ctx) //nolint:errcheck // stops with the manager
}

// leaked returns the secrets that appear in s, plain or base64 encoded.
func leaked(s string, secrets []string) []string {
	var out []string
	for _, sec := range secrets {
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

// probeUI reads every route of the UI at base with hc, plus the SSE stream
// for 2 s, and returns everything it got back, headers included. It fails
// the test on any CORS header.
func probeUI(t *testing.T, hc *http.Client, base string, b *border) string {
	t.Helper()
	var all strings.Builder
	paths := []string{
		"/", "/api/status", "/api/bridges", "/api/connections", "/api/logs", "/api/config",
		"/api/tailnets/" + b.srcName + "/devices", "/api/tailnets/" + b.dstName + "/services",
	}
	waitFor(t, 30*time.Second, "UI at "+base, func() bool {
		resp, err := hc.Get(base + "/api/status")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	read := func(method, path string) {
		req, _ := http.NewRequest(method, base+path, nil)
		resp, err := hc.Do(req)
		if err != nil {
			t.Errorf("%s %s: %v", method, path, err)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Header.Write(&all)
		all.Write(body)
		if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "" {
			t.Errorf("%s %s: Access-Control-Allow-Origin = %q", method, path, v)
		}
		if method == http.MethodGet && resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d: %s", path, resp.StatusCode, body)
		}
	}
	for _, p := range paths {
		read(http.MethodGet, p)
	}
	read(http.MethodOptions, "/api/config")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/events", nil)
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("SSE: %v", err)
	}
	defer resp.Body.Close()
	if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "" {
		t.Errorf("SSE Access-Control-Allow-Origin = %q", v)
	}
	sse, _ := io.ReadAll(resp.Body) // ends when ctx expires
	if !strings.Contains(string(sse), "event: init") {
		t.Errorf("no SSE init event from %s", base)
	}
	all.Write(sse)
	return all.String()
}

// No secret leaves tailnetlink over HTTP: not from the local listener, not
// through svc:tailnetlink from either tailnet, not in the SSE stream and
// not in the log. Flipped from TestKnownBad_SecretsOverHTTP.
func TestNoSecretsOverHTTP(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	echoBackend(t, ctx, b.src, "backend", 8080)
	cfg := b.config(b.deviceRule("web", "backend", "", 8080))
	webAddr := freeAddr(t)
	srcClient := client(t, ctx, b.src, "src-client")
	dstClient := client(t, ctx, b.dst, "dst-client")

	r := startManager(t, cfg, webAddr)
	startUI(t, r, cfg, webAddr)
	waitVIP(t, b.dstAPI, b.serviceName("backend", ""))

	got := map[string]string{"local": probeUI(t, &http.Client{Timeout: 30 * time.Second}, "http://"+webAddr, b)}
	for name, c := range map[string]struct {
		n   node
		api *ctlBridge
	}{"src": {srcClient, b.srcAPI}, "dst": {dstClient, b.dstAPI}} {
		vip := waitVIP(t, c.api, "svc:tailnetlink")
		got[name] = probeUI(t, httpVia(c.n, netip.AddrPortFrom(vip, 80)), "http://tailnetlink", b)
	}
	got["log"] = r.logs.String()
	for where, body := range got {
		if l := leaked(body, b.secrets()); len(l) != 0 {
			t.Errorf("%s: leaked %v", where, l)
		}
		if where != "log" && !strings.Contains(body, config.RedactedSecret) {
			t.Errorf("%s: no redacted config in the responses", where)
		}
	}
}
