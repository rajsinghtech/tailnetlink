package e2e

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
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

// readRoutes are what the read-only UI serves. removedRoutes are the old
// config and CRUD routes, which are gone.
var (
	readRoutes    = []string{"/", "/api/status", "/api/bridges", "/api/connections", "/api/logs"}
	removedRoutes = []string{"/api/config", "/api/settings", "/api/tailnets", "/api/tailnets/x", "/api/tailnets/detect",
		"/api/tailnets/x/devices", "/api/tailnets/x/services", "/api/bridge-rules", "/api/bridge-rules/web"}
)

// waitUI waits until the UI at base answers.
func waitUI(t *testing.T, hc *http.Client, base string) {
	t.Helper()
	waitFor(t, 30*time.Second, "UI at "+base, func() bool {
		resp, err := hc.Get(base + "/api/status")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
}

// probeUI reads every route of the UI at base with hc, plus the SSE stream
// for 3 s, and returns everything it got back, headers included. It fails
// the test on any CORS header, a read route that isn't 200, or a removed
// route that isn't 404.
func probeUI(t *testing.T, hc *http.Client, base string) string {
	t.Helper()
	var all strings.Builder
	waitUI(t, hc, base)
	read := func(path string, want int) {
		resp, err := hc.Get(base + path)
		if err != nil {
			t.Errorf("GET %s: %v", path, err)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Header.Write(&all)
		all.Write(body)
		if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "" {
			t.Errorf("GET %s: Access-Control-Allow-Origin = %q", path, v)
		}
		if resp.StatusCode != want {
			t.Errorf("GET %s%s = %d, want %d", base, path, resp.StatusCode, want)
		}
	}
	for _, p := range readRoutes {
		read(p, http.StatusOK)
	}
	for _, p := range removedRoutes {
		read(p, http.StatusNotFound)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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

// checkNoWrites sends every non-GET method to every path, old write routes
// included, and wants 404 or 405 for all of them.
func checkNoWrites(t *testing.T, hc *http.Client, base string) {
	t.Helper()
	paths := append(append([]string{"/api/events"}, readRoutes...), removedRoutes...)
	for _, path := range paths {
		for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
			req, _ := http.NewRequest(method, base+path, strings.NewReader(`{"name":"x","ports":[1]}`))
			req.Header.Set("Content-Type", "application/json")
			resp, err := hc.Do(req)
			if err != nil {
				t.Errorf("%s %s: %v", method, path, err)
				continue
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s %s%s = %d, want 405 or 404", method, base, path, resp.StatusCode)
			}
		}
	}
}

// The read-only UI is published in both tailnets and served locally. Every
// read route works, every write is refused, and nothing it serves carries a
// secret, a client ID or a secret file path, not even the SSE stream. The
// log has no secret either.
func TestUIReadOnlyInEveryTailnet(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	echoBackend(t, ctx, b.src, "backend", 8080)
	cfg := b.config(b.deviceRule("web", "backend", "", 8080))
	webAddr := freeAddr(t)
	srcClient := client(t, ctx, b.src, "src-client")
	dstClient := client(t, ctx, b.dst, "dst-client")

	r := startManager(t, cfg, webAddr)
	waitVIP(t, b.dstAPI, b.serviceName("backend", ""))

	clients := map[string]struct {
		hc   *http.Client
		base string
	}{"local": {&http.Client{Timeout: 30 * time.Second}, "http://" + webAddr}}
	for name, c := range map[string]struct {
		n   node
		api *ctlBridge
	}{"src": {srcClient, b.srcAPI}, "dst": {dstClient, b.dstAPI}} {
		vip := waitVIP(t, c.api, "svc:tailnetlink")
		clients[name] = struct {
			hc   *http.Client
			base string
		}{httpVia(c.n, netip.AddrPortFrom(vip, 80)), "http://tailnetlink"}
	}

	got := map[string]string{}
	for name, c := range clients {
		got[name] = probeUI(t, c.hc, c.base)
		checkNoWrites(t, c.hc, c.base)
	}
	got["log"] = r.logs.String()
	private := append(b.secrets(), "client-"+b.sfx)
	private = append(private, b.secretFiles...)
	for where, body := range got {
		if where == "log" {
			if l := leaked(body, b.secrets()); len(l) != 0 {
				t.Errorf("log: leaked %v", l)
			}
			continue
		}
		if l := leaked(body, private); len(l) != 0 {
			t.Errorf("%s: leaked %v", where, l)
		}
		if !strings.Contains(body, b.src.domain) {
			t.Errorf("%s: no public config in the responses", where)
		}
	}
	if s, _ := b.dstAPI.Service(b.serviceName("backend", "")); len(s.Ports) != 1 {
		t.Errorf("writes changed the bridged service: %+v", s)
	}
}

// With ui.enabled=false no UI service is created in any tailnet. Turning it
// on in the config publishes it, and turning it off again deletes it.
func TestUIDisabled(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	echoBackend(t, ctx, b.src, "backend", 8080)
	off, on := false, true
	cfg := b.config(b.deviceRule("web", "backend", "", 8080))
	cfg.UI.Enabled = &off
	r := startManager(t, cfg, freeAddr(t))
	waitVIP(t, b.dstAPI, b.serviceName("backend", ""))
	waitFor(t, 10*time.Second, "both tailnets connected", func() bool {
		return len(r.store.GetStatus().Tailnets) == 2
	})
	time.Sleep(time.Second)
	for name, api := range map[string]*ctlBridge{"src": b.srcAPI, "dst": b.dstAPI} {
		if _, ok := api.Service("svc:tailnetlink"); ok {
			t.Errorf("UI service created in %s with ui.enabled=false", name)
		}
	}

	next := cfg.Clone()
	next.UI.Enabled = &on
	r.reconcile(next)
	waitVIP(t, b.srcAPI, "svc:tailnetlink")
	waitVIP(t, b.dstAPI, "svc:tailnetlink")

	next = next.Clone()
	next.UI.Enabled = &off
	r.reconcile(next)
	for name, api := range map[string]*ctlBridge{"src": b.srcAPI, "dst": b.dstAPI} {
		waitFor(t, 30*time.Second, "UI service gone from "+name, func() bool {
			_, ok := api.Service("svc:tailnetlink")
			return !ok
		})
	}
	if _, ok := b.dstAPI.Service(b.serviceName("backend", "")); !ok {
		t.Error("turning the UI off removed the bridged service")
	}
}

// Editing the config file while running is picked up: the bridged service
// in dst moves to the new port and traffic flows on it.
func TestConfigFileChangeMovesPort(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	backend := b.src.node(t, ctx, "backend")
	for _, p := range []int{8080, 8081} {
		ln, err := backend.srv.Listen("tcp", fmt.Sprintf(":%d", p))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go serveEcho(ln, make(chan string, 16))
	}
	cl := client(t, ctx, b.dst, "client")

	path := filepath.Join(t.TempDir(), "tailnetlink.json")
	writeBorder(t, path, b.border(b.deviceLink("web", "backend", "", 8080)))
	cs, err := config.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	cs.SetWatchInterval(50 * time.Millisecond)
	r := startManager(t, cs.Get(), "")
	cs.OnChange(r.reconcile)
	go cs.Watch(r.ctx, r.logger)

	svc := b.serviceName("backend", "")
	vip := waitVIP(t, b.dstAPI, svc)
	echoVia(t, ctx, cl, netip.AddrPortFrom(vip, 8080), "before")

	writeBorder(t, path, b.border(b.deviceLink("web", "backend", "", 8081)))
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(path, future, future)
	waitFor(t, 30*time.Second, "service moved to tcp:8081", func() bool {
		s, ok := b.dstAPI.Service(svc)
		return ok && slices.Equal(s.Ports, []string{"tcp:8081"})
	})
	vip = waitVIP(t, b.dstAPI, svc)
	echoVia(t, ctx, cl, netip.AddrPortFrom(vip, 8081), "after")
}
