package e2e

import (
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

// Tests named TestKnownBad_* pin behavior the roadmap says is wrong, end to
// end. The PR that fixes the behavior flips the assertion and renames the
// test.

// KNOWN-BAD: stopping the manager deletes every service it created. Flip in
// roadmap PR 6.
func TestKnownBad_ManagerShutdownDeletesServices(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	echoBackend(t, ctx, b.src, "backend", 8080)
	r := startManager(t, b.config(b.deviceRule("web", "backend", "", 8080)), "")
	svc := b.serviceName("backend", "")
	waitVIP(t, b.dstAPI, svc)

	r.cancel()
	waitFor(t, 30*time.Second, "service deleted on shutdown", func() bool {
		_, ok := b.dstAPI.Service(svc)
		return !ok
	})
}

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
	go server.New(webAddr, r.store, cs, r.logger).Run() //nolint:errcheck // Run never returns today
}

// KNOWN-BAD: the web UI hands out the OAuth client secrets, locally and to
// every peer that can reach svc:tailnetlink. Flip in roadmap PR 7.
func TestKnownBad_SecretsOverHTTP(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	cfg := b.config()
	webAddr := freeAddr(t)
	srcClient := client(t, ctx, b.src, "src-client")
	dstClient := client(t, ctx, b.dst, "dst-client")

	r := startManager(t, cfg, webAddr)
	startUI(t, r, cfg, webAddr)

	get := func(hc *http.Client, url string) string {
		var body string
		waitFor(t, 30*time.Second, "GET "+url, func() bool {
			resp, err := hc.Get(url)
			if err != nil {
				return false
			}
			defer resp.Body.Close()
			data, _ := io.ReadAll(resp.Body)
			body = string(data)
			return resp.StatusCode == http.StatusOK
		})
		return body
	}

	bodies := map[string]string{"local": get(http.DefaultClient, "http://"+webAddr+"/api/config")}
	for name, c := range map[string]struct {
		n   node
		api *ctlBridge
	}{"src": {srcClient, b.srcAPI}, "dst": {dstClient, b.dstAPI}} {
		vip := waitVIP(t, c.api, "svc:tailnetlink")
		bodies[name] = get(httpVia(c.n, netip.AddrPortFrom(vip, 80)), "http://tailnetlink/api/config")
	}
	for where, body := range bodies {
		for _, s := range b.secrets() {
			if !strings.Contains(body, s) {
				t.Errorf("%s: expected the secret in /api/config today", where)
			}
		}
	}
}
