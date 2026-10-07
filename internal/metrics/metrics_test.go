package metrics

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestEndpoint(t *testing.T) {
	for path, want := range map[string]string{
		"/api/v2/oauth/token":                    "oauth",
		"/api/v2/oauth/token-exchange":           "oauth",
		"/api/v2/tailnet/-/devices":              "devices",
		"/api/v2/tailnet/example.com/keys":       "keys",
		"/api/v2/tailnet/-/vip-services/svc:foo": "services",
		"/api/v2/tailnet/-/services/svc:foo":     "services",
		"/api/v2/tailnet/-/dns/split-dns":        "dns",
		"/api/v2/device/123":                     "devices",
		"/api/v2/tailnet/-/acl":                  "other",
		"/api/v2/tailnet":                        "other",
		"/somewhere/else":                        "other",
	} {
		if got := Endpoint(path); got != want {
			t.Errorf("Endpoint(%q) = %q, want %q", path, got, want)
		}
	}
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTransportCountsErrors(t *testing.T) {
	m := New()
	status := 200
	var fail error
	rt := m.Transport(rtFunc(func(r *http.Request) (*http.Response, error) {
		if fail != nil {
			return nil, fail
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(""))}, nil
	}))
	do := func(path string) {
		req, _ := http.NewRequest("GET", "https://api.example"+path, nil)
		if resp, err := rt.RoundTrip(req); err == nil {
			resp.Body.Close()
		}
	}
	do("/api/v2/tailnet/-/devices")
	status = 404
	do("/api/v2/tailnet/-/vip-services/svc:x")
	status = 500
	do("/api/v2/tailnet/-/vip-services/svc:x")
	status = 403
	do("/api/v2/tailnet/-/keys")
	fail = errors.New("boom")
	do("/api/v2/oauth/token")

	for ep, want := range map[string]float64{"devices": 0, "services": 1, "keys": 1, "oauth": 1} {
		if got := testutil.ToFloat64(m.apiErrors.WithLabelValues(ep)); got != want {
			t.Errorf("api errors %s = %v, want %v", ep, got, want)
		}
	}
}

func TestNilMetricsIsSafe(t *testing.T) {
	var m *Metrics
	m.ConnOpened("r")
	m.ConnClosed("r", 1, 2)
	m.DialFailed("r")
	m.PollDone("r", time.Second, errors.New("x"))
	m.Conflict("t")
	m.TrackBridges(nil, nil)
	if m.Registry() != nil {
		t.Error("nil Metrics has a registry")
	}
	if m.Transport(nil) != http.DefaultTransport {
		t.Error("nil Metrics wrapped the transport")
	}
	// Health still works without metrics; /metrics is just absent.
	srv := httptest.NewServer(Handler(nil, nil))
	defer srv.Close()
	if c := status(t, srv.URL+"/healthz"); c != 200 {
		t.Errorf("/healthz = %d", c)
	}
	if c := status(t, srv.URL+"/metrics"); c != 404 {
		t.Errorf("/metrics = %d", c)
	}
}

func TestCounters(t *testing.T) {
	m := New()
	m.ConnOpened("web")
	m.ConnOpened("web")
	m.ConnClosed("web", 10, 20)
	m.DialFailed("web")
	m.PollDone("web", 50*time.Millisecond, nil)
	m.PollDone("web", 50*time.Millisecond, errors.New("api down"))
	m.Conflict("dst")
	m.TrackBridges([]string{"active", "error"}, func() map[string]int { return map[string]int{"active": 3} })

	checks := map[string]float64{
		"active":   testutil.ToFloat64(m.connsActive.WithLabelValues("web")),
		"total":    testutil.ToFloat64(m.connsTotal.WithLabelValues("web")),
		"in":       testutil.ToFloat64(m.bytes.WithLabelValues("web", "in")),
		"out":      testutil.ToFloat64(m.bytes.WithLabelValues("web", "out")),
		"dial":     testutil.ToFloat64(m.dialFailures.WithLabelValues("web")),
		"pollerrs": testutil.ToFloat64(m.pollErrors.WithLabelValues("web")),
		"conflict": testutil.ToFloat64(m.conflicts.WithLabelValues("dst")),
	}
	want := map[string]float64{"active": 1, "total": 2, "in": 10, "out": 20, "dial": 1, "pollerrs": 1, "conflict": 1}
	for k, v := range want {
		if checks[k] != v {
			t.Errorf("%s = %v, want %v", k, checks[k], v)
		}
	}
	err := testutil.GatherAndCompare(m.reg, strings.NewReader(`
# HELP tailnetlink_bridges Bridges by status.
# TYPE tailnetlink_bridges gauge
tailnetlink_bridges{status="active"} 3
tailnetlink_bridges{status="error"} 0
`), "tailnetlink_bridges")
	if err != nil {
		t.Error(err)
	}
	if n := testutil.CollectAndCount(m.pollDuration); n != 1 {
		t.Errorf("poll duration series = %d", n)
	}
}

func status(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestHandler(t *testing.T) {
	m := New()
	ready := errors.New("tailnet \"a\" is not connected")
	srv := httptest.NewServer(Handler(m, func() error { return ready }))
	defer srv.Close()

	if c := status(t, srv.URL+"/healthz"); c != 200 {
		t.Errorf("/healthz = %d", c)
	}
	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 503 || !strings.Contains(string(body), "not connected") {
		t.Errorf("/readyz = %d %q", resp.StatusCode, body)
	}
	ready = nil
	if c := status(t, srv.URL+"/readyz"); c != 200 {
		t.Errorf("/readyz after ready = %d", c)
	}
	if c := status(t, srv.URL+"/metrics"); c != 200 {
		t.Errorf("/metrics = %d", c)
	}
	if c := status(t, srv.URL+"/"); c != 404 {
		t.Errorf("/ = %d", c)
	}
	req, _ := http.NewRequest("POST", srv.URL+"/healthz", nil)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 405 {
		t.Errorf("POST /healthz = %v %v", resp, err)
	}
}

func TestServe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, addr, Handler(nil, nil)) }()
	var c int
	for range 100 {
		if resp, err := http.Get("http://" + addr + "/healthz"); err == nil {
			c = resp.StatusCode
			resp.Body.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if c != 200 {
		t.Fatalf("/healthz = %d", c)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Serve returned %v after cancel", err)
	}
	// A taken address fails at once.
	busy, _ := net.Listen("tcp", "127.0.0.1:0")
	defer busy.Close()
	if err := Serve(context.Background(), busy.Addr().String(), Handler(nil, nil)); err == nil {
		t.Error("Serve on a taken address returned nil")
	}
}
