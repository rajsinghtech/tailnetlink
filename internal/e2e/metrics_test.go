package e2e

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/bridge"
	"github.com/rajsinghtech/tailnetlink/internal/metrics"
	"github.com/rajsinghtech/tailnetlink/internal/state"
)

// metricSum adds up every series of the named counter or gauge whose labels
// include all of want.
func metricSum(t *testing.T, mt *metrics.Metrics, name string, want map[string]string) float64 {
	t.Helper()
	mfs, err := mt.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	var sum float64
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
	series:
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			for k, v := range want {
				if labels[k] != v {
					continue series
				}
			}
			sum += m.GetCounter().GetValue() + m.GetGauge().GetValue()
		}
	}
	return sum
}

func getStatus(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// /readyz says 503 until both nodes are up and the rule has polled, then
// 200. /healthz is 200 the whole time.
func TestReadyzWaitsForNodes(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	echoBackend(t, ctx, b.src, "backend", 8080)

	store := state.New()
	logs := &lockedBuffer{}
	m := bridge.New(store, slog.New(slog.NewTextHandler(logs, nil)), nil)
	mt := metrics.New()
	m.SetMetrics(mt)
	srv := httptest.NewServer(metrics.Handler(mt, m.Ready))
	defer srv.Close()
	mctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		cctx, ccancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer ccancel()
		_ = m.Close(cctx)
		if t.Failed() {
			t.Logf("tailnetlink log:\n%s", logs.String())
		}
	})

	if c, body := getStatus(t, srv.URL+"/readyz"); c != 503 {
		t.Fatalf("/readyz before start = %d %s", c, body)
	}
	if c, _ := getStatus(t, srv.URL+"/healthz"); c != 200 {
		t.Fatalf("/healthz = %d", c)
	}

	go m.Reconcile(mctx, b.config(b.deviceRule("web", "backend", "", 8080)))
	waitFor(t, 60*time.Second, "/readyz 200", func() bool {
		c, _ := getStatus(t, srv.URL+"/readyz")
		return c == 200
	})
	// Ready means both nodes are connected.
	st := store.GetStatus()
	connected := 0
	for _, tn := range st.Tailnets {
		if tn.Connected {
			connected++
		}
	}
	if connected != 2 {
		t.Errorf("ready with %d of 2 tailnets connected: %+v", connected, st.Tailnets)
	}
	if c, _ := getStatus(t, srv.URL+"/metrics"); c != 200 {
		t.Errorf("/metrics = %d", c)
	}
}

// After three echo round trips the link's byte counters match what went
// over the wire, and the connection gauges settle back to zero.
func TestMetricsCountTraffic(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	echoBackend(t, ctx, b.src, "backend", 8080)
	cl := client(t, ctx, b.dst, "client")
	r := startManager(t, b.config(b.deviceRule("web", "backend", "", 8080)), "")
	vip := waitVIP(t, b.dstAPI, b.serviceName("backend", ""))

	// Warm up first so retries while the VIP settles don't skew the counts.
	echoVia(t, ctx, cl, netip.AddrPortFrom(vip, 8080), "warmup")
	waitFor(t, 10*time.Second, "warm-up connection closed", func() bool {
		return metricSum(t, r.metrics, "tailnetlink_connections_active", nil) == 0
	})
	in0 := metricSum(t, r.metrics, "tailnetlink_bytes_total", map[string]string{"rule": "web", "direction": "in"})
	out0 := metricSum(t, r.metrics, "tailnetlink_bytes_total", map[string]string{"rule": "web", "direction": "out"})
	conns0 := metricSum(t, r.metrics, "tailnetlink_connections_total", map[string]string{"rule": "web"})

	var wantIn, wantOut float64
	for _, msg := range []string{"one", "two two", "three three three"} {
		if err := tryEcho(ctx, cl, netip.AddrPortFrom(vip, 8080), msg); err != nil {
			t.Fatalf("echo %q: %v", msg, err)
		}
		wantIn += float64(len(msg) + 1)
		wantOut += float64(len("echo: ") + len(msg) + 1)
	}
	var in, out float64
	waitFor(t, 10*time.Second, "byte counters", func() bool {
		in = metricSum(t, r.metrics, "tailnetlink_bytes_total", map[string]string{"rule": "web", "direction": "in"}) - in0
		out = metricSum(t, r.metrics, "tailnetlink_bytes_total", map[string]string{"rule": "web", "direction": "out"}) - out0
		return in >= wantIn && out >= wantOut
	})
	if in != wantIn || out != wantOut {
		t.Errorf("bytes in/out = %v/%v, want %v/%v", in, out, wantIn, wantOut)
	}
	if n := metricSum(t, r.metrics, "tailnetlink_connections_total", map[string]string{"rule": "web"}) - conns0; n != 3 {
		t.Errorf("connections = %v, want 3", n)
	}
	if n := metricSum(t, r.metrics, "tailnetlink_connections_active", nil); n != 0 {
		t.Errorf("active connections = %v after all closed", n)
	}
	if n := metricSum(t, r.metrics, "tailnetlink_bridges", map[string]string{"status": "active"}); n != 1 {
		t.Errorf("active bridges = %v, want 1", n)
	}
}
