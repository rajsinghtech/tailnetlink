package tsapi

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLimitedTransportRetries429(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	var attempts []APIAttempt
	rt := LimitedTransport(http.DefaultTransport, 0, 0, obsFunc(func(a APIAttempt) { attempts = append(attempts, a) }))
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v2/tailnet/-/devices", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if n.Load() != 2 {
		t.Fatalf("attempts = %d, want 2", n.Load())
	}
	if len(attempts) != 2 || attempts[0].Code != 429 || attempts[1].Code != 200 {
		t.Fatalf("observed = %+v", attempts)
	}
}

type obsFunc func(APIAttempt)

func (f obsFunc) ObserveAPI(a APIAttempt) { f(a) }

func TestLimitedTransportDoesNotRetry404OrPost5xx(t *testing.T) {
	var gets, posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
			http.Error(w, "no", http.StatusInternalServerError)
			return
		}
		gets.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	rt := LimitedTransport(http.DefaultTransport, 0, 0, nil)
	for _, tc := range []struct {
		method string
		want   int
	}{
		{http.MethodGet, 1},
		{http.MethodPost, 1},
	} {
		req, _ := http.NewRequest(tc.method, srv.URL+"/api/v2/tailnet/-/keys", strings.NewReader("x"))
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if gets.Load() != 1 || posts.Load() != 1 {
		t.Fatalf("gets=%d posts=%d, want 1 and 1", gets.Load(), posts.Load())
	}
}

func TestLimitedTransportRetriesGet5xxWithinBudget(t *testing.T) {
	old := apiRetryWait
	var waits atomic.Int32
	apiRetryWait = func(context.Context, time.Duration) error {
		waits.Add(1)
		return nil
	}
	t.Cleanup(func() { apiRetryWait = old })

	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer srv.Close()
	rt := LimitedTransport(http.DefaultTransport, 0, 0, nil)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v2/tailnet/-/vip-services", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if n.Load() != maxAPIAttempts {
		t.Fatalf("attempts = %d, want %d", n.Load(), maxAPIAttempts)
	}
	if waits.Load() != maxAPIAttempts-1 {
		t.Fatalf("waits = %d, want %d", waits.Load(), maxAPIAttempts-1)
	}
}

func TestLimitedTransportReplaysBody(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, string(b))
		if len(got) == 1 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, "later", http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	rt := LimitedTransport(http.DefaultTransport, 0, 0, nil)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/v2/tailnet/-/vip-services/svc:a", strings.NewReader(`{"name":"svc:a"}`))
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(got) != 2 || got[0] != got[1] || got[0] != `{"name":"svc:a"}` {
		t.Fatalf("bodies = %q", got)
	}
}

func TestLimitedTransportHonorsRetryAfter(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "later", http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	rt := LimitedTransport(http.DefaultTransport, 0, 0, nil)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v2/tailnet/-/devices", nil)
	start := time.Now()
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if d := time.Since(start); d < time.Second {
		t.Fatalf("returned in %s, Retry-After was 1s", d)
	}
	if n.Load() != 2 || resp.StatusCode != 200 {
		t.Fatalf("attempts=%d status=%d", n.Load(), resp.StatusCode)
	}
}

func TestRetryAfterParsingAndBudget(t *testing.T) {
	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
	if d, ok := parseRetryAfter(past); !ok || d != 0 {
		t.Fatalf("past date = %s ok=%v", d, ok)
	}
	if _, ok := parseRetryAfter("not-a-date"); ok {
		t.Fatal("garbage parsed")
	}
	if _, ok := parseRetryAfter(""); ok {
		t.Fatal("empty parsed")
	}
	if d, ok := parseRetryAfter("2"); !ok || d != 2*time.Second {
		t.Fatalf("seconds = %s ok=%v", d, ok)
	}

	// A huge Retry-After exceeds the wait budget, so the 429 is returned
	// without sleeping.
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.Header().Set("Retry-After", "100")
		http.Error(w, "later", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	rt := LimitedTransport(http.DefaultTransport, 0, 0, nil)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v2/tailnet/-/devices", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if n.Load() != 1 || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("attempts=%d status=%d", n.Load(), resp.StatusCode)
	}

	// burst < 1 is raised to 1, and a cancelled context stops the wait.
	paced := LimitedTransport(http.DefaultTransport, 1, 0, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/x", nil)
	if _, err := paced.RoundTrip(req); err == nil {
		t.Fatal("cancelled request succeeded")
	}

	big := bytes.Repeat([]byte("a"), 8<<20+1)
	req, _ = http.NewRequest(http.MethodPut, srv.URL+"/x", io.NopCloser(bytes.NewReader(big)))
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("oversized body was accepted")
	}
}

func TestTokenBucketSpacesRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	// 20/s, burst 2. 12 requests need at least (12-2)/20 = 500ms.
	rt := LimitedTransport(http.DefaultTransport, 20, 2, nil)
	start := time.Now()
	for range 12 {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v2/tailnet/-/devices", nil)
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if d := time.Since(start); d < 400*time.Millisecond {
		t.Fatalf("12 requests took %s, bucket did not pace them", d)
	}
}
