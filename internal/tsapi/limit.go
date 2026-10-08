package tsapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// DefaultAPIRatePerSec and DefaultAPIBurst pace one tailnet's admin API
// client. Each tailnet has its own client, so each has its own bucket.
const (
	DefaultAPIRatePerSec = 20
	DefaultAPIBurst      = 40
)

// How many times one call is sent, including the first, and how long we
// are willing to spend waiting between those tries.
const (
	maxAPIAttempts  = 4
	maxAPIRetryWait = 30 * time.Second
)

// APIAttempt is one try against the admin API, successful or not.
type APIAttempt struct {
	Path     string
	Code     int // 0 when the round trip itself failed
	Err      error
	Duration time.Duration
}

// APIObserver records each try. A 429 is visible here even when a later
// try succeeds.
type APIObserver interface {
	ObserveAPI(APIAttempt)
}

// apiRetryWait sleeps before a retry. Tests replace it.
var apiRetryWait = func(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// LimitedTransport paces requests with a token bucket and retries 429 and
// 5xx. POST is not retried on 5xx: creating a key or exchanging a token may
// already have happened. 429 is retried for every method, honoring
// Retry-After. perSec <= 0 disables the bucket.
func LimitedTransport(base http.RoundTripper, perSec float64, burst int, obs APIObserver) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	var lim *rate.Limiter
	if perSec > 0 {
		if burst < 1 {
			burst = 1
		}
		lim = rate.NewLimiter(rate.Limit(perSec), burst)
	}
	return &limitedTransport{base: base, lim: lim, obs: obs}
}

type limitedTransport struct {
	base http.RoundTripper
	lim  *rate.Limiter
	obs  APIObserver
}

func (t *limitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := bufferBody(req); err != nil {
		return nil, err
	}
	var waited time.Duration
	var resp *http.Response
	var err error
	for attempt := 1; attempt <= maxAPIAttempts; attempt++ {
		if t.lim != nil {
			if err := t.lim.Wait(req.Context()); err != nil {
				return nil, err
			}
		}
		r, rerr := cloneReq(req, attempt > 1)
		if rerr != nil {
			return nil, rerr
		}
		start := time.Now()
		resp, err = t.base.RoundTrip(r)
		t.observe(req, resp, err, time.Since(start))
		if !shouldRetry(req, resp, err) || attempt == maxAPIAttempts {
			return resp, err
		}
		delay := retryDelay(resp, attempt)
		if waited+delay > maxAPIRetryWait {
			return resp, err
		}
		drain(resp)
		if err := apiRetryWait(req.Context(), delay); err != nil {
			return nil, err
		}
		waited += delay
	}
	return resp, err
}

func (t *limitedTransport) observe(req *http.Request, resp *http.Response, err error, d time.Duration) {
	if t.obs == nil {
		return
	}
	code := 0
	if resp != nil {
		code = resp.StatusCode
	}
	t.obs.ObserveAPI(APIAttempt{Path: req.URL.Path, Code: code, Err: err, Duration: d})
}

func shouldRetry(req *http.Request, resp *http.Response, err error) bool {
	if err != nil || resp == nil {
		return false
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return true
	}
	if resp.StatusCode >= 500 && req.Method != http.MethodPost {
		return true
	}
	return false
}

func retryDelay(resp *http.Response, attempt int) time.Duration {
	if resp != nil {
		if d, ok := parseRetryAfter(resp.Header.Get("Retry-After")); ok {
			return d + retryJitter(d)
		}
	}
	shift := attempt - 1
	if shift > 5 {
		shift = 5
	}
	d := 100 * time.Millisecond << shift
	if d > 5*time.Second {
		d = 5 * time.Second
	}
	return d + retryJitter(d)
}

func parseRetryAfter(v string) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second, true
	}
	if when, err := http.ParseTime(v); err == nil {
		d := time.Until(when)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

var (
	jitterMu  sync.Mutex
	jitterRNG = rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 1))
)

func retryJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	jitterMu.Lock()
	n := jitterRNG.Int64N(int64(d/4) + 1)
	jitterMu.Unlock()
	return time.Duration(n)
}

// bufferBody makes req replayable. The admin client builds bodies with
// bytes.Buffer, which does not set GetBody, so a retry would otherwise
// send an empty body.
func bufferBody(req *http.Request) error {
	if req.Body == nil || req.Body == http.NoBody || req.GetBody != nil {
		return nil
	}
	buf, err := io.ReadAll(io.LimitReader(req.Body, 8<<20+1))
	_ = req.Body.Close()
	if err != nil {
		return err
	}
	if len(buf) > 8<<20 {
		return errors.New("request body too large to retry")
	}
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf)), nil
	}
	req.Body, _ = req.GetBody()
	req.ContentLength = int64(len(buf))
	return nil
}
