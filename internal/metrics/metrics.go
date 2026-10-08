// Package metrics holds tailnetlink's Prometheus metrics and the health
// endpoints. Everything is on its own registry so several instances (or
// tests) in one process don't share counters.
//
// Labels are kept bounded: rule names come from the config, endpoints and
// directions are fixed sets, and nothing is labelled per device, client or
// connection.
package metrics

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/rajsinghtech/tailnetlink/internal/tsapi"
)

// Metrics is safe to use as a nil pointer: every method does nothing then.
type Metrics struct {
	reg *prometheus.Registry

	connsActive  *prometheus.GaugeVec
	connsTotal   *prometheus.CounterVec
	bytes        *prometheus.CounterVec
	dialFailures *prometheus.CounterVec
	routedDials  *prometheus.CounterVec
	apiErrors    *prometheus.CounterVec
	apiRequests  *prometheus.CounterVec
	apiLatency   *prometheus.HistogramVec
	pollDuration *prometheus.HistogramVec
	pollErrors   *prometheus.CounterVec
	conflicts    *prometheus.CounterVec
}

// New returns metrics on a fresh registry that also carries the Go runtime
// and process collectors.
func New() *Metrics {
	m := &Metrics{
		reg: prometheus.NewRegistry(),
		connsActive: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tailnetlink_connections_active",
			Help: "Connections currently being forwarded.",
		}, []string{"rule"}),
		connsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tailnetlink_connections_total",
			Help: "Connections forwarded, counted when the backend dial succeeds.",
		}, []string{"rule"}),
		bytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tailnetlink_bytes_total",
			Help: "Bytes forwarded. direction is in (client to backend) or out (backend to client).",
		}, []string{"rule", "direction"}),
		dialFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tailnetlink_dial_failures_total",
			Help: "Backend dials that failed.",
		}, []string{"rule"}),
		routedDials: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tailnetlink_routed_dial_failures_total",
			Help: "Routed dials that failed. reason is no_route (nothing in the source tailnet covers that IP, or this node is not accepting subnet routes) or denied (the dial was filtered or timed out; a missing grant drops the packets).",
		}, []string{"rule", "reason"}),
		apiErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tailnetlink_api_errors_total",
			Help: "Tailscale API requests that failed or returned an error status (404 is not counted).",
		}, []string{"endpoint"}),
		apiRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tailnetlink_api_requests_total",
			Help: "Tailscale API attempts by endpoint and HTTP status. code is the status, or \"error\" when the attempt did not get a response. 429 is counted on its own so it can be alerted on.",
		}, []string{"endpoint", "code"}),
		apiLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "tailnetlink_api_request_duration_seconds",
			Help:    "How long one Tailscale API attempt took.",
			Buckets: prometheus.DefBuckets,
		}, []string{"endpoint"}),
		pollDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "tailnetlink_poll_duration_seconds",
			Help:    "How long a discovery poll took.",
			Buckets: prometheus.DefBuckets,
		}, []string{"rule"}),
		pollErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tailnetlink_poll_errors_total",
			Help: "Discovery polls that failed.",
		}, []string{"rule"}),
		conflicts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tailnetlink_ownership_conflicts_total",
			Help: "Times a wanted service name was taken by something this instance doesn't own.",
		}, []string{"tailnet"}),
	}
	m.reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.connsActive, m.connsTotal, m.bytes, m.dialFailures, m.routedDials,
		m.apiErrors, m.apiRequests, m.apiLatency, m.pollDuration, m.pollErrors, m.conflicts,
	)
	return m
}

// Registry is where everything is registered; tests read from it.
func (m *Metrics) Registry() *prometheus.Registry {
	if m == nil {
		return nil
	}
	return m.reg
}

// TrackBridges exports tailnetlink_bridges{status}, read from count at
// scrape time. count returns the number of bridges per status.
func (m *Metrics) TrackBridges(statuses []string, count func() map[string]int) {
	if m == nil {
		return
	}
	m.reg.MustRegister(&bridgeCollector{statuses: statuses, count: count})
}

var bridgesDesc = prometheus.NewDesc("tailnetlink_bridges", "Bridges by status.", []string{"status"}, nil)

type bridgeCollector struct {
	statuses []string
	count    func() map[string]int
}

func (c *bridgeCollector) Describe(ch chan<- *prometheus.Desc) { ch <- bridgesDesc }

func (c *bridgeCollector) Collect(ch chan<- prometheus.Metric) {
	counts := c.count()
	for _, s := range c.statuses {
		ch <- prometheus.MustNewConstMetric(bridgesDesc, prometheus.GaugeValue, float64(counts[s]), s)
	}
}

// TrackNodes exports tailnetlink_node_up{tailnet}. up returns 1 or 0 per
// tailnet label. Labels come from the configured tailnets, not from
// discovered devices.
func (m *Metrics) TrackNodes(up func() map[string]float64) {
	if m == nil {
		return
	}
	m.reg.MustRegister(&nodeCollector{up: up})
}

var nodeDesc = prometheus.NewDesc(
	"tailnetlink_node_up",
	"1 when this process's node in the tailnet is connected.",
	[]string{"tailnet"},
	nil,
)

type nodeCollector struct {
	up func() map[string]float64
}

func (c *nodeCollector) Describe(ch chan<- *prometheus.Desc) { ch <- nodeDesc }

func (c *nodeCollector) Collect(ch chan<- prometheus.Metric) {
	states := c.up()
	names := make([]string, 0, len(states))
	for name := range states {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		ch <- prometheus.MustNewConstMetric(nodeDesc, prometheus.GaugeValue, states[name], name)
	}
}

// TrackVIPServices exports tailnetlink_vip_services{tailnet,state}. state is
// desired (a listen was started) or advertised (the name was then found in
// the node's AdvertiseServices). count is read at scrape time.
func (m *Metrics) TrackVIPServices(count func() (desired, advertised map[string]int)) {
	if m == nil {
		return
	}
	m.reg.MustRegister(&vipCollector{count: count})
}

var vipDesc = prometheus.NewDesc(
	"tailnetlink_vip_services",
	"VIP services this process intends to host (desired) and has verified in AdvertiseServices (advertised).",
	[]string{"tailnet", "state"},
	nil,
)

type vipCollector struct {
	count func() (desired, advertised map[string]int)
}

func (c *vipCollector) Describe(ch chan<- *prometheus.Desc) { ch <- vipDesc }

func (c *vipCollector) Collect(ch chan<- prometheus.Metric) {
	desired, advertised := c.count()
	seen := map[string]struct{}{}
	var names []string
	for _, set := range []map[string]int{desired, advertised} {
		for name := range set {
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, tn := range names {
		ch <- prometheus.MustNewConstMetric(vipDesc, prometheus.GaugeValue, float64(desired[tn]), tn, "desired")
		ch <- prometheus.MustNewConstMetric(vipDesc, prometheus.GaugeValue, float64(advertised[tn]), tn, "advertised")
	}
}

// ConnOpened records a forwarded connection starting on rule.
func (m *Metrics) ConnOpened(rule string) {
	if m == nil {
		return
	}
	m.connsTotal.WithLabelValues(rule).Inc()
	m.connsActive.WithLabelValues(rule).Inc()
}

// ConnClosed records a forwarded connection ending, with the bytes it moved.
func (m *Metrics) ConnClosed(rule string, in, out int64) {
	if m == nil {
		return
	}
	m.connsActive.WithLabelValues(rule).Dec()
	m.bytes.WithLabelValues(rule, "in").Add(float64(in))
	m.bytes.WithLabelValues(rule, "out").Add(float64(out))
}

// DialFailed records a failed backend dial on rule.
func (m *Metrics) DialFailed(rule string) {
	if m == nil {
		return
	}
	m.dialFailures.WithLabelValues(rule).Inc()
}

// RoutedDialFailed records a failed dial through a source-tailnet subnet route.
// reason is no_route, denied, or error.
func (m *Metrics) RoutedDialFailed(rule, reason string) {
	if m == nil {
		return
	}
	switch reason {
	case "no_route", "denied", "error":
	default:
		reason = "error"
	}
	m.routedDials.WithLabelValues(rule, reason).Inc()
}

// PollDone records one discovery poll for rule.
func (m *Metrics) PollDone(rule string, d time.Duration, err error) {
	if m == nil {
		return
	}
	m.pollDuration.WithLabelValues(rule).Observe(d.Seconds())
	if err != nil {
		m.pollErrors.WithLabelValues(rule).Inc()
	}
}

// ObserveAPI records one admin API attempt, including retries. A nil
// Metrics ignores it.
func (m *Metrics) ObserveAPI(a tsapi.APIAttempt) {
	if m == nil {
		return
	}
	code := "error"
	if a.Err == nil {
		code = strconv.Itoa(a.Code)
	}
	ep := Endpoint(a.Path)
	m.apiRequests.WithLabelValues(ep, code).Inc()
	m.apiLatency.WithLabelValues(ep).Observe(a.Duration.Seconds())
	if a.Err != nil || (a.Code >= 400 && a.Code != http.StatusNotFound) {
		m.apiErrors.WithLabelValues(ep).Inc()
	}
}

// Conflict records an ownership conflict in tailnet.
func (m *Metrics) Conflict(tailnet string) {
	if m == nil {
		return
	}
	m.conflicts.WithLabelValues(tailnet).Inc()
}

// Transport wraps base (http.DefaultTransport if nil) so failed Tailscale
// API requests are counted by endpoint. A nil Metrics returns base as is.
func (m *Metrics) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if m == nil {
		return base
	}
	return &countingTransport{base: base, m: m}
}

type countingTransport struct {
	base http.RoundTripper
	m    *Metrics
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || (resp.StatusCode >= 400 && resp.StatusCode != http.StatusNotFound) {
		t.m.apiErrors.WithLabelValues(Endpoint(req.URL.Path)).Inc()
	}
	return resp, err
}

// Endpoint maps a Tailscale API path to a small fixed set of names, so the
// endpoint label can't grow with tailnet or service names.
func Endpoint(path string) string {
	rest, ok := strings.CutPrefix(path, "/api/v2/")
	if !ok {
		return "other"
	}
	if strings.HasPrefix(rest, "oauth/") {
		return "oauth"
	}
	parts := strings.Split(rest, "/")
	switch {
	case len(parts) >= 3 && parts[0] == "tailnet":
		switch parts[2] {
		case "devices", "keys", "dns":
			return parts[2]
		case "vip-services", "services":
			return "services"
		}
	case len(parts) >= 1 && parts[0] == "device":
		return "devices"
	}
	return "other"
}
