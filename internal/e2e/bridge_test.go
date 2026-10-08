package e2e

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	tsclient "tailscale.com/client/tailscale/v2"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

// ctlBridge serves the parts of the admin API that tailnetlink calls, for one
// testcontrol tailnet. It keeps VIP services and split-DNS in memory and
// mirrors them into testcontrol the way the real control plane would: nodes
// get their tags, and a tagged node gets the service-host capability and the
// VIP route for every service carrying one of its tags.
type ctlBridge struct {
	tn  *tailnet
	srv *httptest.Server

	// secret, when set, is the only OAuth client secret the token endpoint
	// accepts.
	secret string

	mu       sync.Mutex
	calls    []string
	services map[string]tsclient.VIPService
	splitDNS map[string][]string
	hostTags map[string][]string // hostname prefix -> tags
	nextIP   int
	applied  map[key.NodePublic]string
	// wakeUntil / wakeNext replay a publish. testcontrol keeps one wake per
	// node and drops the rest, and a map poll replaced during startup never
	// reads the dropped one. The fingerprint would otherwise not try again,
	// so the client dials the VIP through the kernel and times out.
	wakeUntil map[key.NodePublic]time.Time
	wakeNext  map[key.NodePublic]time.Time
	hidden    map[string]bool
	stop      chan struct{}
}

func newCtlBridge(t *testing.T, tn *tailnet) *ctlBridge {
	t.Helper()
	b := &ctlBridge{
		tn:        tn,
		services:  map[string]tsclient.VIPService{},
		splitDNS:  map[string][]string{},
		hostTags:  map[string][]string{"tailnetlink-": {"tag:tailnetlink"}},
		nextIP:    1,
		applied:   map[key.NodePublic]string{},
		wakeUntil: map[key.NodePublic]time.Time{},
		wakeNext:  map[key.NodePublic]time.Time{},
		hidden:    map[string]bool{},
		stop:      make(chan struct{}),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v2/oauth/token", b.token)
	for _, p := range []string{"vip-services", "services"} {
		mux.HandleFunc("GET /api/v2/tailnet/{tn}/"+p, b.listServices)
		mux.HandleFunc("GET /api/v2/tailnet/{tn}/"+p+"/{name}", b.getService)
		mux.HandleFunc("PUT /api/v2/tailnet/{tn}/"+p+"/{name}", b.putService)
		mux.HandleFunc("DELETE /api/v2/tailnet/{tn}/"+p+"/{name}", b.deleteService)
	}
	mux.HandleFunc("GET /api/v2/tailnet/{tn}/dns/split-dns", b.getSplitDNS)
	mux.HandleFunc("PATCH /api/v2/tailnet/{tn}/dns/split-dns", b.patchSplitDNS)
	mux.HandleFunc("GET /api/v2/tailnet/{tn}/devices", b.listDevices)
	mux.HandleFunc("POST /api/v2/tailnet/{tn}/keys", b.createKey)
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.calls = append(b.calls, r.Method+" "+r.URL.Path)
		b.mu.Unlock()
		if r.URL.Path != "/api/v2/oauth/token" && r.Header.Get("Authorization") == "" {
			http.Error(w, `{"message":"missing auth"}`, http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	go b.syncLoop()
	t.Cleanup(func() {
		close(b.stop)
		b.srv.Close()
	})
	return b
}

func (b *ctlBridge) URL() string { return b.srv.URL }

// hide drops a node from the device list, as if it was removed in the admin
// console. testcontrol itself has no way to delete a node.
func (b *ctlBridge) hide(hostname string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.hidden[hostname] = true
}

func (b *ctlBridge) isHidden(hostname string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.hidden[hostname]
}

// setHostTags sets the tags given to nodes whose hostname starts with prefix.
func (b *ctlBridge) setHostTags(prefix string, tags ...string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.hostTags[prefix] = tags
}

// Calls returns every request so far as "METHOD /path".
func (b *ctlBridge) Calls() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.calls)
}

// Writes returns the non-GET API calls, leaving out token requests.
func (b *ctlBridge) Writes() []string {
	var out []string
	for _, c := range b.Calls() {
		if !strings.HasPrefix(c, "GET ") && !strings.Contains(c, "/oauth/token") {
			out = append(out, c)
		}
	}
	return out
}

func (b *ctlBridge) ResetCalls() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = nil
}

// Service returns a VIP service and whether it exists.
func (b *ctlBridge) Service(name string) (tsclient.VIPService, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.services[name]
	return s, ok
}

// PutService creates or replaces a service by hand, as an admin would.
// ServiceNames returns the names of every service, sorted.
func (b *ctlBridge) ServiceNames() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Sorted(maps.Keys(b.services))
}

func (b *ctlBridge) PutService(svc tsclient.VIPService) tsclient.VIPService {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.putLocked(svc)
}

func (b *ctlBridge) SplitDNS(zone string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.splitDNS[zone])
}

func (b *ctlBridge) putLocked(svc tsclient.VIPService) tsclient.VIPService {
	if len(svc.Addrs) == 0 {
		if old, ok := b.services[svc.Name]; ok {
			svc.Addrs = old.Addrs
		} else {
			svc.Addrs = []string{fmt.Sprintf("100.11.0.%d", b.nextIP)}
			b.nextIP++
		}
	}
	b.services[svc.Name] = svc
	return svc
}

func (b *ctlBridge) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	secret := r.PostForm.Get("client_secret")
	if secret == "" {
		if _, p, ok := r.BasicAuth(); ok {
			secret = p
		}
	}
	if b.secret != "" && secret != b.secret {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]any{"access_token": "e2e-token", "token_type": "Bearer", "expires_in": 3600})
}

func (b *ctlBridge) listServices(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	names := slices.Sorted(maps.Keys(b.services))
	out := make([]tsclient.VIPService, 0, len(names))
	for _, n := range names {
		out = append(out, b.services[n])
	}
	b.mu.Unlock()
	writeJSON(w, map[string]any{"vipServices": out})
}

func (b *ctlBridge) getService(w http.ResponseWriter, r *http.Request) {
	svc, ok := b.Service(r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, svc)
}

func (b *ctlBridge) putService(w http.ResponseWriter, r *http.Request) {
	var svc tsclient.VIPService
	if err := json.NewDecoder(r.Body).Decode(&svc); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	svc.Name = r.PathValue("name")
	b.PutService(svc)
	writeJSON(w, map[string]any{})
}

func (b *ctlBridge) deleteService(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	_, ok := b.services[r.PathValue("name")]
	delete(b.services, r.PathValue("name"))
	b.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, map[string]any{})
}

func (b *ctlBridge) getSplitDNS(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	out := maps.Clone(b.splitDNS)
	b.mu.Unlock()
	writeJSON(w, out)
}

func (b *ctlBridge) patchSplitDNS(w http.ResponseWriter, r *http.Request) {
	var req map[string][]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	b.mu.Lock()
	for z, rs := range req {
		if len(rs) == 0 {
			delete(b.splitDNS, z)
		} else {
			b.splitDNS[z] = slices.Clone(rs)
		}
	}
	out := maps.Clone(b.splitDNS)
	b.mu.Unlock()
	writeJSON(w, out)
}

func (b *ctlBridge) listDevices(w http.ResponseWriter, r *http.Request) {
	var out []tsclient.Device
	for _, n := range b.tn.control.AllNodes() {
		d := tsclient.Device{
			NodeID:   string(n.StableID),
			Hostname: n.Hostinfo.Hostname(),
			Name:     strings.TrimSuffix(n.Name, "."),
			Tags:     n.Tags,
		}
		if !strings.Contains(d.Name, ".") {
			d.Name = d.Hostname + "." + b.tn.domain
		}
		if b.isHidden(d.Hostname) {
			continue
		}
		for _, a := range n.Addresses {
			d.Addresses = append(d.Addresses, a.Addr().String())
		}
		out = append(out, d)
	}
	writeJSON(w, map[string]any{"devices": out})
}

func (b *ctlBridge) createKey(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"id": "k-e2e", "key": "tskey-auth-e2e", "expires": time.Now().Add(time.Hour)})
}

func (b *ctlBridge) syncLoop() {
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-t.C:
			b.sync()
		}
	}
}

// How long, and how often, to replay a route publish. A client that is
// still opening its map poll when the first wake is sent keeps the netmap
// from before the route existed.
const (
	routeWakeFor   = 3 * time.Second
	routeWakeEvery = 200 * time.Millisecond
)

// keepWaking replays the current service-host publish for d. Use it after a
// control change that is not itself a VIP publish, such as an app-cap grant.
// The replayed map is built from control's current state, so it includes
// that grant and any VIP route already stored.
func (b *ctlBridge) keepWaking(d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	until := time.Now().Add(d)
	for _, n := range b.tn.control.AllNodes() {
		if until.After(b.wakeUntil[n.Key]) {
			b.wakeUntil[n.Key] = until
		}
		b.wakeNext[n.Key] = time.Time{}
	}
}

// sync tags nodes and hands out service-host capabilities.
func (b *ctlBridge) sync() {
	b.mu.Lock()
	hostTags := maps.Clone(b.hostTags)
	svcs := slices.Collect(maps.Values(b.services))
	b.mu.Unlock()
	sort.Slice(svcs, func(i, j int) bool { return svcs[i].Name < svcs[j].Name })

	now := time.Now()
	for _, n := range b.tn.control.AllNodes() {
		var tags []string
		best := -1
		for p, ts := range hostTags {
			if strings.HasPrefix(n.Hostinfo.Hostname(), p) && len(p) > best {
				tags, best = ts, len(p)
			}
		}
		if tags == nil {
			continue
		}
		tagsChanged := !slices.Equal(n.Tags, tags)
		if tagsChanged {
			n.Tags = slices.Clone(tags)
		}
		caps := tailcfg.ServiceIPMappings{}
		var routes []netip.Prefix
		for _, s := range svcs {
			if !slices.ContainsFunc(s.Tags, func(t string) bool { return slices.Contains(tags, t) }) {
				continue
			}
			var ips []netip.Addr
			for _, a := range s.Addrs {
				if ip, err := netip.ParseAddr(a); err == nil {
					ips = append(ips, ip)
					routes = append(routes, netip.PrefixFrom(ip, ip.BitLen()))
				}
			}
			caps[tailcfg.ServiceName(s.Name)] = ips
		}
		j, _ := json.Marshal(caps)
		fp := string(j) + fmt.Sprint(routes)
		b.mu.Lock()
		same := b.applied[n.Key] == fp
		if !same {
			b.applied[n.Key] = fp
			b.wakeUntil[n.Key] = now.Add(routeWakeFor)
			b.wakeNext[n.Key] = now.Add(routeWakeEvery)
		}
		due := now.Before(b.wakeUntil[n.Key]) && !now.Before(b.wakeNext[n.Key])
		if due {
			b.wakeNext[n.Key] = now.Add(routeWakeEvery)
		}
		b.mu.Unlock()
		if same && !tagsChanged && !due {
			continue
		}
		cm := serviceHostCap(caps)
		if !same {
			// Store the VIP route before waking anyone. SetNodeCapMap and
			// UpdateNode wake every streaming client, and SetSubnetRoutes
			// wakes only this node. A wake that is sent first is often
			// dropped once the buffer holds it, and the client then dials
			// the VIP through the kernel until it times out.
			b.tn.control.SetSubnetRoutes(n.Key, routes)
			b.tn.control.SetNodeCapMap(n.Key, cm)
		} else if due {
			// The route is already stored. Wake again so a poll that
			// missed the first one builds a map that includes it.
			b.tn.control.SetNodeCapMap(n.Key, cm)
		}
		if tagsChanged {
			b.tn.control.UpdateNode(n)
		}
	}
}

func serviceHostCap(caps tailcfg.ServiceIPMappings) tailcfg.NodeCapMap {
	cm := tailcfg.NodeCapMap{}
	if len(caps) == 0 {
		return cm
	}
	vcaps := map[tailcfg.ServiceName]views.Slice[netip.Addr]{}
	for k, v := range caps {
		vcaps[k] = views.SliceOf(v)
	}
	vj, _ := json.Marshal(vcaps)
	cm[tailcfg.NodeAttrServiceHost] = []tailcfg.RawMessage{tailcfg.RawMessage(vj)}
	return cm
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": msg})
}
