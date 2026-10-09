package e2e

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	tsclient "tailscale.com/client/tailscale/v2"
	"tailscale.com/types/key"
)

// TestMeshUserJSON loads a mesh the way a user does: a JSON file with
// tailnets and bridges, including one bridge whose to list has two keys.
// Subtests then prove bytes on every bridge, a reverse broad selector, and
// a file edit that adds a fourth tailnet without restarting the others.
func TestMeshUserJSON(t *testing.T) {
	ctx := e2eSetup(t)
	g := newMeshRig(t)
	homeAPI, workAPI, partnerAPI := g.apis["home"], g.apis["work"], g.apis["partner"]

	unrelated := map[string]tsclient.VIPService{}
	for key, addr := range map[string]string{"home": "100.80.1.1", "work": "100.80.1.2", "partner": "100.80.1.4", "lab": "100.80.1.5"} {
		unrelated[key] = g.apis[key].PutService(foreignVIP("svc:unrelated", addr))
	}
	taken := workAPI.PutService(foreignVIP("svc:taken", "100.80.1.3"))
	real := workAPI.PutService(tsclient.VIPService{
		Name: "svc:real-loop", Addrs: []string{"100.90.0.8"}, Tags: []string{"tag:tailnetlink"}, Comment: "already there",
	})
	for _, api := range g.apis {
		api.SetSplitDNS("other.example.com", []string{"9.9.9.9"})
		api.ResetCalls()
	}
	colleague := map[string]nodeSnap{}
	for key, tn := range g.nets {
		n := tn.node(t, ctx, "colleague")
		colleague[key] = snapNode(tn, n.key)
	}

	echoBackend(t, ctx, g.nets["home"], "api", 8080)
	echoBackend(t, ctx, g.nets["work"], "build", 8022)
	echoBackend(t, ctx, g.nets["partner"], "billing", 8443)
	echoBackend(t, ctx, g.nets["lab"], "labbox", 9090)
	g.nets["home"].node(t, ctx, "other")
	homeClient := client(t, ctx, g.nets["home"], "home-client")
	workClient := client(t, ctx, g.nets["work"], "work-client")
	partnerClient := client(t, ctx, g.nets["partner"], "partner-client")

	path := filepath.Join(t.TempDir(), "tailnetlink.json")
	body := g.meshJSON([]string{"home", "work", "partner"}, g.coreBridges(false, false, true))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SharedNodes || len(cfg.Tailnets) != 3 {
		t.Fatalf("loaded mesh = shared %v tailnets %d", cfg.SharedNodes, len(cfg.Tailnets))
	}
	var fanOut bool
	for _, b := range cfg.Bridges {
		if b.Name == "api/api" && len(b.DestTailnets) == 2 {
			fanOut = true
		}
	}
	if !fanOut {
		t.Fatalf("loaded file has no fan-out bridge: %+v", cfg.Bridges)
	}

	r := startManager(t, cfg, "")
	g.watch(t, r, path)

	flow := func() {
		t.Helper()
		echoVia(t, ctx, workClient, netip.AddrPortFrom(waitVIP(t, workAPI, "svc:api"), 8080), "home to work")
		echoVia(t, ctx, partnerClient, netip.AddrPortFrom(waitVIP(t, partnerAPI, "svc:api"), 8080), "home to partner")
		echoVia(t, ctx, homeClient, netip.AddrPortFrom(waitVIP(t, homeAPI, "svc:builds"), 8022), "work to home")
		echoVia(t, ctx, workClient, netip.AddrPortFrom(waitVIP(t, workAPI, "svc:billing"), 8443), "partner to work")
	}

	t.Run("every bridge carries bytes", func(t *testing.T) {
		flow()
		for _, key := range []string{"home", "work", "partner"} {
			if n := hostnameCount(g.nets[key], "tailnetlink-"+key); n != 1 {
				t.Errorf("%s has %d tailnetlink nodes", key, n)
			}
			if got := r.m.NodeStarts(key); got != 1 {
				t.Errorf("%s node starts = %d, want 1", key, got)
			}
		}
		if r.m.NodeStarts("lab") != 0 {
			t.Errorf("lab started before it was in the file: %d", r.m.NodeStarts("lab"))
		}
		waitFor(t, 20*time.Second, "short_name conflict", func() bool {
			_, errText := r.bridgeStatus("taken/taken/work/other." + g.nets["home"].domain)
			return strings.Contains(errText, "conflict")
		})
		g.assertForeign(t, colleague, map[string][]tsclient.VIPService{
			"home": {unrelated["home"]}, "work": {unrelated["work"], taken, real},
			"partner": {unrelated["partner"]}, "lab": {unrelated["lab"]},
		})
	})

	t.Run("reverse broad selector", func(t *testing.T) {
		g.rewrite(t, path, g.meshJSON([]string{"home", "work", "partner"}, g.coreBridges(true, false, true)))
		waitFor(t, 20*time.Second, "unmanaged tagged service exported", func() bool {
			_, ok := homeAPI.Service("svc:loop-real-loop")
			return ok
		})
		if _, ok := homeAPI.Service("svc:loop-api"); ok {
			t.Fatal("managed VIP was published back into the tailnet it came from")
		}
		if _, ok := homeAPI.Service("svc:loop-unrelated"); ok {
			t.Fatal("foreign service was re-exported")
		}
		flow()
		for _, key := range []string{"home", "work", "partner"} {
			if got := r.m.NodeStarts(key); got != 1 {
				t.Errorf("reverse bridge restarted %s (%d starts)", key, got)
			}
		}
	})

	t.Run("fourth tailnet without node restart", func(t *testing.T) {
		g.rewrite(t, path, g.meshJSON([]string{"home", "work", "partner", "lab"}, g.coreBridges(true, true, true)))
		waitFor(t, 30*time.Second, "lab node started once", func() bool {
			return r.m.NodeStarts("lab") == 1 && hostnameCount(g.nets["lab"], "tailnetlink-lab") == 1
		})
		for _, key := range []string{"home", "work", "partner"} {
			if got := r.m.NodeStarts(key); got != 1 {
				t.Errorf("adding lab restarted %s (%d starts)", key, got)
			}
		}
		labVIP := waitVIP(t, homeAPI, "svc:box")
		echoVia(t, ctx, homeClient, netip.AddrPortFrom(labVIP, 9090), "lab to home")
		flow()

		// Drop the partner billing bridge. The partner node stays, and the
		// bridges that were not removed keep moving bytes.
		g.rewrite(t, path, g.meshJSON([]string{"home", "work", "partner", "lab"}, g.coreBridges(true, true, false)))
		waitFor(t, 20*time.Second, "billing bridge removed", func() bool {
			_, ok := workAPI.Service("svc:billing")
			return !ok
		})
		for _, key := range []string{"home", "work", "partner", "lab"} {
			if got := r.m.NodeStarts(key); got != 1 {
				t.Errorf("removing a bridge restarted %s (%d starts)", key, got)
			}
		}
		echoVia(t, ctx, workClient, netip.AddrPortFrom(waitVIP(t, workAPI, "svc:api"), 8080), "home to work after removal")
		echoVia(t, ctx, partnerClient, netip.AddrPortFrom(waitVIP(t, partnerAPI, "svc:api"), 8080), "home to partner after removal")
		echoVia(t, ctx, homeClient, netip.AddrPortFrom(waitVIP(t, homeAPI, "svc:builds"), 8022), "work to home after removal")
		echoVia(t, ctx, homeClient, netip.AddrPortFrom(labVIP, 9090), "lab to home after removal")
		g.assertForeign(t, colleague, map[string][]tsclient.VIPService{
			"home": {unrelated["home"]}, "work": {unrelated["work"], taken, real},
			"partner": {unrelated["partner"]}, "lab": {unrelated["lab"]},
		})
	})
}

type meshRig struct {
	stateDir string
	nets     map[string]*tailnet
	apis     map[string]*ctlBridge
	secrets  map[string]string
}

func newMeshRig(t *testing.T) *meshRig {
	t.Helper()
	g := &meshRig{
		stateDir: t.TempDir(),
		nets:     map[string]*tailnet{},
		apis:     map[string]*ctlBridge{},
		secrets:  map[string]string{},
	}
	domains := map[string]string{
		"home":    "keiretsu.ts.net",
		"work":    "example.ts.net",
		"partner": "partner.example.com",
		"lab":     "lab.example.com",
	}
	dir := t.TempDir()
	for key, domain := range domains {
		tn := newTailnet(t, domain)
		api := newCtlBridge(t, tn)
		sec := key + "-secret"
		path := dir + "/" + key
		if err := writeSecret(path, sec); err != nil {
			t.Fatal(err)
		}
		api.secret = sec
		g.nets[key] = tn
		g.apis[key] = api
		g.secrets[key] = path
	}
	return g
}

func writeSecret(path, sec string) error {
	return os.WriteFile(path, []byte(sec+"\n"), 0o600)
}

// meshJSON is the file a user would write. keys are the tailnets in the
// file. bridges is the raw JSON array body.
func (g *meshRig) meshJSON(keys []string, body string) string {
	var tails []string
	for _, key := range keys {
		tn, api := g.nets[key], g.apis[key]
		tails = append(tails, fmt.Sprintf(`%q: {
			"tailnet": %q,
			"auth": {"client_id": "mesh", "client_secret_file": %q},
			"tags": ["tag:tailnetlink"],
			"control_url": %q,
			"api_base_url": %q
		}`, key, tn.domain, g.secrets[key], tn.url, api.URL()))
	}
	return fmt.Sprintf(`{
		"name": "mesh",
		"dns": false,
		"poll_interval": "200ms",
		"dial_timeout": "5s",
		"state_dir": %q,
		"tailnets": {%s},
		%s
	}`, g.stateDir, strings.Join(tails, ",\n"), body)
}

// coreBridges is the directional set. withLoop adds the broad return tag.
// withBilling keeps partner to work. withLab adds lab to home.
func (g *meshRig) coreBridges(withLoop, withLab, withBilling bool) string {
	home, work, partner := g.nets["home"].domain, g.nets["work"].domain, g.nets["partner"].domain
	targets := []string{
		fmt.Sprintf(`"api": {"in": "home", "device": "api.%s", "ports": [8080]}`, home),
		fmt.Sprintf(`"builds": {"in": "work", "device": "build.%s", "ports": [8022]}`, work),
		fmt.Sprintf(`"taken": {"in": "home", "device": "other.%s", "ports": [9]}`, home),
	}
	exports := []string{
		`{"target": "api", "to": ["work", "partner"]}`,
		`{"target": "builds", "to": ["home"]}`,
		`{"target": "taken", "to": ["work"], "name": "taken"}`,
	}
	if withBilling {
		targets = append(targets, fmt.Sprintf(`"billing": {"in": "partner", "device": "billing.%s", "ports": [8443]}`, partner))
		exports = append(exports, `{"target": "billing", "to": ["work"]}`)
	}
	if withLoop {
		targets = append(targets, `"loop": {"in": "work", "tag": "tag:tailnetlink", "ports": [443]}`)
		exports = append(exports, `{"target": "loop", "to": ["home"]}`)
	}
	if withLab {
		targets = append(targets, fmt.Sprintf(`"box": {"in": "lab", "device": "labbox.%s", "ports": [9090]}`, g.nets["lab"].domain))
		exports = append(exports, `{"target": "box", "to": ["home"]}`)
	}
	return `"targets": {` + strings.Join(targets, ",\n") + `}, "exports": [` + strings.Join(exports, ",\n") + `]`
}

// watch reloads the file the way the process does: a mtime change is parsed
// and reconciled. The interval is short so the test does not wait out the
// production default.
func (g *meshRig) watch(t *testing.T, r *running, path string) {
	t.Helper()
	st, err := config.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	st.SetWatchInterval(30 * time.Millisecond)
	st.OnChange(func(cfg *config.Config) { r.reconcile(cfg) })
	go st.Watch(r.ctx, r.logger)
}

func (g *meshRig) rewrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// Force the mtime forward. A same-second rewrite can look unchanged.
	stamp := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
}

func foreignVIP(name, addr string) tsclient.VIPService {
	return tsclient.VIPService{
		Name: name, Addrs: []string{addr}, Comment: "someone else",
		Ports: []string{"tcp:9"}, Tags: []string{"tag:user"},
	}
}

type nodeSnap struct {
	key        key.NodePublic
	name, host string
	tags       []string
	addrs      []string
	caps       string
}

func snapNode(tn *tailnet, k key.NodePublic) nodeSnap {
	n := tn.control.Node(k)
	var addrs []string
	for _, a := range n.Addresses {
		addrs = append(addrs, a.String())
	}
	caps, _ := json.Marshal(n.CapMap)
	host := ""
	if n.Hostinfo.Valid() {
		host = n.Hostinfo.Hostname()
	}
	return nodeSnap{key: k, name: n.Name, host: host, tags: append([]string(nil), n.Tags...), addrs: addrs, caps: string(caps)}
}

func (s nodeSnap) same(o nodeSnap) bool {
	return s.name == o.name && s.host == o.host && s.caps == o.caps &&
		reflect.DeepEqual(s.tags, o.tags) && reflect.DeepEqual(s.addrs, o.addrs)
}

func hostnameCount(tn *tailnet, host string) int {
	n := 0
	for _, node := range tn.control.AllNodes() {
		if node.Hostinfo.Valid() && node.Hostinfo.Hostname() == host {
			n++
		}
	}
	return n
}

func (g *meshRig) assertForeign(t *testing.T, colleagues map[string]nodeSnap, svcs map[string][]tsclient.VIPService) {
	t.Helper()
	for key, want := range colleagues {
		got := snapNode(g.nets[key], want.key)
		if !want.same(got) {
			t.Errorf("%s device changed\n got %+v\nwant %+v", key, got, want)
		}
		api := g.apis[key]
		for _, svc := range svcs[key] {
			gotSvc, ok := api.Service(svc.Name)
			if !ok || !reflect.DeepEqual(gotSvc, svc) {
				t.Errorf("%s service %s = %+v, want %+v", key, svc.Name, gotSvc, svc)
			}
		}
		if gotDNS := api.SplitDNS("other.example.com"); !reflect.DeepEqual(gotDNS, []string{"9.9.9.9"}) {
			t.Errorf("%s split-DNS = %v", key, gotDNS)
		}
		for _, c := range api.Writes() {
			if strings.Contains(c, "/vip-services/svc:unrelated") || strings.Contains(c, "/vip-services/svc:taken") || strings.Contains(c, "/vip-services/svc:real-loop") ||
				strings.Contains(c, "split-dns") || strings.Contains(c, "/acl") || strings.Contains(c, "/policy") || strings.Contains(c, "/routes") || strings.Contains(c, "/devices") {
				t.Errorf("%s write touched a resource this process does not own: %s", key, c)
			}
		}
	}
}
