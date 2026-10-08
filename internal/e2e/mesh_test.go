package e2e

import (
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	tsclient "tailscale.com/client/tailscale/v2"
	"tailscale.com/types/key"
)

// TestMeshSharesNodes runs one process across three tailnets. Each tailnet
// gets one node, which dials for bridges that leave and hosts VIP services
// for bridges that arrive. Services, devices and split-DNS that this
// process did not create stay as they were, including a service whose name
// is the one a link would have published.
func TestMeshSharesNodes(t *testing.T) {
	ctx := e2eSetup(t)
	g := newMeshRig(t)

	homeAPI, workAPI, partnerAPI := g.apis["home"], g.apis["work"], g.apis["partner"]
	unrelatedHome := homeAPI.PutService(foreignVIP("svc:unrelated", "100.80.1.1"))
	unrelatedWork := workAPI.PutService(foreignVIP("svc:unrelated", "100.80.1.2"))
	taken := workAPI.PutService(foreignVIP("svc:taken", "100.80.1.3"))
	real := workAPI.PutService(tsclient.VIPService{
		Name: "svc:real-loop", Addrs: []string{"100.90.0.8"}, Tags: []string{"tag:tailnetlink"}, Comment: "already there",
	})
	unrelatedPartner := partnerAPI.PutService(foreignVIP("svc:unrelated", "100.80.1.4"))
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
	g.nets["home"].node(t, ctx, "other")
	homeClient := client(t, ctx, g.nets["home"], "home-client")
	workClient := client(t, ctx, g.nets["work"], "work-client")
	partnerClient := client(t, ctx, g.nets["partner"], "partner-client")

	r := startManager(t, g.mustParse(t, g.bridges(true, true, false)), "")
	if !r.config().SharedNodes {
		t.Fatal("mesh did not compile to one node per tailnet")
	}

	apiOnWork := waitVIP(t, workAPI, "svc:tnl-home-api")
	apiOnPartner := waitVIP(t, partnerAPI, "svc:tnl-home-api")
	buildOnHome := waitVIP(t, homeAPI, "svc:tnl-work-build")
	billOnWork := waitVIP(t, workAPI, "svc:tnl-partner-billing")
	echoVia(t, ctx, workClient, netip.AddrPortFrom(apiOnWork, 8080), "home to work")
	echoVia(t, ctx, partnerClient, netip.AddrPortFrom(apiOnPartner, 8080), "home to partner")
	echoVia(t, ctx, homeClient, netip.AddrPortFrom(buildOnHome, 8022), "work to home")
	echoVia(t, ctx, workClient, netip.AddrPortFrom(billOnWork, 8443), "partner to work")

	for key, host := range map[string]string{"home": "tailnetlink-home", "work": "tailnetlink-work", "partner": "tailnetlink-partner"} {
		if n := hostnameCount(g.nets[key], host); n != 1 {
			t.Errorf("%s nodes named %s = %d, want 1", key, host, n)
		}
	}
	waitFor(t, 20*time.Second, "short_name conflict", func() bool {
		_, errText := r.bridgeStatus("home/taken/work/other." + g.nets["home"].domain)
		return strings.Contains(errText, "conflict")
	})
	assertMeshForeign(t, g, colleague, map[*ctlBridge][]tsclient.VIPService{
		homeAPI:    {unrelatedHome},
		workAPI:    {unrelatedWork, taken, real},
		partnerAPI: {unrelatedPartner},
	})

	// A return selector that matches the VIP just published must not mirror it.
	r.reconcile(g.mustParse(t, g.bridges(true, true, true)))
	waitFor(t, 20*time.Second, "unmanaged tagged service exported", func() bool {
		_, ok := homeAPI.Service("svc:tnl-work-real-loop")
		return ok
	})
	if _, ok := homeAPI.Service("svc:tnl-work-tnl-home-api"); ok {
		t.Fatal("managed VIP was published back into the tailnet it came from")
	}
	if logCount(r, `disconnected from tailnet "home"`) != 0 || logCount(r, `disconnected from tailnet "work"`) != 0 || logCount(r, `disconnected from tailnet "partner"`) != 0 {
		t.Fatal("adding a bridge disconnected a node")
	}
	assertMeshForeign(t, g, colleague, map[*ctlBridge][]tsclient.VIPService{
		homeAPI:    {unrelatedHome},
		workAPI:    {unrelatedWork, taken, real},
		partnerAPI: {unrelatedPartner},
	})

	// Removing partner drops its node and the services this process published
	// there. The other nodes stay up.
	r.reconcile(g.mustParse(t, g.bridges(false, false, false)))
	waitFor(t, 20*time.Second, "partner node removed", func() bool {
		return logCount(r, `disconnected from tailnet "partner"`) >= 1
	})
	if logCount(r, `disconnected from tailnet "home"`) != 0 || logCount(r, `disconnected from tailnet "work"`) != 0 {
		t.Fatal("removing partner disconnected another node")
	}
	if _, ok := partnerAPI.Service("svc:tnl-home-api"); ok {
		t.Fatal("partner still has a VIP this process published")
	}
	if _, ok := workAPI.Service("svc:tnl-partner-billing"); ok {
		t.Fatal("work still has the removed partner bridge")
	}
	if _, ok := workAPI.Service("svc:tnl-home-api"); !ok {
		t.Fatal("removing partner deleted the VIP on work")
	}
	assertMeshForeign(t, g, colleague, map[*ctlBridge][]tsclient.VIPService{
		homeAPI:    {unrelatedHome},
		workAPI:    {unrelatedWork, taken, real},
		partnerAPI: {unrelatedPartner},
	})

	r.stop(t)
	if _, ok := workAPI.Service("svc:tnl-home-api"); !ok {
		t.Fatal("shutdown deleted an owned VIP")
	}
	assertMeshForeign(t, g, colleague, map[*ctlBridge][]tsclient.VIPService{
		homeAPI:    {unrelatedHome},
		workAPI:    {unrelatedWork, taken, real},
		partnerAPI: {unrelatedPartner},
	})
	for _, api := range g.apis {
		for _, c := range api.Writes() {
			if strings.Contains(c, "svc:unrelated") || strings.Contains(c, "svc:taken") || strings.Contains(c, "svc:real-loop") ||
				strings.Contains(c, "split-dns") || strings.Contains(c, "/acl") || strings.Contains(c, "/policy") || strings.Contains(c, "/routes") || strings.Contains(c, "/devices") {
				t.Errorf("%s write touched a resource this process does not own: %s", api.tn.domain, c)
			}
		}
	}
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

func (g *meshRig) side(key string) config.MeshTailnet {
	tn, api := g.nets[key], g.apis[key]
	return config.MeshTailnet{Side: config.Side{
		Tailnet:    tn.domain,
		OAuth:      config.OAuthCreds{ClientID: "mesh", ClientSecretFile: g.secrets[key]},
		Tags:       []string{"tag:tailnetlink"},
		ControlURL: tn.url,
		APIBaseURL: api.URL(),
	}}
}

// bridges builds the mesh links. withPartner keeps the partner tailnet.
// withLoop adds the return tag selector used to check that managed VIPs
// are not exported again.
func (g *meshRig) bridges(withPartner, withTaken, withLoop bool) *config.Mesh {
	off := false
	poll := config.Duration{Duration: 200 * time.Millisecond}
	dial := config.Duration{Duration: 5 * time.Second}
	homeTo := []string{"work"}
	if withPartner {
		homeTo = []string{"work", "partner"}
	}
	tailnets := map[string]config.MeshTailnet{
		"home": g.side("home"),
		"work": g.side("work"),
	}
	links := []config.MeshBridge{
		{From: "home", To: homeTo, Links: []config.Link{{
			Name: "api", Devices: []config.DeviceSpec{{FQDN: "api." + g.nets["home"].domain}}, Ports: []int{8080},
		}}},
		{From: "work", To: []string{"home"}, Links: []config.Link{{
			Name: "builds", Devices: []config.DeviceSpec{{FQDN: "build." + g.nets["work"].domain}}, Ports: []int{8022},
		}}},
	}
	if withTaken {
		links = append(links, config.MeshBridge{From: "home", To: []string{"work"}, Links: []config.Link{{
			Name: "taken", Devices: []config.DeviceSpec{{FQDN: "other." + g.nets["home"].domain, ShortName: "taken"}}, Ports: []int{9},
		}}})
	}
	if withLoop {
		links = append(links, config.MeshBridge{From: "work", To: []string{"home"}, Links: []config.Link{{
			Name: "loop", Tag: "tag:tailnetlink", Ports: []int{443},
		}}})
	}
	if withPartner {
		tailnets["partner"] = g.side("partner")
		links = append(links, config.MeshBridge{From: "partner", To: []string{"work"}, Links: []config.Link{{
			Name: "billing", Devices: []config.DeviceSpec{{FQDN: "billing." + g.nets["partner"].domain}}, Ports: []int{8443},
		}}})
	}
	return &config.Mesh{
		Name: "mesh", Node: config.NodeConfig{StateDir: g.stateDir},
		DNS:          config.DNSConfig{Enabled: &off},
		PollInterval: &poll, DialTimeout: &dial,
		Tailnets: tailnets, Bridges: links,
	}
}

func (g *meshRig) mustParse(t *testing.T, m *config.Mesh) *config.Config {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatalf("parse mesh: %v\n%s", err, data)
	}
	return cfg
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

func logCount(r *running, sub string) int {
	n := 0
	for _, l := range r.store.GetLogs(1000) {
		if strings.Contains(l.Message, sub) {
			n++
		}
	}
	return n
}

func assertMeshForeign(t *testing.T, g *meshRig, colleagues map[string]nodeSnap, svcs map[*ctlBridge][]tsclient.VIPService) {
	t.Helper()
	for key, want := range colleagues {
		got := snapNode(g.nets[key], want.key)
		if !want.same(got) {
			t.Errorf("%s device changed\n got %+v\nwant %+v", key, got, want)
		}
	}
	for api, list := range svcs {
		for _, want := range list {
			got, ok := api.Service(want.Name)
			if !ok || !reflect.DeepEqual(got, want) {
				t.Errorf("%s service %s = %+v, want %+v", api.tn.domain, want.Name, got, want)
			}
		}
		if got := api.SplitDNS("other.example.com"); !reflect.DeepEqual(got, []string{"9.9.9.9"}) {
			t.Errorf("%s split-DNS = %v", api.tn.domain, got)
		}
	}
}
