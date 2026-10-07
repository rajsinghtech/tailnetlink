package e2e

import (
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/metrics"
	tsclient "tailscale.com/client/tailscale/v2"
)

// A border with no links still logs both nodes in and is ready. It creates
// no VIP services and leaves a service it does not own alone. Adding a link
// in the config file is picked up like any other edit.
func TestManagerEmptyLinksThenHotReload(t *testing.T) {
	ctx := e2eSetup(t)
	b := newBorder(t)
	echoBackend(t, ctx, b.src, "backend", 8080)
	cl := client(t, ctx, b.dst, "client")

	foreignName := "svc:other-" + b.sfx
	foreign := b.dstAPI.PutService(tsclient.VIPService{
		Name: foreignName, Comment: "not ours", Ports: []string{"tcp:9"}, Tags: []string{"tag:other"},
	})
	b.srcAPI.ResetCalls()
	b.dstAPI.ResetCalls()

	path := filepath.Join(t.TempDir(), "tailnetlink.json")
	empty := b.border()
	empty.Links = []config.Link{}
	writeBorder(t, path, empty)
	cs, err := config.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(cs.Get().Bridges); n != 0 {
		t.Fatalf("compiled bridges = %d, want 0", n)
	}

	r := startManager(t, cs.Get(), "")
	cs.OnChange(r.reconcile)
	go cs.Watch(r.ctx, r.logger)
	srv := httptest.NewServer(metrics.Handler(r.metrics, r.m.Ready))
	t.Cleanup(srv.Close)

	waitFor(t, 60*time.Second, "/readyz 200 with no links", func() bool {
		c, _ := getStatus(t, srv.URL+"/readyz")
		return c == 200
	})
	connected := 0
	for _, tn := range r.store.GetStatus().Tailnets {
		if tn.Connected {
			connected++
		}
	}
	if connected != 2 {
		t.Fatalf("connected tailnets = %d, want 2", connected)
	}
	if !r.logged(`connected to tailnet "`+b.srcName) || !r.logged(`connected to tailnet "`+b.dstName) {
		t.Fatalf("logs:\n%s", r.logs.String())
	}
	if got := vipWrites(b.srcAPI); len(got) != 0 {
		t.Errorf("source VIP writes with no links: %v", got)
	}
	if got := vipWrites(b.dstAPI); len(got) != 0 {
		t.Errorf("dest VIP writes with no links: %v", got)
	}
	if names := b.dstAPI.ServiceNames(); len(names) != 1 || names[0] != foreignName {
		t.Errorf("dest services = %v, want only %s", names, foreignName)
	}
	if got, ok := b.dstAPI.Service(foreignName); !ok || !reflect.DeepEqual(got, foreign) {
		t.Errorf("foreign service changed while idle: %+v", got)
	}

	writeBorder(t, path, b.border(b.deviceLink("web", "backend", "be-"+b.sfx, 8080)))
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	svc := b.serviceName("backend", "be-"+b.sfx)
	vip := waitVIP(t, b.dstAPI, svc)
	echoVia(t, ctx, cl, netip.AddrPortFrom(vip, 8080), "after adding a link")
	if got, ok := b.dstAPI.Service(foreignName); !ok || !reflect.DeepEqual(got, foreign) {
		t.Errorf("foreign service changed after the link was added: %+v", got)
	}
	for _, w := range b.dstAPI.Writes() {
		if strings.Contains(w, "/"+foreignName) {
			t.Errorf("write to a service this border does not own: %s", w)
		}
	}
}

func vipWrites(api *ctlBridge) []string {
	var out []string
	for _, w := range api.Writes() {
		if strings.Contains(w, "/vip-services") || strings.Contains(w, "/services/") {
			out = append(out, w)
		}
	}
	return out
}
