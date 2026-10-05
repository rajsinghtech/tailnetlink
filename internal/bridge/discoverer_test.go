package bridge

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/testutil/fakeapi"
	tsclient "tailscale.com/client/tailscale/v2"
)

func dev(host string, tags []string, addrs ...string) tsclient.Device {
	return tsclient.Device{
		NodeID:    "n-" + host,
		Name:      host + ".src.example",
		Hostname:  host,
		Tags:      tags,
		Addresses: addrs,
	}
}

func drain(ch <-chan Device) []Device {
	var out []Device
	for {
		select {
		case d := <-ch:
			out = append(out, d)
		default:
			return out
		}
	}
}

func names(ds []Device) map[string]bool {
	out := map[string]bool{}
	for _, d := range ds {
		out[d.FQDN] = true
	}
	return out
}

func TestDiscovererTagMode(t *testing.T) {
	api := fakeapi.New(t)
	api.SetDevices([]tsclient.Device{
		dev("web-1", []string{"tag:web"}, "100.64.0.1", "fd7a::1"),
		dev("db-1", []string{"tag:db"}, "100.64.0.2"),
	})
	d := NewDiscoverer(api.Client(), "tag:web", nil, nil, 0, discardLogger())
	d.poll1(context.Background())

	added := drain(d.Added())
	if len(added) != 1 {
		t.Fatalf("added = %+v", added)
	}
	got := added[0]
	if got.FQDN != "web-1.src.example" || got.Name != "web-1" || got.IP.String() != "100.64.0.1" {
		t.Errorf("device = %+v", got)
	}
}

func TestDiscovererTagModeIncludesTaggedServices(t *testing.T) {
	api := fakeapi.New(t)
	api.PutService(tsclient.VIPService{Name: "svc:ai", Addrs: []string{"100.100.1.1"}, Tags: []string{"tag:web"}})
	api.PutService(tsclient.VIPService{Name: "svc:other", Addrs: []string{"100.100.1.2"}, Tags: []string{"tag:db"}})
	d := NewDiscoverer(api.Client(), "tag:web", nil, nil, 0, discardLogger())
	d.poll1(context.Background())

	added := names(drain(d.Added()))
	if !added["svc:ai"] || added["svc:other"] || len(added) != 1 {
		t.Errorf("added = %v", added)
	}
}

// Tag mode skips VIP services tailnetlink created (tailnetlink/managed
// annotation) and tailnetlink's own nodes, so its output is never bridged
// again. Flipped from TestKnownBad_TagModeDiscoversOwnServices.
func TestTagModeSkipsOwnOutput(t *testing.T) {
	api := fakeapi.New(t)
	api.PutService(tsclient.VIPService{
		Name:        "svc:tnl-other-web-1",
		Addrs:       []string{"100.100.1.1"},
		Tags:        []string{"tag:web"},
		Annotations: map[string]string{"tailnetlink/managed": "true"},
	})
	api.PutService(tsclient.VIPService{Name: "svc:real", Addrs: []string{"100.100.1.2"}, Tags: []string{"tag:web"}})
	api.SetDevices([]tsclient.Device{
		dev("tailnetlink-dst", []string{"tag:web"}, "100.64.0.9"),
		dev("web-1", []string{"tag:web"}, "100.64.0.1"),
	})
	d := NewDiscoverer(api.Client(), "tag:web", nil, nil, 0, discardLogger())
	d.poll1(context.Background())

	added := names(drain(d.Added()))
	if len(added) != 2 || !added["svc:real"] || !added["web-1.src.example"] {
		t.Errorf("added = %v, want only svc:real and web-1", added)
	}
}

func TestDiscovererRemoval(t *testing.T) {
	api := fakeapi.New(t)
	api.SetDevices([]tsclient.Device{dev("web-1", []string{"tag:web"}, "100.64.0.1")})
	d := NewDiscoverer(api.Client(), "tag:web", nil, nil, 0, discardLogger())
	d.poll1(context.Background())
	drain(d.Added())

	api.SetDevices(nil)
	d.poll1(context.Background())
	removed := drain(d.Removed())
	if len(removed) != 1 || removed[0].FQDN != "web-1.src.example" {
		t.Errorf("removed = %+v", removed)
	}
	if again := drain(d.Added()); len(again) != 0 {
		t.Errorf("unexpected adds: %+v", again)
	}
}

func TestDiscovererSkipsDevicesWithoutIPAndWarns(t *testing.T) {
	api := fakeapi.New(t)
	api.SetDevices([]tsclient.Device{dev("web-1", []string{"tag:web"})})
	d := NewDiscoverer(api.Client(), "tag:web", nil, nil, 0, discardLogger())
	var warns []string
	d.OnWarn(func(s string) { warns = append(warns, s) })
	d.poll1(context.Background())

	if added := drain(d.Added()); len(added) != 0 {
		t.Errorf("added = %+v", added)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "no routable IP") {
		t.Errorf("warns = %v", warns)
	}
}

func TestDiscovererWarnsWithAvailableTags(t *testing.T) {
	api := fakeapi.New(t)
	api.SetDevices([]tsclient.Device{dev("db-1", []string{"tag:db"}, "100.64.0.2")})
	d := NewDiscoverer(api.Client(), "tag:web", nil, nil, 0, discardLogger())
	var warns []string
	d.OnWarn(func(s string) { warns = append(warns, s) })
	d.poll1(context.Background())

	if len(warns) != 1 || !strings.Contains(warns[0], "tag:db") {
		t.Errorf("warns = %v", warns)
	}
}

func TestDiscovererDeviceModeIsCaseInsensitive(t *testing.T) {
	api := fakeapi.New(t)
	api.SetDevices([]tsclient.Device{
		dev("web-1", nil, "100.64.0.1"),
		dev("web-2", nil, "100.64.0.2"),
	})
	d := NewDiscoverer(api.Client(), "", []string{"WEB-1.src.example"}, nil, 0, discardLogger())
	d.poll1(context.Background())

	added := names(drain(d.Added()))
	if !added["web-1.src.example"] || len(added) != 1 {
		t.Errorf("added = %v", added)
	}
}

func TestDiscovererServiceMode(t *testing.T) {
	api := fakeapi.New(t)
	api.PutService(tsclient.VIPService{Name: "svc:ai", Addrs: []string{"100.100.1.1"}})
	api.PutService(tsclient.VIPService{Name: "svc:noaddr"})
	api.PutService(tsclient.VIPService{Name: "svc:unlisted", Addrs: []string{"100.100.1.3"}})
	api.SetDevices([]tsclient.Device{dev("web-1", nil, "100.64.0.1")})
	d := NewDiscoverer(api.Client(), "", []string{"web-1.src.example"}, []string{"svc:ai", "svc:noaddr"}, 0, discardLogger())
	d.poll1(context.Background())

	// Services take priority over devices when no tag is set, and services
	// without an address are skipped.
	added := names(drain(d.Added()))
	if !added["svc:ai"] || len(added) != 1 {
		t.Errorf("added = %v", added)
	}
}

func TestDiscovererTagOverridesExplicitLists(t *testing.T) {
	api := fakeapi.New(t)
	api.SetDevices([]tsclient.Device{
		dev("web-1", []string{"tag:web"}, "100.64.0.1"),
		dev("db-1", nil, "100.64.0.2"),
	})
	d := NewDiscoverer(api.Client(), "tag:web", []string{"db-1.src.example"}, nil, 0, discardLogger())
	d.poll1(context.Background())

	added := names(drain(d.Added()))
	if !added["web-1.src.example"] || added["db-1.src.example"] {
		t.Errorf("added = %v", added)
	}
}

func TestDiscovererAPIErrorKeepsState(t *testing.T) {
	api := fakeapi.New(t)
	api.SetDevices([]tsclient.Device{dev("web-1", []string{"tag:web"}, "100.64.0.1")})
	d := NewDiscoverer(api.Client(), "tag:web", nil, nil, 0, discardLogger())
	d.poll1(context.Background())
	drain(d.Added())

	d.client.Tailnet = "wrong.example"
	d.poll1(context.Background())
	if r := drain(d.Removed()); len(r) != 0 {
		t.Errorf("API error caused removals: %+v", r)
	}
}

// Every change is announced even when there are more than the channels
// hold: 50 devices in one poll are all added, and all removed later.
// Flipped from TestKnownBad_DiscovererDropsEventsOverBuffer.
func TestDiscovererAnnouncesEveryDevice(t *testing.T) {
	api := fakeapi.New(t)
	var ds []tsclient.Device
	for i := range 50 {
		ds = append(ds, dev(fmt.Sprintf("web-%02d", i), []string{"tag:web"}, fmt.Sprintf("100.64.0.%d", i+1)))
	}
	api.SetDevices(ds)
	d := NewDiscoverer(api.Client(), "tag:web", nil, nil, 0, discardLogger())

	collect := func(ch <-chan Device, poll func()) map[string]bool {
		got := make(chan map[string]bool)
		go func() {
			seen := map[string]bool{}
			for len(seen) < 50 {
				select {
				case dv := <-ch:
					seen[dv.FQDN] = true
				case <-time.After(5 * time.Second):
					got <- seen
					return
				}
			}
			got <- seen
		}()
		poll()
		return <-got
	}
	ctx := context.Background()
	if added := collect(d.Added(), func() { d.poll1(ctx) }); len(added) != 50 {
		t.Fatalf("added %d devices, want 50", len(added))
	}
	d.poll1(ctx)
	if again := drain(d.Added()); len(again) != 0 {
		t.Errorf("second poll re-announced %d devices", len(again))
	}
	api.SetDevices(nil)
	if removed := collect(d.Removed(), func() { d.poll1(ctx) }); len(removed) != 50 {
		t.Fatalf("removed %d devices, want 50", len(removed))
	}
}

// When the rule stops while events are pending, the poll gives up instead
// of blocking, and whatever wasn't announced is announced on a later poll.
func TestDiscovererCancelledPollRetriesLater(t *testing.T) {
	api := fakeapi.New(t)
	var ds []tsclient.Device
	for i := range 20 {
		ds = append(ds, dev(fmt.Sprintf("web-%02d", i), []string{"tag:web"}, fmt.Sprintf("100.64.0.%d", i+1)))
	}
	api.SetDevices(ds)
	d := NewDiscoverer(api.Client(), "tag:web", nil, nil, 0, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		d.poll1(ctx) // fills the 16-slot channel, then blocks
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("poll did not return after cancel")
	}
	first := drain(d.Added())
	if len(first) != 16 {
		t.Fatalf("first poll announced %d, want 16", len(first))
	}
	d.poll1(context.Background())
	second := drain(d.Added())
	if len(first)+len(second) != 20 {
		t.Errorf("announced %d + %d devices, want 20 in total", len(first), len(second))
	}
	for _, dv := range second {
		if names(first)[dv.FQDN] {
			t.Errorf("%s announced twice", dv.FQDN)
		}
	}
}
