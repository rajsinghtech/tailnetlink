package bridge

import (
	"context"
	"fmt"
	"strings"
	"testing"

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

// KNOWN-BAD: tag mode also picks up VIP services that tailnetlink created
// itself, so a setup where the source tag matches the tag on bridged
// services (or two instances pointed at each other) re-bridges its own
// output. Flip in roadmap PR 10: skip services carrying the
// tailnetlink/managed annotation.
func TestKnownBad_TagModeDiscoversOwnServices(t *testing.T) {
	api := fakeapi.New(t)
	api.PutService(tsclient.VIPService{
		Name:        "svc:tnl-other-web-1",
		Addrs:       []string{"100.100.1.1"},
		Tags:        []string{"tag:web"},
		Annotations: map[string]string{"tailnetlink/managed": "true"},
	})
	d := NewDiscoverer(api.Client(), "tag:web", nil, nil, 0, discardLogger())
	d.poll1(context.Background())

	if added := names(drain(d.Added())); !added["svc:tnl-other-web-1"] {
		t.Errorf("expected own service to be discovered today, added = %v", added)
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

// KNOWN-BAD: the added channel holds 16 events and extra events are dropped,
// but the discoverer still records the device as seen, so a dropped device is
// never announced again. Flip in roadmap PR 10.
func TestKnownBad_DiscovererDropsEventsOverBuffer(t *testing.T) {
	api := fakeapi.New(t)
	var ds []tsclient.Device
	for i := range 20 {
		ds = append(ds, dev(fmt.Sprintf("web-%02d", i), []string{"tag:web"}, fmt.Sprintf("100.64.0.%d", i+1)))
	}
	api.SetDevices(ds)
	d := NewDiscoverer(api.Client(), "tag:web", nil, nil, 0, discardLogger())

	d.poll1(context.Background())
	first := drain(d.Added())
	d.poll1(context.Background())
	second := drain(d.Added())

	if len(first) != 16 {
		t.Errorf("first poll announced %d devices, expected 16 today", len(first))
	}
	if len(second) != 0 {
		t.Errorf("second poll announced %d devices, expected the dropped ones to stay lost today", len(second))
	}
}
