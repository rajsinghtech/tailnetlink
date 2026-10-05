package bridge

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/rajsinghtech/tailnetlink/internal/testutil/fakeapi"
	tsclient "tailscale.com/client/tailscale/v2"
)

func testDevice() Device {
	return Device{Name: "web-1", FQDN: "web-1.src.example", IP: netip.MustParseAddr("100.64.0.1")}
}

func TestReconcilerEnsureCreatesService(t *testing.T) {
	api := fakeapi.New(t)
	r := NewReconciler(api.Client(), []int{80, 443}, []string{"tag:bridge"}, discardLogger())

	vip, err := r.Ensure(context.Background(), "src", testDevice(), "")
	if err != nil {
		t.Fatal(err)
	}
	if vip.ServiceName != "svc:tnl-src-web-1" {
		t.Errorf("service name = %q", vip.ServiceName)
	}
	if vip.VIP.String() != "100.100.0.1" {
		t.Errorf("vip = %v, want the address the API assigned", vip.VIP)
	}

	svc, ok := api.Service("svc:tnl-src-web-1")
	if !ok {
		t.Fatal("service not created")
	}
	if !slices.Equal(svc.Ports, []string{"tcp:80", "tcp:443"}) {
		t.Errorf("ports = %v", svc.Ports)
	}
	if !slices.Equal(svc.Tags, []string{"tag:bridge"}) {
		t.Errorf("tags = %v", svc.Tags)
	}
	if svc.Annotations["tailnetlink/managed"] != "true" || svc.Annotations["tailnetlink/source"] != "src" {
		t.Errorf("annotations = %v", svc.Annotations)
	}
}

func TestReconcilerEnsureIsCached(t *testing.T) {
	api := fakeapi.New(t)
	r := NewReconciler(api.Client(), []int{80}, nil, discardLogger())
	if _, err := r.Ensure(context.Background(), "src", testDevice(), ""); err != nil {
		t.Fatal(err)
	}
	api.ResetCalls()
	if _, err := r.Ensure(context.Background(), "src", testDevice(), ""); err != nil {
		t.Fatal(err)
	}
	if calls := api.Calls(); len(calls) != 0 {
		t.Errorf("second Ensure hit the API: %v", callStrings(calls))
	}
}

func TestReconcilerEnsureKeepsExistingAddrs(t *testing.T) {
	api := fakeapi.New(t)
	api.PutService(tsclient.VIPService{
		Name:        "svc:tnl-src-web-1",
		Addrs:       []string{"100.100.9.9"},
		Annotations: map[string]string{"tailnetlink/managed": "true"},
	})
	r := NewReconciler(api.Client(), []int{80}, nil, discardLogger())
	vip, err := r.Ensure(context.Background(), "src", testDevice(), "")
	if err != nil {
		t.Fatal(err)
	}
	if vip.VIP.String() != "100.100.9.9" {
		t.Errorf("vip = %v, want existing 100.100.9.9", vip.VIP)
	}
}

func TestReconcilerEnsureErrorIsNotCached(t *testing.T) {
	api := fakeapi.New(t)
	c := api.Client()
	c.Tailnet = "wrong.example"
	r := NewReconciler(c, []int{80}, nil, discardLogger())
	if _, err := r.Ensure(context.Background(), "src", testDevice(), ""); err == nil {
		t.Fatal("want error from API")
	}
	if got := r.List(); len(got) != 0 {
		t.Errorf("failed Ensure was cached: %v", got)
	}
}

// KNOWN-BAD: Ensure overwrites a service it did not create. Here a hand made
// svc:api gets its ports, tags, comment and annotations replaced because a
// rule used short_name "api". Flip in roadmap PR 4 (ownership guard): Ensure
// should refuse and make no PUT.
func TestKnownBad_EnsureOverwritesForeignService(t *testing.T) {
	api := fakeapi.New(t)
	api.PutService(tsclient.VIPService{
		Name:    "svc:api",
		Addrs:   []string{"100.100.7.7"},
		Comment: "hand made",
		Ports:   []string{"tcp:9000"},
		Tags:    []string{"tag:other"},
	})
	r := NewReconciler(api.Client(), []int{80}, []string{"tag:bridge"}, discardLogger())

	if _, err := r.Ensure(context.Background(), "src", testDevice(), "api"); err != nil {
		t.Fatal(err)
	}

	if got := callStrings(api.Writes()); !slices.Equal(got, []string{"PUT /vip-services/svc:api"}) {
		t.Errorf("writes = %v", got)
	}
	svc, _ := api.Service("svc:api")
	if svc.Comment == "hand made" || !slices.Equal(svc.Ports, []string{"tcp:80"}) || svc.Annotations["tailnetlink/managed"] != "true" {
		t.Errorf("expected the foreign service to be overwritten today, got %+v", svc)
	}
}

func TestReconcilerDeleteRemovesOwnService(t *testing.T) {
	api := fakeapi.New(t)
	r := NewReconciler(api.Client(), []int{80}, nil, discardLogger())
	if _, err := r.Ensure(context.Background(), "src", testDevice(), ""); err != nil {
		t.Fatal(err)
	}
	api.ResetCalls()
	if err := r.Delete(context.Background(), "src", testDevice(), ""); err != nil {
		t.Fatal(err)
	}
	if got := callStrings(api.Writes()); !slices.Equal(got, []string{"DELETE /vip-services/svc:tnl-src-web-1"}) {
		t.Errorf("writes = %v", got)
	}
	if _, ok := api.Service("svc:tnl-src-web-1"); ok {
		t.Error("service still exists")
	}
}

// Delete only acts on services this Reconciler instance ensured. That is the
// only thing stopping it from deleting arbitrary services today.
func TestReconcilerDeleteIgnoresUnknown(t *testing.T) {
	api := fakeapi.New(t)
	api.PutService(tsclient.VIPService{Name: "svc:tnl-src-web-1"})
	r := NewReconciler(api.Client(), []int{80}, nil, discardLogger())
	if err := r.Delete(context.Background(), "src", testDevice(), ""); err != nil {
		t.Fatal(err)
	}
	if w := api.Writes(); len(w) != 0 {
		t.Errorf("unexpected writes: %v", callStrings(w))
	}
}

// KNOWN-BAD: Delete trusts its in-memory map and never re-reads the service,
// so it deletes a service even after someone else changed its ownership
// annotation. Flip in roadmap PR 4: re-read and only delete when the owner
// annotation matches.
func TestKnownBad_DeleteIgnoresOwnershipChange(t *testing.T) {
	api := fakeapi.New(t)
	r := NewReconciler(api.Client(), []int{80}, nil, discardLogger())
	if _, err := r.Ensure(context.Background(), "src", testDevice(), ""); err != nil {
		t.Fatal(err)
	}
	api.PutService(tsclient.VIPService{
		Name:        "svc:tnl-src-web-1",
		Addrs:       []string{"100.100.0.1"},
		Annotations: map[string]string{"owner": "someone-else"},
	})
	if err := r.Delete(context.Background(), "src", testDevice(), ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := api.Service("svc:tnl-src-web-1"); ok {
		t.Error("expected the service to be deleted today")
	}
}
