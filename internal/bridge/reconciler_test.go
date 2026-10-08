package bridge

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/rajsinghtech/tailnetlink/internal/testutil/fakeapi"
	tsclient "tailscale.com/client/tailscale/v2"
)

func testDevice() Device {
	return Device{Name: "web-1", FQDN: "web-1.src.example", IP: netip.MustParseAddr("100.64.0.1")}
}

func TestReconcilerEnsureCreatesService(t *testing.T) {
	api := fakeapi.New(t)
	r := NewReconciler(api.Client(), []int{80, 443}, []string{"tag:bridge"}, testOwner, discardLogger())

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
	if svc.Annotations["tailnetlink/managed"] != "true" || svc.Annotations["tailnetlink/owner"] != testOwner || svc.Annotations["tailnetlink/source"] != "src" {
		t.Errorf("annotations = %v", svc.Annotations)
	}
}

func TestReconcilerEnsureIsCached(t *testing.T) {
	api := fakeapi.New(t)
	r := NewReconciler(api.Client(), []int{80}, nil, testOwner, discardLogger())
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
		Annotations: map[string]string{"tailnetlink/managed": "true", "tailnetlink/owner": testOwner},
	})
	r := NewReconciler(api.Client(), []int{80}, nil, testOwner, discardLogger())
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
	r := NewReconciler(c, []int{80}, nil, testOwner, discardLogger())
	if _, err := r.Ensure(context.Background(), "src", testDevice(), ""); err == nil {
		t.Fatal("want error from API")
	}
	if got := r.services; len(got) != 0 {
		t.Errorf("failed Ensure was cached: %v", got)
	}
}

// A hand made svc:api must survive a rule that uses short_name "api": no
// write, and Ensure reports a name conflict.
func TestReconcilerEnsureRefusesForeignService(t *testing.T) {
	api := fakeapi.New(t)
	foreign := tsclient.VIPService{
		Name:    "svc:api",
		Addrs:   []string{"100.100.7.7"},
		Comment: "hand made",
		Ports:   []string{"tcp:9000"},
		Tags:    []string{"tag:other"},
	}
	api.PutService(foreign)
	r := NewReconciler(api.Client(), []int{80}, []string{"tag:bridge"}, testOwner, discardLogger())

	_, err := r.Ensure(context.Background(), "src", testDevice(), "api")
	if !errors.Is(err, ErrNameConflict) {
		t.Fatalf("err = %v, want a name conflict", err)
	}
	if w := api.Writes(); len(w) != 0 {
		t.Errorf("writes = %v, want none", callStrings(w))
	}
	if svc, _ := api.Service("svc:api"); !reflect.DeepEqual(svc, foreign) {
		t.Errorf("foreign service changed: %+v", svc)
	}
	if got := r.services; len(got) != 0 {
		t.Errorf("conflict was cached as ours: %v", got)
	}
}

// Services from older versions only carry tailnetlink/managed. They are
// foreign: there is no adoption.
func TestReconcilerEnsureTreatsManagedWithoutOwnerAsForeign(t *testing.T) {
	api := fakeapi.New(t)
	api.PutService(tsclient.VIPService{
		Name:        "svc:tnl-src-web-1",
		Addrs:       []string{"100.100.9.9"},
		Annotations: map[string]string{"tailnetlink/managed": "true"},
	})
	r := NewReconciler(api.Client(), []int{80}, nil, testOwner, discardLogger())
	_, err := r.Ensure(context.Background(), "src", testDevice(), "")
	var ce *ConflictError
	if !errors.As(err, &ce) || ce.Owner != "" {
		t.Fatalf("err = %v, want a conflict with no owner", err)
	}
	if w := api.Writes(); len(w) != 0 {
		t.Errorf("writes = %v, want none", callStrings(w))
	}
}

// Another instance's service is foreign too, and the error names the owner.
func TestReconcilerEnsureRefusesOtherInstance(t *testing.T) {
	api := fakeapi.New(t)
	api.PutService(tsclient.VIPService{
		Name:        "svc:tnl-src-web-1",
		Annotations: map[string]string{"tailnetlink/managed": "true", "tailnetlink/owner": "other"},
	})
	r := NewReconciler(api.Client(), []int{80}, nil, testOwner, discardLogger())
	_, err := r.Ensure(context.Background(), "src", testDevice(), "")
	if err == nil || !strings.Contains(err.Error(), `instance "other"`) {
		t.Fatalf("err = %v", err)
	}
}

// A failed read is not the same as "not there": Ensure must not write.
func TestReconcilerEnsureStopsOnReadError(t *testing.T) {
	api := fakeapi.New(t)
	api.Fail("GET", "/vip-services/svc:tnl-src-web-1", 500)
	r := NewReconciler(api.Client(), []int{80}, nil, testOwner, discardLogger())
	if _, err := r.Ensure(context.Background(), "src", testDevice(), ""); err == nil {
		t.Fatal("want an error")
	}
	if w := api.Writes(); len(w) != 0 {
		t.Errorf("writes = %v, want none", callStrings(w))
	}
}

// Our own service is reused on restart: same VIP, one update, no delete.
func TestReconcilerEnsureReusesOwnService(t *testing.T) {
	api := fakeapi.New(t)
	api.PutService(tsclient.VIPService{
		Name:        "svc:tnl-src-web-1",
		Addrs:       []string{"100.100.9.9"},
		Ports:       []string{"tcp:81"},
		Annotations: map[string]string{"tailnetlink/managed": "true", "tailnetlink/owner": testOwner},
	})
	r := NewReconciler(api.Client(), []int{80}, nil, testOwner, discardLogger())
	vip, err := r.Ensure(context.Background(), "src", testDevice(), "")
	if err != nil {
		t.Fatal(err)
	}
	if vip.VIP.String() != "100.100.9.9" {
		t.Errorf("vip = %v, want 100.100.9.9", vip.VIP)
	}
	if got := callStrings(api.Writes()); !slices.Equal(got, []string{"PUT /vip-services/svc:tnl-src-web-1"}) {
		t.Errorf("writes = %v", got)
	}
	if svc, _ := api.Service("svc:tnl-src-web-1"); !slices.Equal(svc.Ports, []string{"tcp:80"}) {
		t.Errorf("ports = %v, want the new tcp:80", svc.Ports)
	}
}

func TestEnsureNeedsOwner(t *testing.T) {
	api := fakeapi.New(t)
	if _, err := ensureVIPService(context.Background(), api.Client(), "", tsclient.VIPService{Name: "svc:x"}); err == nil {
		t.Fatal("want an error without an instance id")
	}
	if c := api.Calls(); len(c) != 0 {
		t.Errorf("calls = %v", callStrings(c))
	}
}

func TestReconcilerDeleteRemovesOwnService(t *testing.T) {
	api := fakeapi.New(t)
	r := NewReconciler(api.Client(), []int{80}, nil, testOwner, discardLogger())
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
	r := NewReconciler(api.Client(), []int{80}, nil, testOwner, discardLogger())
	if err := r.Delete(context.Background(), "src", testDevice(), ""); err != nil {
		t.Fatal(err)
	}
	if w := api.Writes(); len(w) != 0 {
		t.Errorf("unexpected writes: %v", callStrings(w))
	}
}

// Delete re-reads the service and leaves it alone if someone else's owner
// annotation is on it now.
func TestReconcilerDeleteSkipsServiceWithNewOwner(t *testing.T) {
	api := fakeapi.New(t)
	r := NewReconciler(api.Client(), []int{80}, nil, testOwner, discardLogger())
	if _, err := r.Ensure(context.Background(), "src", testDevice(), ""); err != nil {
		t.Fatal(err)
	}
	api.PutService(tsclient.VIPService{
		Name:        "svc:tnl-src-web-1",
		Addrs:       []string{"100.100.0.1"},
		Annotations: map[string]string{"tailnetlink/owner": "someone-else"},
	})
	api.ResetCalls()
	err := r.Delete(context.Background(), "src", testDevice(), "")
	if !errors.Is(err, ErrNameConflict) {
		t.Fatalf("err = %v, want a name conflict", err)
	}
	if w := api.Writes(); len(w) != 0 {
		t.Errorf("writes = %v, want none", callStrings(w))
	}
	if _, ok := api.Service("svc:tnl-src-web-1"); !ok {
		t.Error("service was deleted")
	}
}

// A service that is already gone is fine.
func TestReconcilerDeleteAlreadyGone(t *testing.T) {
	api := fakeapi.New(t)
	r := NewReconciler(api.Client(), []int{80}, nil, testOwner, discardLogger())
	if _, err := r.Ensure(context.Background(), "src", testDevice(), ""); err != nil {
		t.Fatal(err)
	}
	api.ResetCalls()
	api.Fail("GET", "/vip-services/svc:tnl-src-web-1", 404)
	if err := r.Delete(context.Background(), "src", testDevice(), ""); err != nil {
		t.Fatal(err)
	}
	if w := api.Writes(); len(w) != 0 {
		t.Errorf("writes = %v, want none", callStrings(w))
	}
}

func TestReconcilerDeleteReadError(t *testing.T) {
	api := fakeapi.New(t)
	r := NewReconciler(api.Client(), []int{80}, nil, testOwner, discardLogger())
	if _, err := r.Ensure(context.Background(), "src", testDevice(), ""); err != nil {
		t.Fatal(err)
	}
	api.ResetCalls()
	api.Fail("GET", "/vip-services/svc:tnl-src-web-1", 500)
	if err := r.Delete(context.Background(), "src", testDevice(), ""); err == nil {
		t.Fatal("want an error")
	}
	if w := api.Writes(); len(w) != 0 {
		t.Errorf("writes = %v, want none", callStrings(w))
	}
}

func TestReconcilerDeleteRetriesAfterFailure(t *testing.T) {
	api := fakeapi.New(t)
	r := NewReconciler(api.Client(), []int{80}, nil, testOwner, discardLogger())
	if _, err := r.Ensure(context.Background(), "src", testDevice(), ""); err != nil {
		t.Fatal(err)
	}
	api.FailOnce(http.MethodDelete, "/vip-services/svc:tnl-src-web-1", http.StatusInternalServerError)
	if err := r.Delete(context.Background(), "src", testDevice(), ""); err == nil {
		t.Fatal("want the injected failure")
	}
	if _, ok := api.Service("svc:tnl-src-web-1"); !ok {
		t.Fatal("failed delete removed the service from the reconciler")
	}
	if err := r.Delete(context.Background(), "src", testDevice(), ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := api.Service("svc:tnl-src-web-1"); ok {
		t.Fatal("service still exists after the retry")
	}
}

func TestReconcilerDeleteError(t *testing.T) {
	api := fakeapi.New(t)
	r := NewReconciler(api.Client(), []int{80}, nil, testOwner, discardLogger())
	if _, err := r.Ensure(context.Background(), "src", testDevice(), ""); err != nil {
		t.Fatal(err)
	}
	api.Fail("DELETE", "/vip-services/svc:tnl-src-web-1", 500)
	if err := r.Delete(context.Background(), "src", testDevice(), ""); err == nil {
		t.Fatal("want an error")
	}
}

func TestConflictErrorMessage(t *testing.T) {
	for _, tc := range []struct {
		err  *ConflictError
		want string
	}{
		{&ConflictError{Service: "svc:a"}, "name conflict: svc:a already exists and was not created by this tailnetlink instance"},
		{&ConflictError{Service: "svc:a", Owner: "b"}, `name conflict: svc:a is owned by tailnetlink instance "b"`},
	} {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}
