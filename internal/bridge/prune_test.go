package bridge

import (
	"context"
	"slices"
	"testing"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/testutil/fakeapi"
	tsclient "tailscale.com/client/tailscale/v2"
)

func pruneFixture(t *testing.T) (*fakeapi.Server, *config.Config) {
	t.Helper()
	api := fakeapi.New(t)
	own := map[string]string{"tailnetlink/owner": testOwner}
	api.PutService(tsclient.VIPService{Name: "svc:tnl-src-web-1", Addrs: []string{"100.100.0.1"}, Annotations: own})
	api.PutService(tsclient.VIPService{Name: "svc:tnl-dns-src-example-dns", Addrs: []string{"100.100.0.53"}, Annotations: own})
	api.PutService(tsclient.VIPService{Name: "svc:theirs", Addrs: []string{"100.100.0.9"}, Annotations: map[string]string{"tailnetlink/owner": "other"}})
	api.PutService(tsclient.VIPService{Name: "svc:old", Addrs: []string{"100.100.0.8"}, Annotations: map[string]string{"tailnetlink/managed": "true"}})
	api.PutService(tsclient.VIPService{Name: "svc:hand-made", Addrs: []string{"100.100.0.7"}})
	api.SetSplitDNS("src.example", []string{"100.100.0.53", "100.99.0.1"})
	api.SetSplitDNS("only.example", []string{"100.100.0.53"})
	api.SetSplitDNS("other.example", []string{"100.99.0.2"})
	cfg := &config.Config{
		InstanceID: testOwner,
		Tailnets: map[string]config.TailnetConfig{
			"dest": {Tailnet: api.Tailnet, APIBaseURL: api.URL(), OAuth: config.OAuthCreds{ClientID: "id", ClientSecret: "secret"}},
		},
	}
	return api, cfg
}

// Prune deletes only owned services and only their split-DNS resolvers.
func TestPruneDeletesOnlyOwned(t *testing.T) {
	api, cfg := pruneFixture(t)
	actions, err := Prune(context.Background(), cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := api.ServiceNames(), []string{"svc:hand-made", "svc:old", "svc:theirs"}; !slices.Equal(got, want) {
		t.Errorf("services left = %v, want %v", got, want)
	}
	if got := api.SplitDNS("src.example"); !slices.Equal(got, []string{"100.99.0.1"}) {
		t.Errorf("src.example resolvers = %v", got)
	}
	if api.HasZone("only.example") {
		t.Error("zone with only our resolver is still there")
	}
	if got := api.SplitDNS("other.example"); !slices.Equal(got, []string{"100.99.0.2"}) {
		t.Errorf("other.example resolvers = %v", got)
	}
	want := []string{
		"dest: delete service svc:tnl-dns-src-example-dns",
		"dest: delete service svc:tnl-src-web-1",
		"dest: remove split-DNS resolver only.example 100.100.0.53",
		"dest: remove split-DNS resolver src.example 100.100.0.53",
	}
	if got := callStrings(actions); !slices.Equal(got, want) {
		t.Errorf("actions = %v\nwant %v", got, want)
	}
}

func TestPruneDryRunChangesNothing(t *testing.T) {
	api, cfg := pruneFixture(t)
	api.ResetCalls()
	actions, err := Prune(context.Background(), cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 4 {
		t.Errorf("actions = %v", callStrings(actions))
	}
	if w := api.Writes(); len(w) != 0 {
		t.Errorf("writes in dry run = %v", callStrings(w))
	}
}

func TestPruneErrors(t *testing.T) {
	if _, err := Prune(context.Background(), &config.Config{}, false); err == nil {
		t.Error("want an error without instance_id")
	}
	api, cfg := pruneFixture(t)
	api.Fail("GET", "/vip-services", 500)
	if _, err := Prune(context.Background(), cfg, false); err == nil {
		t.Error("want an error when listing fails")
	}
	api2, cfg2 := pruneFixture(t)
	api2.Fail("GET", "/dns/split-dns", 500)
	if _, err := Prune(context.Background(), cfg2, false); err == nil {
		t.Error("want an error when split-DNS read fails")
	}
	api3, cfg3 := pruneFixture(t)
	api3.Fail("DELETE", "/vip-services/svc:tnl-dns-src-example-dns", 500)
	if _, err := Prune(context.Background(), cfg3, false); err == nil {
		t.Error("want an error when delete fails")
	}
	api4, cfg4 := pruneFixture(t)
	api4.Fail("PATCH", "/dns/split-dns", 500)
	if _, err := Prune(context.Background(), cfg4, false); err == nil {
		t.Error("want an error when split-DNS update fails")
	}
}
