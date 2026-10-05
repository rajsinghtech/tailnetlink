package bridge

import (
	"context"
	"slices"
	"testing"

	"github.com/rajsinghtech/tailnetlink/internal/testutil/fakeapi"
)

func TestSplitDNSConfigureAddsResolver(t *testing.T) {
	api := fakeapi.New(t)
	s := NewSplitDNSConfigurator(api.Client(), "src.example", "100.100.0.53", discardLogger())
	if err := s.Configure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := api.SplitDNS("src.example"); !slices.Equal(got, []string{"100.100.0.53"}) {
		t.Errorf("resolvers = %v", got)
	}
}

func TestSplitDNSConfigureKeepsExistingResolvers(t *testing.T) {
	api := fakeapi.New(t)
	api.SetSplitDNS("src.example", []string{"192.0.2.1"})
	api.SetSplitDNS("other.example", []string{"192.0.2.2"})
	s := NewSplitDNSConfigurator(api.Client(), "src.example", "100.100.0.53", discardLogger())
	if err := s.Configure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := api.SplitDNS("src.example"); !slices.Equal(got, []string{"192.0.2.1", "100.100.0.53"}) {
		t.Errorf("resolvers = %v", got)
	}
	if got := api.SplitDNS("other.example"); !slices.Equal(got, []string{"192.0.2.2"}) {
		t.Errorf("other zone changed: %v", got)
	}
}

func TestSplitDNSConfigureIsIdempotent(t *testing.T) {
	api := fakeapi.New(t)
	api.SetSplitDNS("src.example", []string{"100.100.0.53"})
	s := NewSplitDNSConfigurator(api.Client(), "src.example", "100.100.0.53", discardLogger())
	if err := s.Configure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w := api.Writes(); len(w) != 0 {
		t.Errorf("unexpected writes: %v", callStrings(w))
	}
}

func TestSplitDNSRemoveKeepsOtherResolvers(t *testing.T) {
	api := fakeapi.New(t)
	api.SetSplitDNS("src.example", []string{"192.0.2.1", "100.100.0.53"})
	s := NewSplitDNSConfigurator(api.Client(), "src.example", "100.100.0.53", discardLogger())
	if err := s.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := api.SplitDNS("src.example"); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("resolvers = %v", got)
	}
}

func TestSplitDNSRemoveLastResolverDropsZone(t *testing.T) {
	api := fakeapi.New(t)
	api.SetSplitDNS("src.example", []string{"100.100.0.53"})
	s := NewSplitDNSConfigurator(api.Client(), "src.example", "100.100.0.53", discardLogger())
	if err := s.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if api.HasZone("src.example") {
		t.Errorf("zone still present: %v", api.SplitDNS("src.example"))
	}
}

func TestSplitDNSRemoveNotPresentIsNoop(t *testing.T) {
	api := fakeapi.New(t)
	api.SetSplitDNS("src.example", []string{"192.0.2.1"})
	s := NewSplitDNSConfigurator(api.Client(), "src.example", "100.100.0.53", discardLogger())
	if err := s.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w := api.Writes(); len(w) != 0 {
		t.Errorf("unexpected writes: %v", callStrings(w))
	}
}
