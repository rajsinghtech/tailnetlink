package config

import (
	"slices"
	"testing"
)

func TestLinkRuleKeepsTheDestinationSlice(t *testing.T) {
	dsts := []string{"work", "partner"}
	got, err := (Link{
		Name:  "api",
		Tag:   "tag:api",
		Ports: []int{80},
	}).rule("home", dsts, AuthzConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.DestTailnets, []string{"work", "partner"}) {
		t.Fatalf("dests = %v", got.DestTailnets)
	}
	dsts[0] = "changed"
	if got.DestTailnets[0] != "work" {
		t.Fatal("rule kept the caller's slice")
	}
	if got.SourceTailnet != "home" || got.From != "" {
		t.Fatalf("non-local rule = %+v", got)
	}

	local, err := (Link{
		Name:  "db",
		Local: []LocalSourceSpec{{Addr: "10.0.0.1:5432", DNSName: "db.example.com"}},
	}).rule("home", []string{"work"}, AuthzConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if local.SourceTailnet != "" || len(local.DestTailnets) != 1 || local.DestTailnets[0] != "work" {
		t.Fatalf("local rule = %+v", local)
	}

	routed, err := (Link{
		Name: "db",
		Local: []LocalSourceSpec{{
			Addr: "app.internal.example.com", DNSName: "db.example.com", Via: ViaTailnet, Ports: LocalPortList(443),
		}},
	}).rule("home", []string{"work", "partner"}, AuthzConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if routed.SourceTailnet != "home" || !slices.Equal(routed.DestTailnets, []string{"work", "partner"}) {
		t.Fatalf("via tailnet rule = %+v", routed)
	}
}
