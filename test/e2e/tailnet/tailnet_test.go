package tailnet_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/test/e2e/tailnet"
	"github.com/rajsinghtech/tailnetlink/test/e2e/tailnet/tailnettest"
)

func TestListFollowsCursor(t *testing.T) {
	f := tailnettest.New(t)
	f.PageSize = 2
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		f.Add(n, time.Now())
	}
	cl := tailnet.New(f.URL(), tailnet.StaticToken(tailnettest.OrgToken))
	got, err := cl.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("listed %d tailnets, want 5", len(got))
	}
}

func TestCreateValidatesName(t *testing.T) {
	f := tailnettest.New(t)
	cl := tailnet.New(f.URL(), tailnet.StaticToken(tailnettest.OrgToken))
	if _, err := cl.Create(context.Background(), "bad/name"); err == nil {
		t.Fatal("accepted a name with a slash")
	}
	if n := len(f.Calls()); n != 0 {
		t.Fatalf("sent %d calls for an invalid name", n)
	}
}

func TestOrgTokenCannotDelete(t *testing.T) {
	f := tailnettest.New(t)
	tn := f.Add("tailnetlink-ci-1-1-src", time.Now())
	cl := tailnet.New(f.URL(), tailnet.StaticToken(tailnettest.OrgToken))
	err := cl.Delete(context.Background(), cl.Org, tn.ID)
	if err == nil {
		t.Fatal("org token deleted a child tailnet")
	}
	// A child OAuth token works, and deleting again is a no-op (404).
	child := cl.OAuthToken(tn.OAuthClientID, tn.OAuthSecret)
	if err := cl.Delete(context.Background(), child, tn.ID); err != nil {
		t.Fatal(err)
	}
	if err := cl.Delete(context.Background(), tailnet.StaticToken("child:"+tn.ID), tn.ID); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}

func TestChildHelpers(t *testing.T) {
	f := tailnettest.New(t)
	ctx := context.Background()
	cl := tailnet.New(f.URL(), tailnet.StaticToken(tailnettest.OrgToken))
	tn, err := cl.Create(ctx, "tailnetlink-ci-1-1-src")
	if err != nil {
		t.Fatal(err)
	}
	child := cl.OAuthToken(tn.OAuthClientID, tn.OAuthClientSecret)
	if _, err := cl.CreateAuthKey(ctx, child, tn.ID, []string{"tag:e2e-client"}); err != nil {
		t.Fatal(err)
	}
	if id, secret, err := cl.CreateOAuthClient(ctx, child, tn.ID, "app", []string{"auth_keys"}, []string{"tag:tailnetlink"}); err != nil || id == "" || secret == "" {
		t.Fatalf("oauth client: %q %q %v", id, secret, err)
	}
	fed, aud, err := cl.CreateFederatedIdentity(ctx, child, tn.ID, tailnet.FederatedIdentity{Scopes: []string{"all"}, Issuer: "https://token.actions.githubusercontent.com", Subject: "repo:x/y:*"})
	if err != nil || aud != tailnet.AudienceFor(fed) {
		t.Fatalf("fed: %q %q %v", fed, aud, err)
	}
	// The federated identity yields a child token through GitHub OIDC.
	oidc, ok := tailnet.GitHubOIDCFromEnv(func(k string) string {
		return map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": f.URL() + "/oidc", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "gh-request-token"}[k]
	})
	if !ok {
		t.Fatal("no oidc")
	}
	if err := cl.DeleteAndVerify(ctx, cl.WIFToken(oidc, fed, ""), tn.ID, tailnet.Retry{Sleep: func(time.Duration) {}}); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteAndVerifyCapsWait(t *testing.T) {
	f := tailnettest.New(t)
	tn := f.Add("tailnetlink-ci-1-1-src", time.Now())
	f.SilentDeletes = 3
	cl := tailnet.New(f.URL(), tailnet.StaticToken(tailnettest.OrgToken))
	var slept []time.Duration
	err := cl.DeleteAndVerify(context.Background(), tailnet.StaticToken("child:"+tn.ID), tn.ID, tailnet.Retry{
		Attempts: 6,
		Backoff:  8 * time.Second,
		MaxWait:  10 * time.Second,
		Sleep:    func(d time.Duration) { slept = append(slept, d) },
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{8 * time.Second, 10 * time.Second, 10 * time.Second}
	if len(slept) != len(want) {
		t.Fatalf("sleeps = %v, want %v", slept, want)
	}
	for i := range want {
		if slept[i] != want[i] {
			t.Fatalf("sleeps = %v, want %v", slept, want)
		}
	}
	if f.Get(tn.DisplayName) != nil {
		t.Fatal("tailnet still listed")
	}
}

func TestBadTokens(t *testing.T) {
	f := tailnettest.New(t)
	cl := tailnet.New(f.URL(), tailnet.StaticToken(""))
	if _, err := cl.List(context.Background()); err == nil {
		t.Fatal("empty token accepted")
	}
	if _, err := cl.Exchange(context.Background(), "nope", "bad-jwt"); err == nil {
		t.Fatal("bad jwt accepted")
	}
	if _, err := cl.OAuthToken("x", "y")(context.Background()); err == nil {
		t.Fatal("bad oauth client accepted")
	}
	if _, ok := tailnet.GitHubOIDCFromEnv(func(string) string { return "" }); ok {
		t.Fatal("oidc without env")
	}
}

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := &tailnet.State{}
	s.Upsert(tailnet.StateEntry{ID: "T1", DisplayName: "a"})
	s.Upsert(tailnet.StateEntry{ID: "T1", DisplayName: "a", FedClientID: "f"})
	if err := s.Save(filepath.Join(dir, "x.json")); err != nil {
		t.Fatal(err)
	}
	got, err := tailnet.LoadStateDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := got.Lookup("", "a"); !ok || e.FedClientID != "f" || len(got.Tailnets) != 1 {
		t.Fatalf("state = %+v", got)
	}
	if empty, err := tailnet.LoadStateDir(filepath.Join(dir, "missing")); err != nil || len(empty.Tailnets) != 0 {
		t.Fatalf("missing dir: %v %v", empty, err)
	}
}
