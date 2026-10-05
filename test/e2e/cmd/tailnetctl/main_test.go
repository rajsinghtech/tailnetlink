package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/test/e2e/tailnet"
	"github.com/rajsinghtech/tailnetlink/test/e2e/tailnet/tailnettest"
)

var now = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

type harness struct {
	t      *testing.T
	fake   *tailnettest.Fake
	env    map[string]string
	stderr bytes.Buffer
	stdout bytes.Buffer
	sleeps []time.Duration
}

func newHarness(t *testing.T) *harness {
	f := tailnettest.New(t)
	f.Now = func() time.Time { return now }
	h := &harness{t: t, fake: f, env: map[string]string{
		"ACTIONS_ID_TOKEN_REQUEST_URL":   f.URL() + "/oidc?api-version=2.0",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "gh-request-token",
	}}
	return h
}

func (h *harness) run(args ...string) int {
	h.stderr.Reset()
	h.stdout.Reset()
	a := &app{
		getenv: func(k string) string { return h.env[k] },
		out:    &h.stdout, errw: &h.stderr,
		now:   func() time.Time { return now },
		sleep: func(d time.Duration) { h.sleeps = append(h.sleeps, d) },
	}
	args = append(args[:1:1], append([]string{"--api-base", h.fake.URL(), "--org-client-id", "org-fed"}, args[1:]...)...)
	return a.run(context.Background(), args)
}

// leftover adds a CI tailnet with a federated identity recorded in a state
// file under dir, as an earlier create would have.
func (h *harness) leftover(dir, name string, age time.Duration, record bool) *tailnettest.Tailnet {
	tn := h.fake.Add(name, now.Add(-age))
	if !record {
		return tn
	}
	fed := h.fake.AddFed(tn)
	runID, attempt, role, _ := tailnet.ParseName(name)
	st := &tailnet.State{}
	st.Upsert(tailnet.StateEntry{RunID: runID, Attempt: attempt, Role: role, ID: tn.ID, DisplayName: name, FedClientID: fed})
	sub := filepath.Join(dir, runID+"-"+role)
	if err := os.MkdirAll(sub, 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := st.Save(filepath.Join(sub, "tailnets.json")); err != nil {
		h.t.Fatal(err)
	}
	return tn
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestParseNameOnlyMatchesCINames(t *testing.T) {
	good := []string{"tailnetlink-ci-123-1-src", "tailnetlink-ci-9876543210-12-dst"}
	bad := []string{
		"example.com", "Raj's tailnet", "tailnetlink", "tailnetlink-ci-", "tailnetlink-ci-123-src",
		"tailnetlink-ci-abc-1-src", "xtailnetlink-ci-123-1-src", "tailnetlink-ci-123-1-src-extra",
		"tailgate-ci-123-1-src", "tailnetlink-ci-123-1-SRC", "tailnetlink ci 123 1 src",
	}
	for _, n := range good {
		if _, _, _, ok := tailnet.ParseName(n); !ok {
			t.Errorf("ParseName(%q) = false, want true", n)
		}
	}
	for _, n := range bad {
		if _, _, _, ok := tailnet.ParseName(n); ok {
			t.Errorf("ParseName(%q) = true, want false", n)
		}
	}
}

func TestJanitorDeletesOnlyStaleCITailnets(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	h.fake.Add("Main tailnet", now.Add(-1000*time.Hour))
	h.fake.Add("tailgate-ci-5-1-src", now.Add(-10*time.Hour)) // another repo's CI
	h.fake.Add("tailnetlink-ci-notes", now.Add(-10*time.Hour))
	h.leftover(dir, "tailnetlink-ci-100-1-src", 3*time.Hour, true)
	h.leftover(dir, "tailnetlink-ci-100-1-dst", 3*time.Hour, true)
	h.leftover(dir, "tailnetlink-ci-200-1-src", 30*time.Minute, true) // still running

	if code := h.run("janitor", "--older-than", "2h", "--state-dir", dir); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	got := h.fake.Tailnets()
	for _, gone := range []string{"tailnetlink-ci-100-1-src", "tailnetlink-ci-100-1-dst"} {
		if has(got, gone) {
			t.Errorf("%s should have been deleted", gone)
		}
	}
	for _, kept := range []string{"Main tailnet", "tailgate-ci-5-1-src", "tailnetlink-ci-notes", "tailnetlink-ci-200-1-src"} {
		if !has(got, kept) {
			t.Errorf("%s should not have been touched", kept)
		}
	}
	// No delete was ever sent for a non-CI tailnet.
	for _, c := range h.fake.Calls() {
		if c.Method == "DELETE" && !strings.Contains(c.Auth, "child:") {
			t.Errorf("delete sent with non-child token: %+v", c)
		}
	}
}

func TestJanitorAgeCutoff(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	h.leftover(dir, "tailnetlink-ci-1-1-src", 2*time.Hour+time.Minute, true)
	h.leftover(dir, "tailnetlink-ci-2-1-src", 2*time.Hour-time.Minute, true)
	if code := h.run("janitor", "--older-than", "2h", "--state-dir", dir); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	got := h.fake.Tailnets()
	if has(got, "tailnetlink-ci-1-1-src") || !has(got, "tailnetlink-ci-2-1-src") {
		t.Fatalf("tailnets after janitor = %v", got)
	}
}

func TestJanitorRefusesShortCutoff(t *testing.T) {
	h := newHarness(t)
	if code := h.run("janitor", "--older-than", "5m"); code == 0 {
		t.Fatal("janitor accepted a 5m cutoff")
	}
}

func TestJanitorDryRunDeletesNothing(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	h.leftover(dir, "tailnetlink-ci-1-1-src", 5*time.Hour, true)
	if code := h.run("janitor", "--dry-run", "--state-dir", dir); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if n := h.fake.CountCalls("DELETE", "/"); n != 0 {
		t.Fatalf("dry run sent %d deletes", n)
	}
	if !strings.Contains(h.stderr.String(), "would delete tailnetlink-ci-1-1-src") {
		t.Fatalf("dry run output: %s", h.stderr.String())
	}
}

func TestJanitorFailsLoudlyOnOrphan(t *testing.T) {
	h := newHarness(t)
	h.leftover(t.TempDir(), "tailnetlink-ci-1-1-src", 5*time.Hour, false)
	if code := h.run("janitor"); code == 0 {
		t.Fatal("janitor exited 0 with an undeletable CI tailnet")
	}
	if !strings.Contains(h.stderr.String(), "delete it by hand") {
		t.Fatalf("missing orphan message: %s", h.stderr.String())
	}
}

func TestDeleteLooksUpByRunIDWithoutRecordedID(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	// The state file knows the federated identity but the job outputs never
	// got the tailnet ID. delete finds the tailnet by its name.
	tn := h.leftover(dir, "tailnetlink-ci-777-1-src", time.Minute, true)
	st, _ := tailnet.LoadStateDir(dir)
	st.Tailnets[0].ID = "" // only the name and federated identity survived
	path := filepath.Join(t.TempDir(), "s.json")
	if err := st.Save(path); err != nil {
		t.Fatal(err)
	}
	h.fake.Add("tailnetlink-ci-778-1-src", now) // a different run, untouched
	if code := h.run("delete", "--run-id", "777", "--state-file", path); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if h.fake.Get(tn.DisplayName) != nil {
		t.Fatal("run 777 tailnet still exists")
	}
	if h.fake.Get("tailnetlink-ci-778-1-src") == nil {
		t.Fatal("run 778 tailnet was deleted")
	}
}

func TestDeleteOnlyTouchesTheGivenAttempt(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	h.leftover(dir, "tailnetlink-ci-5-1-src", time.Minute, true)
	h.leftover(dir, "tailnetlink-ci-5-2-src", time.Minute, true)
	if code := h.run("delete", "--run-id", "5", "--attempt", "2", "--state-dir", dir); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	got := h.fake.Tailnets()
	if !has(got, "tailnetlink-ci-5-1-src") || has(got, "tailnetlink-ci-5-2-src") {
		t.Fatalf("tailnets = %v", got)
	}
}

func TestDeleteNothingToDo(t *testing.T) {
	h := newHarness(t)
	h.fake.Add("Main tailnet", now)
	if code := h.run("delete", "--run-id", "1"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
}

func TestDeleteRetriesThenVerifies(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	h.leftover(dir, "tailnetlink-ci-9-1-src", time.Minute, true)
	h.fake.FailDeletes = 1   // first delete: 500
	h.fake.SilentDeletes = 1 // second delete: 200 but the tailnet is still listed
	if code := h.run("delete", "--run-id", "9", "--state-dir", dir, "--backoff", "1s"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if n := h.fake.CountCalls("DELETE", "/api/v2/tailnet/"); n != 3 {
		t.Errorf("delete calls = %d, want 3", n)
	}
	if want := []time.Duration{time.Second, 2 * time.Second}; len(h.sleeps) != 2 || h.sleeps[0] != want[0] || h.sleeps[1] != want[1] {
		t.Errorf("backoff = %v, want %v", h.sleeps, want)
	}
	if h.fake.Get("tailnetlink-ci-9-1-src") != nil {
		t.Fatal("tailnet still exists")
	}
}

func TestDeleteFailureExitsNonZero(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	h.leftover(dir, "tailnetlink-ci-9-1-src", time.Minute, true)
	h.fake.ForbidAllDeletes = true
	if code := h.run("delete", "--run-id", "9", "--state-dir", dir, "--attempts", "3"); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(h.stderr.String(), "NOT deleted: tailnetlink-ci-9-1-src") {
		t.Fatalf("missing failure summary: %s", h.stderr.String())
	}
	if n := h.fake.CountCalls("DELETE", "/api/v2/tailnet/"); n != 3 {
		t.Errorf("delete calls = %d, want 3", n)
	}
}

func TestDeleteNeedsRunID(t *testing.T) {
	h := newHarness(t)
	if code := h.run("delete"); code == 0 {
		t.Fatal("delete without --run-id succeeded")
	}
}

func TestCapCheck(t *testing.T) {
	h := newHarness(t)
	h.fake.Add("Main tailnet", now)
	for i := 0; i < 7; i++ {
		h.fake.Add("other "+string(rune('a'+i)), now)
	}
	// 8 tailnets, cap 10: two more fit exactly.
	if code := h.run("check-cap"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	h.fake.Add("tailnetlink-ci-1-1-src", now.Add(-3*time.Hour))
	if code := h.run("check-cap"); code == 0 {
		t.Fatal("check-cap passed with 9 of 10 tailnets and 2 needed")
	}
	msg := h.stderr.String()
	for _, want := range []string{"9 of 10", "tailnetlink-ci-1-1-src (age 3h0m0s)", "e2e-janitor"} {
		if !strings.Contains(msg, want) {
			t.Errorf("cap message missing %q: %s", want, msg)
		}
	}
}

func TestCapCheckCIBudget(t *testing.T) {
	h := newHarness(t)
	for i := 1; i <= 3; i++ {
		h.fake.Add(tailnet.Name("1", "1", []string{"a", "b", "c"}[i-1]), now)
	}
	if code := h.run("check-cap", "--max-ci", "4"); code == 0 {
		t.Fatal("check-cap passed with 3 CI tailnets, 2 needed, limit 4")
	}
	if !strings.Contains(h.stderr.String(), "3 CI tailnets already exist") {
		t.Fatalf("message: %s", h.stderr.String())
	}
}

func TestCreateRecordsIDsAndFederatedIdentity(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "gh_output")
	state := filepath.Join(dir, "tailnets.json")
	code := h.run("create", "--run-id", "42", "--attempt", "1", "--state-file", state, "--github-output", out,
		"--fed-claim", "repository_id=123")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	for _, n := range []string{"tailnetlink-ci-42-1-src", "tailnetlink-ci-42-1-dst"} {
		tn := h.fake.Get(n)
		if tn == nil {
			t.Fatalf("%s not created", n)
		}
		if len(tn.FedClientIDs) != 1 || !strings.Contains(tn.Policy, "tag:tailnetlink") {
			t.Errorf("%s: fed=%v policy applied=%v", n, tn.FedClientIDs, tn.Policy != "")
		}
	}
	b, _ := os.ReadFile(out)
	for _, k := range []string{"src_id=", "src_dns_name=", "src_fed_client_id=", "src_fed_audience=api.tailscale.com/", "dst_id="} {
		if !strings.Contains(string(b), k) {
			t.Errorf("outputs missing %q:\n%s", k, b)
		}
	}
	// No secret ever reaches outputs or the state file.
	sb, _ := os.ReadFile(state)
	for _, f := range [][]byte{b, sb} {
		if bytes.Contains(f, []byte("tskey-client")) {
			t.Fatalf("secret leaked into a file:\n%s", f)
		}
	}
	// The state file is enough for delete to finish the job.
	if code := h.run("delete", "--run-id", "42", "--state-file", state); code != 0 {
		t.Fatalf("delete exit %d: %s", code, h.stderr.String())
	}
	if len(h.fake.Tailnets()) != 0 {
		t.Fatalf("left behind: %v", h.fake.Tailnets())
	}
}

func TestCreateRollsBackOnFailure(t *testing.T) {
	h := newHarness(t)
	h.fake.FailFederated = true
	dir := t.TempDir()
	code := h.run("create", "--run-id", "43", "--state-file", filepath.Join(dir, "s.json"), "--github-output", filepath.Join(dir, "o"))
	if code == 0 {
		t.Fatal("create succeeded although the federated identity failed")
	}
	if got := h.fake.Tailnets(); len(got) != 0 {
		t.Fatalf("rollback left %v", got)
	}
	// The ID was recorded before the failure.
	b, _ := os.ReadFile(filepath.Join(dir, "o"))
	if !strings.Contains(string(b), "src_id=") {
		t.Fatalf("src_id not written before failure: %s", b)
	}
}

func TestCreateRollbackFailureIsLoud(t *testing.T) {
	h := newHarness(t)
	h.fake.FailPolicy = true
	h.fake.ForbidAllDeletes = true
	dir := t.TempDir()
	code := h.run("create", "--run-id", "44", "--attempts", "2", "--state-file", filepath.Join(dir, "s.json"))
	if code == 0 {
		t.Fatal("create succeeded")
	}
	if !strings.Contains(h.stderr.String(), "ROLLBACK FAILED") {
		t.Fatalf("missing rollback failure: %s", h.stderr.String())
	}
}

func TestCreateStopsAtCap(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 9; i++ {
		h.fake.Add("t "+string(rune('a'+i)), now)
	}
	if code := h.run("create", "--run-id", "1", "--state-file", filepath.Join(t.TempDir(), "s.json")); code == 0 {
		t.Fatal("create went over the cap")
	}
	if n := h.fake.CountCalls("POST", "/api/v2/organizations/"); n != 0 {
		t.Fatalf("create sent %d create calls over the cap", n)
	}
}

func TestCreateDryRun(t *testing.T) {
	h := newHarness(t)
	if code := h.run("create", "--run-id", "1", "--dry-run"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if len(h.fake.Tailnets()) != 0 {
		t.Fatal("dry run created tailnets")
	}
}

func TestCreateRefusesExistingName(t *testing.T) {
	h := newHarness(t)
	h.fake.Add("tailnetlink-ci-1-1-src", now)
	if code := h.run("create", "--run-id", "1", "--max-ci", "10", "--state-file", filepath.Join(t.TempDir(), "s.json")); code == 0 {
		t.Fatal("create reused an existing tailnet")
	}
}

func TestOrgTokenFromEnvAndMissingCreds(t *testing.T) {
	h := newHarness(t)
	h.env = map[string]string{"TS_API_ACCESS_TOKEN": tailnettest.OrgToken}
	if code := h.run("check-cap"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	h.env = map[string]string{}
	if code := h.run("check-cap"); code == 0 {
		t.Fatal("check-cap succeeded with no credentials")
	}
}

func TestTokenCommand(t *testing.T) {
	h := newHarness(t)
	if code := h.run("token"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if strings.TrimSpace(h.stdout.String()) != tailnettest.OrgToken {
		t.Fatalf("token output %q", h.stdout.String())
	}
}

func TestUsageErrors(t *testing.T) {
	a := &app{getenv: func(string) string { return "" }, out: &bytes.Buffer{}, errw: &bytes.Buffer{}, now: time.Now, sleep: func(time.Duration) {}}
	if a.run(context.Background(), nil) != 2 || a.run(context.Background(), []string{"nope"}) != 2 {
		t.Fatal("bad usage did not exit 2")
	}
}
