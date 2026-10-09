// Command tailnetctl creates and cleans up the throwaway tailnets that
// tailnetlink's real-tailnet e2e job runs against.
//
//	tailnetctl create    --run-id ID --attempt N   create src and dst for this run
//	tailnetctl delete    --run-id ID [--attempt N]  delete this run's tailnets
//	tailnetctl janitor   --older-than 2h            delete stale CI tailnets
//	tailnetctl check-cap                            fail if creating would hit the cap
//	tailnetctl token     --client-id ID             print a WIF access token
//
// Org-level calls (create, list) use TS_API_ACCESS_TOKEN if set, otherwise
// they exchange a GitHub OIDC token through the shared org federated
// identity. Child-level calls (policy, keys, delete) use the child's one-time
// OAuth client while the creating process is alive, and afterwards a
// federated identity created inside each child, so no secret ever leaves
// the process that created the tailnet.
//
// Every delete is followed by a list call to confirm the tailnet is gone,
// with retries. Any tailnet that can't be deleted makes the command exit
// non-zero. Only display names that match tailnetlink-ci-<run>-<attempt>-<role>
// are ever considered, so the organization's own tailnet is never touched.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/rajsinghtech/tailnetlink/test/e2e/tailnet"
)

// OrgFedClientID is the organization-level federated identity the owner's
// repos already use for e2e (same client as rajsinghtech/tailgate and
// rajsinghtech/tailvoy). Client IDs and audiences are not secret.
const OrgFedClientID = "TbqNGJkY5611CNTRL-kz4CwX2LK721CNTRL"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a := &app{getenv: os.Getenv, out: os.Stdout, errw: os.Stderr, now: time.Now, sleep: time.Sleep}
	os.Exit(a.run(ctx, os.Args[1:]))
}

type app struct {
	getenv func(string) string
	out    io.Writer
	errw   io.Writer
	now    func() time.Time
	sleep  func(time.Duration)
}

func (a *app) logf(format string, args ...any) { fmt.Fprintf(a.errw, format+"\n", args...) }

func (a *app) run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		a.logf("usage: tailnetctl create|delete|janitor|check-cap|token [flags]")
		return 2
	}
	var err error
	switch args[0] {
	case "create":
		err = a.create(ctx, args[1:])
	case "delete":
		err = a.deleteRun(ctx, args[1:])
	case "janitor":
		err = a.janitor(ctx, args[1:])
	case "check-cap":
		err = a.checkCap(ctx, args[1:])
	case "token":
		err = a.token(ctx, args[1:])
	default:
		a.logf("unknown command %q", args[0])
		return 2
	}
	if err != nil {
		a.logf("tailnetctl %s: %v", args[0], err)
		if errors.Is(err, flag.ErrHelp) {
			return 2
		}
		return 1
	}
	return 0
}

type common struct {
	apiBase     string
	orgClientID string
	dryRun      bool
	attempts    int
	backoff     time.Duration
	maxWait     time.Duration
}

func (a *app) flags(name string, c *common) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.errw)
	fs.StringVar(&c.apiBase, "api-base", tailnet.DefaultAPIBase, "Tailscale API base URL")
	fs.StringVar(&c.orgClientID, "org-client-id", OrgFedClientID, "org-level federated identity client ID")
	fs.BoolVar(&c.dryRun, "dry-run", false, "print what would happen without creating or deleting anything")
	fs.IntVar(&c.attempts, "attempts", 10, "delete attempts per tailnet")
	fs.DurationVar(&c.backoff, "backoff", 2*time.Second, "first retry wait, doubled each attempt")
	fs.DurationVar(&c.maxWait, "max-wait", 15*time.Second, "cap on one delete retry wait")
	return fs
}

func (a *app) oidc() (*tailnet.GitHubOIDC, bool) { return tailnet.GitHubOIDCFromEnv(a.getenv) }

func (a *app) client(c common) (*tailnet.Client, error) {
	cl := tailnet.New(c.apiBase, nil)
	if tok := a.getenv("TS_API_ACCESS_TOKEN"); tok != "" {
		cl.Org = tailnet.StaticToken(tok)
		return cl, nil
	}
	o, ok := a.oidc()
	if !ok {
		return nil, errors.New("no org credentials: set TS_API_ACCESS_TOKEN, or run in a GitHub Actions job with id-token: write")
	}
	cl.Org = cl.WIFToken(o, c.orgClientID, "")
	return cl, nil
}

// childToken returns a token source for a recorded tailnet, through the
// federated identity created inside it.
func (a *app) childToken(cl *tailnet.Client, e tailnet.StateEntry) (tailnet.TokenSource, error) {
	if e.FedClientID == "" {
		return nil, fmt.Errorf("no federated identity recorded for %s (%s)", e.DisplayName, e.ID)
	}
	o, ok := a.oidc()
	if !ok {
		return nil, errors.New("deleting needs a GitHub OIDC token (id-token: write)")
	}
	return cl.WIFToken(o, e.FedClientID, e.FedAudience), nil
}

func (c common) retry(sleep func(time.Duration)) tailnet.Retry {
	return tailnet.Retry{Attempts: c.attempts, Backoff: c.backoff, MaxWait: c.maxWait, Sleep: sleep}
}

// ---- cap check ----

type capLimits struct{ maxTotal, maxCI int }

func (a *app) capFlags(fs *flag.FlagSet, l *capLimits) {
	fs.IntVar(&l.maxTotal, "max-tailnets", 10, "organization tailnet cap, including the original tailnet")
	fs.IntVar(&l.maxCI, "max-ci", 4, "most tailnetlink-ci-* tailnets allowed at once")
}

// capError explains why creating need more tailnets would go over a limit.
func capError(all []tailnet.Tailnet, need int, l capLimits, now time.Time) error {
	var ci []string
	for _, t := range all {
		if _, _, _, ok := tailnet.ParseName(t.DisplayName); ok {
			ci = append(ci, fmt.Sprintf("%s (age %s)", t.DisplayName, now.Sub(t.CreatedAt).Round(time.Minute)))
		}
	}
	sort.Strings(ci)
	var reason string
	switch {
	case len(all)+need > l.maxTotal:
		reason = fmt.Sprintf("the organization has %d of %d tailnets and this run needs %d more", len(all), l.maxTotal, need)
	case len(ci)+need > l.maxCI:
		reason = fmt.Sprintf("%d CI tailnets already exist and this run needs %d more (limit %d)", len(ci), need, l.maxCI)
	default:
		return nil
	}
	list := "none"
	if len(ci) > 0 {
		list = strings.Join(ci, ", ")
	}
	return fmt.Errorf("tailnet cap reached: %s. Existing CI tailnets: %s. Run the e2e-janitor workflow (or `tailnetctl janitor`) to delete stale ones; anything without the %q prefix must be cleaned up by hand", reason, list, tailnet.Prefix)
}

func (a *app) checkCap(ctx context.Context, args []string) error {
	var c common
	var l capLimits
	var need int
	fs := a.flags("check-cap", &c)
	a.capFlags(fs, &l)
	fs.IntVar(&need, "need", 2, "tailnets about to be created")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cl, err := a.client(c)
	if err != nil {
		return err
	}
	all, err := cl.List(ctx)
	if err != nil {
		return err
	}
	if err := capError(all, need, l, a.now()); err != nil {
		return err
	}
	a.logf("cap ok: %d tailnets in the organization, room for %d more", len(all), need)
	return nil
}

// ---- create ----

type outputs struct {
	path string
}

func (o outputs) set(key, value string) error {
	if o.path == "" {
		return nil
	}
	f, err := os.OpenFile(o.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s=%s\n", key, value)
	return err
}

type claimFlag map[string]string

func (m claimFlag) String() string { return fmt.Sprint(map[string]string(m)) }
func (m claimFlag) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok || k == "" {
		return fmt.Errorf("want key=value, got %q", v)
	}
	m[k] = val
	return nil
}

func (a *app) create(ctx context.Context, args []string) error {
	var c common
	var l capLimits
	var runID, attempt, roles, statePath, ghOutput, subject, issuer string
	claims := claimFlag{}
	fs := a.flags("create", &c)
	a.capFlags(fs, &l)
	fs.StringVar(&runID, "run-id", "", "GitHub run ID (required)")
	fs.StringVar(&attempt, "attempt", "1", "GitHub run attempt")
	fs.StringVar(&roles, "roles", "src,dst", "comma-separated roles, one tailnet each")
	fs.StringVar(&statePath, "state-file", "tailnets.json", "where to record created tailnets (no secrets)")
	fs.StringVar(&ghOutput, "github-output", a.getenv("GITHUB_OUTPUT"), "file to append step outputs to")
	fs.StringVar(&issuer, "fed-issuer", "https://token.actions.githubusercontent.com", "issuer for the per-tailnet federated identity")
	fs.StringVar(&subject, "fed-subject", "repo:rajsinghtech/tailnetlink:*", "subject pattern for the per-tailnet federated identity")
	fs.Var(claims, "fed-claim", "custom claim rule key=pattern for the per-tailnet federated identity (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if runID == "" {
		return errors.New("--run-id is required")
	}
	roleList := strings.Split(roles, ",")
	cl, err := a.client(c)
	if err != nil {
		return err
	}
	all, err := cl.List(ctx)
	if err != nil {
		return err
	}
	if err := capError(all, len(roleList), l, a.now()); err != nil {
		return err
	}
	if c.dryRun {
		for _, r := range roleList {
			a.logf("dry run: would create %s", tailnet.Name(runID, attempt, r))
		}
		return nil
	}

	out := outputs{ghOutput}
	st, err := tailnet.LoadState(statePath)
	if err != nil {
		return err
	}
	type made struct {
		entry tailnet.StateEntry
		tok   tailnet.TokenSource // child OAuth, in memory only
	}
	var created []made
	rollback := func(cause error) error {
		// Use a fresh context: ctx may already be cancelled by SIGINT.
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
		defer cancel()
		var errs []error
		for _, m := range created {
			a.logf("rolling back: deleting %s (%s)", m.entry.DisplayName, m.entry.ID)
			if err := cl.DeleteAndVerify(rctx, m.tok, m.entry.ID, c.retry(a.sleep)); err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("%w; ROLLBACK FAILED, tailnets may be leaked: %w", cause, errors.Join(errs...))
		}
		return cause
	}

	for _, role := range roleList {
		if err := ctx.Err(); err != nil {
			return rollback(fmt.Errorf("cancelled: %w", err))
		}
		name := tailnet.Name(runID, attempt, role)
		tn, err := cl.Create(ctx, name)
		if err != nil {
			return rollback(err)
		}
		e := tailnet.StateEntry{RunID: runID, Attempt: attempt, Role: role, ID: tn.ID, DisplayName: tn.DisplayName, DNSName: tn.DNSName}
		if e.DisplayName == "" {
			e.DisplayName = name
		}
		tok := cl.OAuthToken(tn.OAuthClientID, tn.OAuthClientSecret)
		created = append(created, made{e, tok})
		// Record the ID before doing anything else, so cleanup can find it
		// even if this process dies on the next line.
		st.Upsert(e)
		if err := st.Save(statePath); err != nil {
			return rollback(err)
		}
		if err := out.set(role+"_id", e.ID); err != nil {
			return rollback(err)
		}
		a.logf("created %s (%s)", e.DisplayName, e.ID)

		if err := cl.ApplyPolicy(ctx, tok, e.ID, tailnet.Policy); err != nil {
			return rollback(err)
		}
		fedID, aud, err := cl.CreateFederatedIdentity(ctx, tok, e.ID, tailnet.FederatedIdentity{
			Description:      "tailnetlink ci " + runID,
			Scopes:           []string{"all"},
			Issuer:           issuer,
			Subject:          subject,
			CustomClaimRules: claims,
		})
		if err != nil {
			return rollback(err)
		}
		e.FedClientID, e.FedAudience = fedID, aud
		created[len(created)-1].entry = e
		st.Upsert(e)
		if err := st.Save(statePath); err != nil {
			return rollback(err)
		}
		for k, v := range map[string]string{"_dns_name": e.DNSName, "_fed_client_id": fedID, "_fed_audience": aud} {
			if err := out.set(role+k, v); err != nil {
				return rollback(err)
			}
		}
	}
	return nil
}

// ---- delete and janitor ----

type target struct {
	id, name string
	entry    tailnet.StateEntry
	known    bool
}

// deleteTargets deletes each target, verifying and retrying, and returns an
// error naming every tailnet that is still there.
func (a *app) deleteTargets(ctx context.Context, cl *tailnet.Client, c common, targets []target) error {
	if len(targets) == 0 {
		a.logf("nothing to delete")
		return nil
	}
	var failed []string
	for _, t := range targets {
		if c.dryRun {
			a.logf("dry run: would delete %s (%s)", t.name, t.id)
			continue
		}
		if !t.known {
			a.logf("ERROR: %s (%s) has no recorded federated identity, so CI cannot get a token to delete it; delete it by hand", t.name, t.id)
			failed = append(failed, t.name)
			continue
		}
		tok, err := a.childToken(cl, t.entry)
		if err == nil {
			err = cl.DeleteAndVerify(ctx, tok, t.id, c.retry(a.sleep))
		}
		if err != nil {
			a.logf("ERROR: %s: %v", t.name, err)
			failed = append(failed, t.name)
			continue
		}
		a.logf("deleted %s (%s), confirmed gone", t.name, t.id)
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d tailnet(s) NOT deleted: %s", len(failed), strings.Join(failed, ", "))
	}
	return nil
}

// collect matches listed tailnets against keep and attaches state entries.
// Recorded entries that are no longer listed are already gone and skipped.
// State entries still present by ID are included even when ParseName rejects
// the display name (roles like dst2 used to fail the old [a-z]+ pattern).
func collect(all []tailnet.Tailnet, st *tailnet.State, keep func(t tailnet.Tailnet, runID, attempt string) bool) []target {
	byID := make(map[string]tailnet.Tailnet, len(all))
	for _, t := range all {
		byID[t.ID] = t
	}
	var out []target
	seen := make(map[string]bool)
	for _, t := range all {
		runID, attempt, _, ok := tailnet.ParseName(t.DisplayName)
		if !ok || !keep(t, runID, attempt) {
			continue
		}
		e, known := st.Lookup(t.ID, t.DisplayName)
		if known {
			e.ID = t.ID
		}
		out = append(out, target{id: t.ID, name: t.DisplayName, entry: e, known: known})
		seen[t.ID] = true
	}
	for _, e := range st.Tailnets {
		if seen[e.ID] {
			continue
		}
		t, ok := byID[e.ID]
		if !ok || !keep(t, e.RunID, e.Attempt) {
			continue
		}
		e.ID = t.ID
		name := t.DisplayName
		if name == "" {
			name = e.DisplayName
		}
		out = append(out, target{id: t.ID, name: name, entry: e, known: true})
		seen[t.ID] = true
	}
	return out
}

func (a *app) deleteRun(ctx context.Context, args []string) error {
	var c common
	var runID, attempt, statePath, stateDir string
	fs := a.flags("delete", &c)
	fs.StringVar(&runID, "run-id", "", "GitHub run ID whose tailnets to delete (required)")
	fs.StringVar(&attempt, "attempt", "", "only this attempt (default: all attempts)")
	fs.StringVar(&statePath, "state-file", "", "state file written by create")
	fs.StringVar(&stateDir, "state-dir", "", "directory of state files (downloaded artifacts)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if runID == "" {
		return errors.New("--run-id is required")
	}
	st, err := loadStates(statePath, stateDir)
	if err != nil {
		return err
	}
	cl, err := a.client(c)
	if err != nil {
		return err
	}
	// Look tailnets up by name as well as by the recorded IDs, so a create
	// step that died before writing outputs still gets cleaned up.
	all, err := cl.List(ctx)
	if err != nil {
		return err
	}
	targets := collect(all, st, func(_ tailnet.Tailnet, r, at string) bool {
		return r == runID && (attempt == "" || at == attempt)
	})
	return a.deleteTargets(ctx, cl, c, targets)
}

func (a *app) janitor(ctx context.Context, args []string) error {
	var c common
	var olderThan time.Duration
	var stateDir string
	fs := a.flags("janitor", &c)
	fs.DurationVar(&olderThan, "older-than", 2*time.Hour, "delete CI tailnets created longer ago than this")
	fs.StringVar(&stateDir, "state-dir", "", "directory of state files (downloaded artifacts)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if olderThan < 30*time.Minute {
		return errors.New("--older-than must be at least 30m so a running job's tailnets are never deleted")
	}
	st, err := tailnet.LoadStateDir(stateDir)
	if err != nil {
		return err
	}
	cl, err := a.client(c)
	if err != nil {
		return err
	}
	all, err := cl.List(ctx)
	if err != nil {
		return err
	}
	cutoff := a.now().Add(-olderThan)
	targets := collect(all, st, func(t tailnet.Tailnet, _, _ string) bool {
		return !t.CreatedAt.IsZero() && t.CreatedAt.Before(cutoff)
	})
	a.logf("janitor: %d tailnets listed, %d CI tailnets older than %s", len(all), len(targets), olderThan)
	return a.deleteTargets(ctx, cl, c, targets)
}

func loadStates(file, dir string) (*tailnet.State, error) {
	st, err := tailnet.LoadStateDir(dir)
	if err != nil {
		return nil, err
	}
	if file != "" {
		f, err := tailnet.LoadState(file)
		if err != nil {
			return nil, err
		}
		for _, e := range f.Tailnets {
			st.Upsert(e)
		}
	}
	return st, nil
}

// ---- token ----

func (a *app) token(ctx context.Context, args []string) error {
	var c common
	var clientID, audience string
	fs := a.flags("token", &c)
	fs.StringVar(&clientID, "client-id", "", "federated identity client ID (default: the org identity)")
	fs.StringVar(&audience, "audience", "", "audience (default api.tailscale.com/<client-id>)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if clientID == "" {
		clientID = c.orgClientID
	}
	o, ok := a.oidc()
	if !ok {
		return errors.New("needs a GitHub OIDC token (id-token: write)")
	}
	cl := tailnet.New(c.apiBase, nil)
	tok, err := cl.WIFToken(o, clientID, audience)(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintln(a.out, tok)
	return nil
}
