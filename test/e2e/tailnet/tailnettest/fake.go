// Package tailnettest is an in-memory fake of the parts of the Tailscale
// organization API that the tailnet package and tailnetctl use, plus a fake
// GitHub OIDC endpoint. It never talks to the real API.
package tailnettest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// OrgToken is the bearer the fake accepts for org-level calls.
const OrgToken = "org-token"

// Call is one recorded request.
type Call struct{ Method, Path, Auth string }

// Tailnet is a tailnet held by the fake.
type Tailnet struct {
	ID, DisplayName, DNSName string
	CreatedAt                time.Time
	OAuthClientID            string // the one-time child client from create
	OAuthSecret              string
	FedClientIDs             []string
	Policy                   string
}

// Fake is the fake API server.
type Fake struct {
	Server *httptest.Server

	mu       sync.Mutex
	tailnets []*Tailnet
	calls    []Call
	next     int
	Now      func() time.Time

	// Failure knobs.
	FailCreate       bool // create returns 500
	FailPolicy       bool // policy POST returns 500
	FailFederated    bool // federated identity create returns 500
	FailDeletes      int  // the next N deletes return 500
	SilentDeletes    int  // the next N deletes return 200 but keep the tailnet
	ForbidAllDeletes bool // every delete returns 403
	PageSize         int  // list page size, default 100
}

// New starts a fake. Close it with t.Cleanup automatically.
func New(t testing.TB) *Fake {
	f := &Fake{Now: time.Now}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Server.Close)
	return f
}

// URL is the fake's base URL (use as APIBase).
func (f *Fake) URL() string { return f.Server.URL }

// Add puts an existing tailnet in the fake (for example the org's own
// tailnet, or a leftover from an earlier run) and returns it.
func (f *Fake) Add(displayName string, createdAt time.Time) *Tailnet {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addLocked(displayName, createdAt)
}

func (f *Fake) addLocked(displayName string, createdAt time.Time) *Tailnet {
	f.next++
	tn := &Tailnet{
		ID:            fmt.Sprintf("T%dCNTRL", f.next),
		DisplayName:   displayName,
		DNSName:       fmt.Sprintf("tail%d.ts.net", f.next),
		CreatedAt:     createdAt,
		OAuthClientID: fmt.Sprintf("kchild%d", f.next),
		OAuthSecret:   fmt.Sprintf("tskey-client-child%d-secret", f.next),
	}
	f.tailnets = append(f.tailnets, tn)
	return tn
}

// AddFed registers a federated identity in tn and returns its client ID.
func (f *Fake) AddFed(tn *Tailnet) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := fmt.Sprintf("fed-%s-%d", tn.ID, len(tn.FedClientIDs)+1)
	tn.FedClientIDs = append(tn.FedClientIDs, id)
	return id
}

// Tailnets returns the display names currently held.
func (f *Fake) Tailnets() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, tn := range f.tailnets {
		out = append(out, tn.DisplayName)
	}
	return out
}

// Get returns the tailnet with displayName, or nil.
func (f *Fake) Get(displayName string) *Tailnet {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, tn := range f.tailnets {
		if tn.DisplayName == displayName {
			return tn
		}
	}
	return nil
}

// Calls returns the recorded requests.
func (f *Fake) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Call(nil), f.calls...)
}

// CountCalls counts recorded requests with method and a path prefix.
func (f *Fake) CountCalls(method, pathPrefix string) int {
	n := 0
	for _, c := range f.Calls() {
		if c.Method == method && strings.HasPrefix(c.Path, pathPrefix) {
			n++
		}
	}
	return n
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.calls = append(f.calls, Call{r.Method, r.URL.Path, auth})
	p := r.URL.Path

	switch {
	case p == "/oidc":
		f.serveOIDC(w, r)
	case p == "/api/v2/oauth/token":
		_ = r.ParseForm()
		for _, tn := range f.tailnets {
			if tn.OAuthClientID == r.PostFormValue("client_id") && tn.OAuthSecret == r.PostFormValue("client_secret") {
				writeJSON(w, map[string]any{"access_token": "child:" + tn.ID, "expires_in": 3600})
				return
			}
		}
		http.Error(w, `{"message":"bad client"}`, http.StatusUnauthorized)
	case p == "/api/v2/oauth/token-exchange":
		_ = r.ParseForm()
		cid, jwt := r.PostFormValue("client_id"), r.PostFormValue("jwt")
		if jwt != "jwt-for-api.tailscale.com/"+cid {
			http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if cid == "org-fed" {
			writeJSON(w, map[string]any{"access_token": OrgToken})
			return
		}
		for _, tn := range f.tailnets {
			for _, id := range tn.FedClientIDs {
				if id == cid {
					writeJSON(w, map[string]any{"access_token": "child:" + tn.ID})
					return
				}
			}
		}
		http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
	case p == "/api/v2/organizations/-/tailnets":
		if auth != OrgToken {
			http.Error(w, `{"message":"forbidden"}`, http.StatusForbidden)
			return
		}
		if r.Method == http.MethodGet {
			f.serveList(w, r)
			return
		}
		f.serveCreate(w, r)
	case strings.HasPrefix(p, "/api/v2/tailnet/"):
		rest := strings.TrimPrefix(p, "/api/v2/tailnet/")
		id, sub, _ := strings.Cut(rest, "/")
		tn := f.byIDLocked(id)
		if tn == nil {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		if auth != "child:"+tn.ID {
			// The org token is not a member of child tailnets.
			http.Error(w, `{"message":"not a member"}`, http.StatusForbidden)
			return
		}
		switch {
		case sub == "" && r.Method == http.MethodDelete:
			f.serveDelete(w, tn)
		case sub == "acl" && r.Method == http.MethodPost:
			if f.FailPolicy {
				http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
				return
			}
			b, _ := io.ReadAll(r.Body)
			tn.Policy = string(b)
			writeJSON(w, map[string]any{})
		case sub == "keys" && r.Method == http.MethodPost:
			f.serveKeys(w, r, tn)
		default:
			http.NotFound(w, r)
		}
	default:
		http.NotFound(w, r)
	}
}

func (f *Fake) serveOIDC(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "bearer gh-request-token" {
		http.Error(w, "no", http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]string{"value": "jwt-for-" + r.URL.Query().Get("audience")})
}

func (f *Fake) serveList(w http.ResponseWriter, r *http.Request) {
	size := f.PageSize
	if size <= 0 {
		size = 100
	}
	start := 0
	if c := r.URL.Query().Get("cursor"); c != "" {
		_, _ = fmt.Sscanf(c, "%d", &start)
	}
	end := min(start+size, len(f.tailnets))
	var items []map[string]any
	for _, tn := range f.tailnets[start:end] {
		items = append(items, map[string]any{
			"id": tn.ID, "displayName": tn.DisplayName, "orgId": "o1CNTRL",
			"createdAt": tn.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	out := map[string]any{"tailnets": items, "totalCount": len(f.tailnets)}
	if end < len(f.tailnets) {
		out["cursor"] = fmt.Sprint(end)
	}
	writeJSON(w, out)
}

func (f *Fake) serveCreate(w http.ResponseWriter, r *http.Request) {
	if f.FailCreate {
		http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
		return
	}
	var req struct {
		DisplayName string `json:"displayName"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	for _, tn := range f.tailnets {
		if tn.DisplayName == req.DisplayName {
			writeJSON(w, map[string]any{"id": tn.ID, "displayName": tn.DisplayName, "alreadyExists": true})
			return
		}
	}
	tn := f.addLocked(req.DisplayName, f.Now())
	writeJSON(w, map[string]any{
		"id": tn.ID, "displayName": tn.DisplayName, "dnsName": tn.DNSName,
		"orgId": "o1CNTRL", "createdAt": tn.CreatedAt.UTC().Format(time.RFC3339),
		"oauthClient": map[string]string{"id": tn.OAuthClientID, "secret": tn.OAuthSecret},
	})
}

func (f *Fake) serveDelete(w http.ResponseWriter, tn *Tailnet) {
	switch {
	case f.ForbidAllDeletes:
		http.Error(w, `{"message":"forbidden"}`, http.StatusForbidden)
		return
	case f.FailDeletes > 0:
		f.FailDeletes--
		http.Error(w, `{"message":"try again"}`, http.StatusInternalServerError)
		return
	case f.SilentDeletes > 0:
		f.SilentDeletes--
		writeJSON(w, map[string]any{})
		return
	}
	for i, x := range f.tailnets {
		if x == tn {
			f.tailnets = append(f.tailnets[:i], f.tailnets[i+1:]...)
			break
		}
	}
	writeJSON(w, map[string]any{})
}

func (f *Fake) serveKeys(w http.ResponseWriter, r *http.Request, tn *Tailnet) {
	var req struct {
		KeyType string `json:"keyType"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	switch req.KeyType {
	case "federated":
		if f.FailFederated {
			http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
			return
		}
		id := fmt.Sprintf("fed-%s-%d", tn.ID, len(tn.FedClientIDs)+1)
		tn.FedClientIDs = append(tn.FedClientIDs, id)
		writeJSON(w, map[string]any{"id": id, "keyType": "federated", "audience": "api.tailscale.com/" + id})
	case "client":
		writeJSON(w, map[string]any{"id": "kclient-" + tn.ID, "key": "tskey-client-" + tn.ID + "-x"})
	default:
		writeJSON(w, map[string]any{"id": "kauth", "key": "tskey-auth-" + tn.ID})
	}
}

func (f *Fake) byIDLocked(id string) *Tailnet {
	for _, tn := range f.tailnets {
		if tn.ID == id {
			return tn
		}
	}
	return nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
