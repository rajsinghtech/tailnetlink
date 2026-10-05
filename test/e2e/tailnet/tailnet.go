// Package tailnet creates, lists and deletes throwaway tailnets through the
// Tailscale organization API, for the real-tailnet e2e tests and the CI
// cleanup tooling.
//
// Adapted from rajsinghtech/tailgate (internal/tailnet), which verified this
// recipe against the live API:
//
//	create: POST   /api/v2/organizations/-/tailnets   (org token)
//	        -> {id, dnsName, oauthClient{id, secret}}  (one-time, all-scope child client)
//	policy: POST   /api/v2/tailnet/<id>/acl            (child token)
//	keys:   POST   /api/v2/tailnet/<id>/keys           (child token)
//	delete: DELETE /api/v2/tailnet/<id>                (child token)
//
// The org token can create and list tailnets but cannot delete one. Deletion
// needs a token for the child tailnet itself, so whoever creates a tailnet
// must keep a way to get a child token until it is gone. In CI that is a
// federated identity created inside each child right after creation, so no
// secret ever has to leave the process that created it.
package tailnet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultAPIBase is the public Tailscale API host.
const DefaultAPIBase = "https://api.tailscale.com"

// TokenSource returns a bearer token for one API call.
type TokenSource func(ctx context.Context) (string, error)

// StaticToken returns a TokenSource that always returns tok.
func StaticToken(tok string) TokenSource {
	return func(context.Context) (string, error) {
		if tok == "" {
			return "", errors.New("empty token")
		}
		return tok, nil
	}
}

// Client talks to the organization API. Org is used for create and list.
type Client struct {
	APIBase string
	HTTP    *http.Client
	Org     TokenSource
}

// New returns a Client for apiBase (DefaultAPIBase if empty).
func New(apiBase string, org TokenSource) *Client {
	if apiBase == "" {
		apiBase = DefaultAPIBase
	}
	return &Client{
		APIBase: strings.TrimRight(apiBase, "/"),
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		Org:     org,
	}
}

// Tailnet is one entry from the organization's tailnet list.
type Tailnet struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"displayName"`
	OrgID       string    `json:"orgId,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
}

// Created is a freshly created tailnet plus its one-time child OAuth client.
// The secret must never be logged, written to disk or passed between jobs.
type Created struct {
	ID                string
	DisplayName       string
	DNSName           string
	OAuthClientID     string
	OAuthClientSecret string
}

// HTTPError is a non-2xx API response.
type HTTPError struct {
	Method, Path string
	Status       int
	Body         string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.Path, e.Status, e.Body)
}

// IsNotFound reports whether err is an HTTP 404 from the API.
func IsNotFound(err error) bool {
	var he *HTTPError
	return errors.As(err, &he) && he.Status == http.StatusNotFound
}

// List returns every tailnet in the organization, following the cursor.
func (c *Client) List(ctx context.Context) ([]Tailnet, error) {
	var all []Tailnet
	cursor := ""
	for page := 0; page < 100; page++ {
		u := c.APIBase + "/api/v2/organizations/-/tailnets?limit=100"
		if cursor != "" {
			u += "&cursor=" + url.QueryEscape(cursor)
		}
		var out struct {
			Tailnets []Tailnet `json:"tailnets"`
			Cursor   string    `json:"cursor"`
		}
		if err := c.call(ctx, c.Org, http.MethodGet, u, nil, "", &out); err != nil {
			return nil, fmt.Errorf("list tailnets: %w", err)
		}
		all = append(all, out.Tailnets...)
		if out.Cursor == "" || len(out.Tailnets) == 0 {
			return all, nil
		}
		cursor = out.Cursor
	}
	return nil, errors.New("list tailnets: too many pages")
}

// Create makes a new API-only tailnet named name.
func (c *Client) Create(ctx context.Context, name string) (*Created, error) {
	if !validDisplayName(name) {
		return nil, fmt.Errorf("create tailnet: invalid display name %q", name)
	}
	body, _ := json.Marshal(map[string]string{"displayName": name})
	var out struct {
		ID            string `json:"id"`
		DisplayName   string `json:"displayName"`
		DNSName       string `json:"dnsName"`
		AlreadyExists bool   `json:"alreadyExists"`
		OAuthClient   struct {
			ID     string `json:"id"`
			Secret string `json:"secret"`
		} `json:"oauthClient"`
	}
	if err := c.call(ctx, c.Org, http.MethodPost, c.APIBase+"/api/v2/organizations/-/tailnets", body, "application/json", &out); err != nil {
		return nil, fmt.Errorf("create tailnet %q: %w", name, err)
	}
	if out.AlreadyExists {
		return nil, fmt.Errorf("create tailnet %q: a tailnet with this name already exists (id %s); refusing to reuse it", name, out.ID)
	}
	if out.ID == "" || out.OAuthClient.ID == "" || out.OAuthClient.Secret == "" {
		return nil, fmt.Errorf("create tailnet %q: response is missing id or oauthClient", name)
	}
	return &Created{
		ID: out.ID, DisplayName: out.DisplayName, DNSName: out.DNSName,
		OAuthClientID: out.OAuthClient.ID, OAuthClientSecret: out.OAuthClient.Secret,
	}, nil
}

// Delete deletes tailnet id using a token for that tailnet. A 404 counts as
// already deleted.
func (c *Client) Delete(ctx context.Context, child TokenSource, id string) error {
	err := c.call(ctx, child, http.MethodDelete, c.APIBase+"/api/v2/tailnet/"+url.PathEscape(id), nil, "", nil)
	if err != nil && !IsNotFound(err) {
		return fmt.Errorf("delete tailnet %s: %w", id, err)
	}
	return nil
}

// Exists reports whether tailnet id is still in the organization's list.
func (c *Client) Exists(ctx context.Context, id string) (bool, error) {
	all, err := c.List(ctx)
	if err != nil {
		return false, err
	}
	for _, t := range all {
		if t.ID == id {
			return true, nil
		}
	}
	return false, nil
}

// Retry controls DeleteAndVerify.
type Retry struct {
	Attempts int                 // total delete attempts, default 5
	Backoff  time.Duration       // first wait, doubled each time, default 2s
	Sleep    func(time.Duration) // default time.Sleep
}

// DeleteAndVerify deletes tailnet id, then confirms with a list call that it
// is gone. It retries the whole sequence with exponential backoff and returns
// an error if the tailnet is still listed after the last attempt.
func (c *Client) DeleteAndVerify(ctx context.Context, child TokenSource, id string, r Retry) error {
	if r.Attempts <= 0 {
		r.Attempts = 5
	}
	if r.Backoff <= 0 {
		r.Backoff = 2 * time.Second
	}
	if r.Sleep == nil {
		r.Sleep = time.Sleep
	}
	var last error
	wait := r.Backoff
	for i := 0; i < r.Attempts; i++ {
		if i > 0 {
			r.Sleep(wait)
			wait *= 2
		}
		if err := c.Delete(ctx, child, id); err != nil {
			last = err
			continue
		}
		exists, err := c.Exists(ctx, id)
		if err != nil {
			last = fmt.Errorf("verify delete of %s: %w", id, err)
			continue
		}
		if !exists {
			return nil
		}
		last = fmt.Errorf("tailnet %s is still listed after delete", id)
	}
	return fmt.Errorf("tailnet %s not deleted after %d attempts: %w", id, r.Attempts, last)
}

// ApplyPolicy replaces the tailnet policy file of tailnet id.
func (c *Client) ApplyPolicy(ctx context.Context, child TokenSource, id string, policy []byte) error {
	if err := c.call(ctx, child, http.MethodPost, c.tailnetURL(id, "acl"), policy, "application/hujson", nil); err != nil {
		return fmt.Errorf("apply policy to %s: %w", id, err)
	}
	return nil
}

// FederatedIdentity is a trust credential that lets an OIDC workload (a
// GitHub Actions job) get a token for the tailnet it lives in.
type FederatedIdentity struct {
	Description      string            `json:"description,omitempty"`
	Scopes           []string          `json:"scopes"`
	Tags             []string          `json:"tags,omitempty"`
	Issuer           string            `json:"issuer"`
	Subject          string            `json:"subject"`
	CustomClaimRules map[string]string `json:"customClaimRules,omitempty"`
}

// CreateFederatedIdentity creates fi in tailnet id and returns its client ID
// and audience. Neither is secret.
func (c *Client) CreateFederatedIdentity(ctx context.Context, child TokenSource, id string, fi FederatedIdentity) (clientID, audience string, err error) {
	req := struct {
		KeyType string `json:"keyType"`
		FederatedIdentity
	}{"federated", fi}
	body, _ := json.Marshal(req)
	var out struct {
		ID       string `json:"id"`
		Audience string `json:"audience"`
	}
	if err := c.call(ctx, child, http.MethodPost, c.tailnetURL(id, "keys"), body, "application/json", &out); err != nil {
		return "", "", fmt.Errorf("create federated identity in %s: %w", id, err)
	}
	if out.ID == "" {
		return "", "", fmt.Errorf("create federated identity in %s: empty id", id)
	}
	if out.Audience == "" {
		out.Audience = AudienceFor(out.ID)
	}
	return out.ID, out.Audience, nil
}

// CreateOAuthClient creates an OAuth client in tailnet id with the given
// scopes and tags. The secret must stay in memory.
func (c *Client) CreateOAuthClient(ctx context.Context, child TokenSource, id, description string, scopes, tags []string) (clientID, secret string, err error) {
	body, _ := json.Marshal(map[string]any{
		"keyType": "client", "description": description, "scopes": scopes, "tags": tags,
	})
	var out struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	if err := c.call(ctx, child, http.MethodPost, c.tailnetURL(id, "keys"), body, "application/json", &out); err != nil {
		return "", "", fmt.Errorf("create oauth client in %s: %w", id, err)
	}
	if out.ID == "" || out.Key == "" {
		return "", "", fmt.Errorf("create oauth client in %s: empty id or secret", id)
	}
	return out.ID, out.Key, nil
}

// CreateAuthKey mints a single-use, ephemeral, pre-authorized auth key with
// tags, valid for one hour.
func (c *Client) CreateAuthKey(ctx context.Context, child TokenSource, id string, tags []string) (string, error) {
	var req struct {
		Capabilities struct {
			Devices struct {
				Create struct {
					Reusable      bool     `json:"reusable"`
					Ephemeral     bool     `json:"ephemeral"`
					Preauthorized bool     `json:"preauthorized"`
					Tags          []string `json:"tags"`
				} `json:"create"`
			} `json:"devices"`
		} `json:"capabilities"`
		ExpirySeconds int `json:"expirySeconds"`
	}
	req.Capabilities.Devices.Create.Ephemeral = true
	req.Capabilities.Devices.Create.Preauthorized = true
	req.Capabilities.Devices.Create.Tags = tags
	req.ExpirySeconds = 3600
	body, _ := json.Marshal(req)
	var out struct {
		Key string `json:"key"`
	}
	if err := c.call(ctx, child, http.MethodPost, c.tailnetURL(id, "keys"), body, "application/json", &out); err != nil {
		return "", fmt.Errorf("create auth key in %s: %w", id, err)
	}
	if out.Key == "" {
		return "", fmt.Errorf("create auth key in %s: empty key", id)
	}
	return out.Key, nil
}

// OAuthToken returns a TokenSource that trades an OAuth client ID and secret
// for an access token on every call.
func (c *Client) OAuthToken(clientID, secret string) TokenSource {
	return func(ctx context.Context) (string, error) {
		form := url.Values{"client_id": {clientID}, "client_secret": {secret}}
		return c.tokenRequest(ctx, "/api/v2/oauth/token", form)
	}
}

// Exchange trades an OIDC JWT for an access token through the federated
// identity clientID (workload identity federation).
func (c *Client) Exchange(ctx context.Context, clientID, jwt string) (string, error) {
	form := url.Values{"client_id": {clientID}, "jwt": {jwt}}
	return c.tokenRequest(ctx, "/api/v2/oauth/token-exchange", form)
}

func (c *Client) tokenRequest(ctx context.Context, path string, form url.Values) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.APIBase+path, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := c.do(req, &out); err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	if out.AccessToken == "" {
		return "", errors.New("token request: empty access_token")
	}
	return out.AccessToken, nil
}

func (c *Client) tailnetURL(id, rest string) string {
	return c.APIBase + "/api/v2/tailnet/" + url.PathEscape(id) + "/" + rest
}

func (c *Client) call(ctx context.Context, ts TokenSource, method, u string, body []byte, ctype string, out any) error {
	if ts == nil {
		return errors.New("no token source")
	}
	tok, err := ts(ctx)
	if err != nil {
		return fmt.Errorf("get token: %w", err)
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	return c.do(req, out)
}

// do sends req and decodes a 2xx JSON body into out. Response bodies on
// error are truncated and never contain request credentials.
func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(b))
		if len(msg) > 300 {
			msg = msg[:300] + "..."
		}
		return &HTTPError{Method: req.Method, Path: req.URL.Path, Status: resp.StatusCode, Body: msg}
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("decode %s: %w", req.URL.Path, err)
		}
	}
	return nil
}

func validDisplayName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == ' ', r == '-', r == '\'':
		default:
			return false
		}
	}
	return true
}
