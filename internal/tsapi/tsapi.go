// Package tsapi builds Tailscale admin API clients from tailnet config.
package tsapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	tsclient "tailscale.com/client/tailscale/v2"
)

// NewClient returns an admin API client for tc. A client secret or an OIDC
// JWT is read from its file or environment variable each time a new API
// token is needed, never held in the config. The JWT itself is not cached.
// rt, when not nil, carries every request, token requests included;
// tailnetlink uses it to count API errors.
func NewClient(tc config.TailnetConfig, rt http.RoundTripper) *tsclient.Client {
	tailnet := tc.Tailnet
	if tailnet == "" {
		tailnet = "-"
	}
	c := &tsclient.Client{Tailnet: tailnet, Auth: &oauth{creds: tc.OAuth, rt: rt}}
	if rt != nil {
		c.HTTP = &http.Client{Transport: rt, Timeout: time.Minute}
	}
	if tc.APIBaseURL != "" {
		if u, err := url.Parse(tc.APIBaseURL); err == nil {
			c.BaseURL = u
		}
	}
	return c
}

// oauth is a tsclient.Auth like tsclient.OAuth, except that it reads the
// secret or JWT at token time. Workload identity posts the JWT to
// /api/v2/oauth/token-exchange (client_id and jwt, form-encoded). The
// tailscale client can do that exchange, but it caches the JWT until the
// JWT itself expires, so this type reads the file on every exchange instead.
type oauth struct {
	creds config.OAuthCreds
	rt    http.RoundTripper
}

func (o *oauth) HTTPClient(orig *http.Client, baseURL string) *http.Client {
	if o.creds.UsesIDToken() {
		src := &cachedToken{fetch: func() (*oauth2.Token, error) {
			return exchangeToken(o.creds, baseURL+"/api/v2/oauth/token-exchange", o.rt)
		}}
		return &http.Client{
			Transport:     &retry401{base: orig.Transport, src: src},
			CheckRedirect: orig.CheckRedirect,
			Jar:           orig.Jar,
			Timeout:       orig.Timeout,
		}
	}
	src := &tokenSource{creds: o.creds, tokenURL: baseURL + "/api/v2/oauth/token", rt: o.rt}
	return &http.Client{
		Transport: &oauth2.Transport{
			Base:   orig.Transport,
			Source: oauth2.ReuseTokenSource(nil, src),
		},
		CheckRedirect: orig.CheckRedirect,
		Jar:           orig.Jar,
		Timeout:       orig.Timeout,
	}
}

// cachedToken keeps the API access token until it expires. The JWT used to
// mint it is not kept.
type cachedToken struct {
	mu    sync.Mutex
	tok   *oauth2.Token
	fetch func() (*oauth2.Token, error)
}

func (c *cachedToken) Token() (*oauth2.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tok.Valid() {
		return c.tok, nil
	}
	tok, err := c.fetch()
	if err != nil {
		return nil, err
	}
	c.tok = tok
	return tok, nil
}

func (c *cachedToken) reset() {
	c.mu.Lock()
	c.tok = nil
	c.mu.Unlock()
}

// retry401 sends the request with a bearer token and, on one 401, drops the
// cached API token, exchanges again (reading the JWT file again) and retries.
type retry401 struct {
	base http.RoundTripper
	src  *cachedToken
}

func (t *retry401) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.roundTrip(req, false)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	drain(resp)
	t.src.reset()
	return t.roundTrip(req, true)
}

func (t *retry401) roundTrip(req *http.Request, replay bool) (*http.Response, error) {
	tok, err := t.src.Token()
	if err != nil {
		return nil, err
	}
	r2, err := cloneReq(req, replay)
	if err != nil {
		return nil, err
	}
	tok.SetAuthHeader(r2)
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r2)
}

func cloneReq(req *http.Request, replay bool) (*http.Request, error) {
	r2 := req.Clone(req.Context())
	if req.Body == nil || req.Body == http.NoBody {
		return r2, nil
	}
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		r2.Body = body
		return r2, nil
	}
	if replay {
		return nil, errors.New("oauth: cannot retry a request whose body cannot be replayed")
	}
	return r2, nil
}

func drain(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
}

// exchangeToken trades the current OIDC JWT for an API access token. The JWT
// is a local variable and is not stored.
func exchangeToken(creds config.OAuthCreds, tokenURL string, rt http.RoundTripper) (*oauth2.Token, error) {
	jwt, err := creds.IDToken()
	if err != nil {
		return nil, err
	}
	form := url.Values{"client_id": {creds.ClientID}, "jwt": {jwt}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Transport: rt, Timeout: time.Minute}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 512 {
			msg = msg[:512]
		}
		return nil, fmt.Errorf("token exchange: HTTP %d: %s", resp.StatusCode, msg)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	if out.AccessToken == "" {
		return nil, errors.New("token exchange: empty access_token")
	}
	expiry := time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	if out.ExpiresIn <= 0 {
		// A zero expiry would otherwise be treated as "never expires".
		expiry = time.Now()
	}
	return &oauth2.Token{AccessToken: out.AccessToken, TokenType: out.TokenType, Expiry: expiry}, nil
}

type tokenSource struct {
	creds    config.OAuthCreds
	tokenURL string
	rt       http.RoundTripper
}

func (s *tokenSource) Token() (*oauth2.Token, error) {
	secret, err := s.creds.Secret()
	if err != nil {
		return nil, err
	}
	cc := clientcredentials.Config{ClientID: s.creds.ClientID, ClientSecret: secret, TokenURL: s.tokenURL}
	ctx := context.Background()
	if s.rt != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Transport: s.rt, Timeout: time.Minute})
	}
	return cc.Token(ctx)
}
