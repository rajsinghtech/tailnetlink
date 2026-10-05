package tailnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// AudienceFor is the audience Tailscale generates for a federated identity.
func AudienceFor(clientID string) string { return "api.tailscale.com/" + clientID }

// GitHubOIDC fetches GitHub Actions OIDC tokens. It only works in a job with
// `permissions: id-token: write`, where the runner sets the two variables.
type GitHubOIDC struct {
	RequestURL   string // ACTIONS_ID_TOKEN_REQUEST_URL
	RequestToken string // ACTIONS_ID_TOKEN_REQUEST_TOKEN
	HTTP         *http.Client
}

// GitHubOIDCFromEnv returns a GitHubOIDC if the runner provides one.
func GitHubOIDCFromEnv(getenv func(string) string) (*GitHubOIDC, bool) {
	u, t := getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if u == "" || t == "" {
		return nil, false
	}
	return &GitHubOIDC{RequestURL: u, RequestToken: t, HTTP: http.DefaultClient}, true
}

// JWT returns a fresh OIDC token for audience. GitHub's tokens live about
// five minutes, so callers fetch a new one for every exchange.
func (g *GitHubOIDC) JWT(ctx context.Context, audience string) (string, error) {
	sep := "&"
	if !strings.Contains(g.RequestURL, "?") {
		sep = "?"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.RequestURL+sep+"audience="+url.QueryEscape(audience), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "bearer "+g.RequestToken)
	hc := g.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("github oidc: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github oidc: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(b, &out); err != nil || out.Value == "" {
		return "", errors.New("github oidc: no token in response")
	}
	return out.Value, nil
}

// WIFToken returns a TokenSource that fetches a fresh GitHub OIDC token for
// the federated identity's audience and exchanges it on every call.
func (c *Client) WIFToken(oidc *GitHubOIDC, clientID, audience string) TokenSource {
	if audience == "" {
		audience = AudienceFor(clientID)
	}
	return func(ctx context.Context) (string, error) {
		jwt, err := oidc.JWT(ctx, audience)
		if err != nil {
			return "", err
		}
		return c.Exchange(ctx, clientID, jwt)
	}
}
