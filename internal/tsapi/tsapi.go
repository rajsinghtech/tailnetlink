// Package tsapi builds Tailscale admin API clients from tailnet config.
package tsapi

import (
	"context"
	"net/http"
	"net/url"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	tsclient "tailscale.com/client/tailscale/v2"
)

// NewClient returns an admin API client for tc. The OAuth client secret is
// read from its file or environment variable each time a new token is
// needed, never held in the config.
func NewClient(tc config.TailnetConfig) *tsclient.Client {
	tailnet := tc.Tailnet
	if tailnet == "" {
		tailnet = "-"
	}
	c := &tsclient.Client{Tailnet: tailnet, Auth: &oauth{creds: tc.OAuth}}
	if tc.APIBaseURL != "" {
		if u, err := url.Parse(tc.APIBaseURL); err == nil {
			c.BaseURL = u
		}
	}
	return c
}

// oauth is a tsclient.Auth like tsclient.OAuth, except that it reads the
// secret at token time.
type oauth struct {
	creds config.OAuthCreds
}

func (o *oauth) HTTPClient(orig *http.Client, baseURL string) *http.Client {
	src := &tokenSource{creds: o.creds, tokenURL: baseURL + "/api/v2/oauth/token"}
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

type tokenSource struct {
	creds    config.OAuthCreds
	tokenURL string
}

func (s *tokenSource) Token() (*oauth2.Token, error) {
	secret, err := s.creds.Secret()
	if err != nil {
		return nil, err
	}
	cc := clientcredentials.Config{ClientID: s.creds.ClientID, ClientSecret: secret, TokenURL: s.tokenURL}
	return cc.Token(context.Background())
}
