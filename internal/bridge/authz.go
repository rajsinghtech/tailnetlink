package bridge

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

// CapName is the PeerCapability whose parameters list which links a peer
// may use when authz.mode is require_cap.
const CapName tailcfg.PeerCapability = "github.com/rajsinghtech/tailnetlink"

// capParams is the JSON value of CapName: {"links": ["api", "db"]} or ["*"].
type capParams struct {
	Links []string `json:"links"`
}

// whoIsResult is what authorize needs from WhoIs.
type whoIsResult struct {
	NodeName string
	Login    string
	Tags     []string
	CapMap   tailcfg.PeerCapMap
}

// whoIs looks up the peer at addr on srv. A variable so tests can inject.
var whoIs = func(ctx context.Context, srv *tsnet.Server, addr string) (whoIsResult, error) {
	if addr == "" {
		return whoIsResult{}, fmt.Errorf("empty peer address")
	}
	lc, err := srv.LocalClient()
	if err != nil {
		return whoIsResult{}, err
	}
	who, err := lc.WhoIs(ctx, addr)
	if err != nil {
		return whoIsResult{}, err
	}
	return whoIsFrom(who), nil
}

func whoIsFrom(who *apitype.WhoIsResponse) whoIsResult {
	var r whoIsResult
	if who == nil {
		return r
	}
	r.CapMap = who.CapMap
	if who.UserProfile != nil {
		r.Login = who.UserProfile.LoginName
	}
	if who.Node != nil {
		r.Tags = append([]string(nil), who.Node.Tags...)
		r.NodeName = strings.SplitN(who.Node.Name, ".", 2)[0]
	}
	return r
}

// authorize reports whether peer may use link under az. Mode off always
// allows. Anything else fails closed on WhoIs errors and on missing grants.
func authorize(az config.AuthzConfig, link string, peer whoIsResult, whoErr error) error {
	mode := az.Mode
	if mode == "" || mode == config.AuthzOff {
		return nil
	}
	if whoErr != nil {
		return fmt.Errorf("whois: %w", whoErr)
	}
	switch mode {
	case config.AuthzRequireCap:
		if allowedByCap(peer.CapMap, link) {
			return nil
		}
		return fmt.Errorf("missing capability %s for link %q", CapName, link)
	case config.AuthzAllowLogins:
		if peer.Login != "" && slices.Contains(az.AllowLogins, peer.Login) {
			return nil
		}
		return fmt.Errorf("login %q is not allowed", peer.Login)
	case config.AuthzAllowTags:
		for _, t := range peer.Tags {
			if slices.Contains(az.AllowTags, t) {
				return nil
			}
		}
		return fmt.Errorf("none of tags %v are allowed", peer.Tags)
	default:
		return fmt.Errorf("unknown authz mode %q", mode)
	}
}

func allowedByCap(cm tailcfg.PeerCapMap, link string) bool {
	if cm == nil {
		return false
	}
	vals, err := tailcfg.UnmarshalCapJSON[capParams](cm, CapName)
	if err != nil || len(vals) == 0 {
		// Presence with an empty / non-JSON value still doesn't grant a link.
		return false
	}
	for _, v := range vals {
		if slices.Contains(v.Links, "*") || slices.Contains(v.Links, link) {
			return true
		}
	}
	return false
}

func identityFromPeer(p whoIsResult) string {
	if p.Login != "" {
		return p.Login
	}
	if len(p.Tags) > 0 {
		return p.Tags[0]
	}
	return ""
}
