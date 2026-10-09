package config

import (
	"fmt"
	"regexp"
)

// UIConfigFile is the read-only web UI block in the config file.
type UIConfigFile struct {
	Enabled     *bool  `json:"enabled,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	ListenAddr  string `json:"listen_addr,omitempty"`
}

// MetricsConfig controls the health and metrics listener.
type MetricsConfig struct {
	ListenAddr string `json:"listen_addr,omitempty"` // "off" disables it
}

// Authz modes. Empty Mode is AuthzOff.
const (
	AuthzOff         = "off"
	AuthzRequireCap  = "require_cap"
	AuthzAllowLogins = "allow_logins"
	AuthzAllowTags   = "allow_tags"
)

// AuthzConfig controls who may dial an export. Mode off (the default) allows
// every peer. require_cap needs the PeerCapability CapName with this export
// name (or "*") in its links list. allow_logins and allow_tags match the
// peer's WhoIs login or tags against the lists below.
type AuthzConfig struct {
	Mode        string   `json:"mode,omitempty"`
	AllowLogins []string `json:"allow_logins,omitempty"`
	AllowTags   []string `json:"allow_tags,omitempty"`
}

// Effective returns az if it sets a mode, otherwise the file default.
func (az AuthzConfig) Effective(file AuthzConfig) AuthzConfig {
	if az.Mode != "" {
		return az
	}
	return file
}

func (az AuthzConfig) validate() error {
	switch az.Mode {
	case "", AuthzOff:
		return nil
	case AuthzRequireCap:
		return nil
	case AuthzAllowLogins:
		if len(az.AllowLogins) == 0 {
			return fmt.Errorf("authz.mode %q needs at least one allow_logins entry", az.Mode)
		}
		return nil
	case AuthzAllowTags:
		if len(az.AllowTags) == 0 {
			return fmt.Errorf("authz.mode %q needs at least one allow_tags entry", az.Mode)
		}
		return nil
	default:
		return fmt.Errorf("authz.mode %q is not one of off, require_cap, allow_logins, allow_tags", az.Mode)
	}
}

// nameRe is the pattern for name, tailnet keys, and node hostnames of at
// most 40 characters. shortNameRe allows the longer DNS label.
var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)
