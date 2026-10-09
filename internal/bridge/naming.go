package bridge

import (
	"crypto/md5"
	"fmt"
	"regexp"
	"strings"
)

var invalidChars = regexp.MustCompile(`[^a-zA-Z0-9-]`)

// ServiceName generates a deterministic VIP service name for a bridged device.
// If shortName is set it is used directly (svc:{shortName}). Otherwise the name
// is tnl-{srcTailnet}-{hostname} to avoid collisions across tailnets.
func ServiceName(srcTailnet, hostname, shortName string) string {
	if shortName != "" {
		// Config validation keeps short names to one DNS label; cap here
		// too so a name built any other way is still one the API accepts.
		return "svc:" + capLabel(sanitize(shortName), maxLabel)
	}

	host := strings.TrimSuffix(hostname, ".")
	host = strings.TrimPrefix(host, "svc:") // normalize service-mode names (svc:ai → ai)
	if idx := strings.Index(host, "."); idx > 0 {
		host = host[:idx]
	}

	base := "tnl-" + sanitize(srcTailnet) + "-" + sanitize(host)
	return "svc:" + capLabel(base, 59)
}

// maxLabel is the longest DNS label, and so the longest bare service name.
const maxLabel = 63

// capLabel shortens s to max bytes by replacing its tail with a short hash
// of the whole, so different long names stay different.
func capLabel(s string, max int) string {
	if len(s) <= max {
		return s
	}
	hash := fmt.Sprintf("%x", md5.Sum([]byte(s)))[:6]
	return strings.TrimRight(s[:max-7], "-") + "-" + hash
}

// HostLabel is the DNS label used in a tag export's VIP name. A service
// name loses its svc: prefix. A device hostname loses any domain.
func HostLabel(name string) string {
	name = strings.TrimPrefix(name, "svc:")
	name = strings.TrimSuffix(name, ".")
	if i := strings.IndexByte(name, '.'); i > 0 {
		name = name[:i]
	}
	s := sanitize(name)
	if s == "" {
		return "host"
	}
	return s
}

// TagServiceLabel is the bare VIP name for one device of a tag target:
// <export name>-<host>, cut and hashed to one DNS label.
func TagServiceLabel(exportName, discovered string) string {
	return capLabel(sanitize(exportName)+"-"+HostLabel(discovered), maxLabel)
}

func sanitize(s string) string {
	s = strings.ToLower(s)
	s = invalidChars.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	return s
}
