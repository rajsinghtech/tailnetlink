package bridge

import (
	"crypto/md5"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"tailscale.com/tsnet"
)

var invalidChars = regexp.MustCompile(`[^a-zA-Z0-9-]`)

// ServiceName generates a deterministic VIP service name for a bridged device.
// If shortName is set it is used directly (svc:{shortName}). Otherwise the name
// is tnl-{srcTailnet}-{hostname} to avoid collisions across tailnets.
func ServiceName(srcTailnet, hostname, shortName string) string {
	if shortName != "" {
		return "svc:" + sanitize(shortName)
	}

	host := strings.TrimSuffix(hostname, ".")
	host = strings.TrimPrefix(host, "svc:") // normalize service-mode names (svc:ai → ai)
	if idx := strings.Index(host, "."); idx > 0 {
		host = host[:idx]
	}

	base := "tnl-" + sanitize(srcTailnet) + "-" + sanitize(host)
	if len(base) > 59 { // 63 - len("svc:") = 59
		hash := fmt.Sprintf("%x", md5.Sum([]byte(base)))[:6]
		base = base[:52] + "-" + hash
	}
	return "svc:" + base
}

func sanitize(s string) string {
	s = strings.ToLower(s)
	s = invalidChars.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	return s
}

// listenServiceWithRetry calls srv.ListenService, retrying up to 8 times on
// etag-mismatch races that occur when concurrent goroutines update the serve config.
func listenServiceWithRetry(srv *tsnet.Server, svcName string, mode tsnet.ServiceMode) (net.Listener, error) {
	for attempt := range 8 {
		ln, err := srv.ListenService(svcName, mode)
		if err == nil {
			return ln, nil
		}
		if strings.Contains(err.Error(), "etag mismatch") {
			time.Sleep(time.Duration(attempt+1) * 150 * time.Millisecond)
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("listen %s: etag mismatch after retries", svcName)
}
