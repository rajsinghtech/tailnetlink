package bridge

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"
)

// Tests named TestKnownBad_* pin behavior that the roadmap says is wrong.
// They pass today on purpose. When the PR that fixes the behavior lands,
// that PR should flip the assertion (and drop the KnownBad prefix) rather
// than delete the test.

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// waitFor polls cond until it returns true or the timeout passes.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func callStrings[T interface{ String() string }](cs []T) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.String()
	}
	return out
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
