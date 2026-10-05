package bridge

import (
	"strings"
	"testing"
)

func TestServiceName(t *testing.T) {
	cases := []struct {
		name             string
		src, host, short string
		want             string
	}{
		{"device fqdn", "src", "api-0.example.ts.net", "", "svc:tnl-src-api-0"},
		{"trailing dot", "src", "api-0.example.ts.net.", "", "svc:tnl-src-api-0"},
		{"bare hostname", "src", "api-0", "", "svc:tnl-src-api-0"},
		{"service name", "src", "svc:ai", "", "svc:tnl-src-ai"},
		{"tailnet key sanitized", "My_Src", "web.example.ts.net", "", "svc:tnl-my-src-web"},
		{"short name wins", "src", "api-0.example.ts.net", "api", "svc:api"},
		{"short name sanitized", "src", "x", "My App", "svc:my-app"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ServiceName(c.src, c.host, c.short); got != c.want {
				t.Errorf("ServiceName(%q, %q, %q) = %q, want %q", c.src, c.host, c.short, got, c.want)
			}
		})
	}
}

func TestServiceNameLongIsCappedAndStable(t *testing.T) {
	src := strings.Repeat("a", 30)
	host := strings.Repeat("b", 40) + ".example.ts.net"
	got := ServiceName(src, host, "")
	if len(got) != 63 {
		t.Fatalf("len = %d, want 63 (%q)", len(got), got)
	}
	if !strings.HasPrefix(got, "svc:tnl-"+src) {
		t.Errorf("unexpected prefix: %q", got)
	}
	if again := ServiceName(src, host, ""); again != got {
		t.Errorf("not deterministic: %q vs %q", got, again)
	}
	other := ServiceName(src, strings.Repeat("b", 39)+"c.example.ts.net", "")
	if other == got {
		t.Errorf("different hosts with a shared prefix collided: %q", got)
	}
}

// KNOWN-BAD: short names are not length capped, so a long short_name gives
// a service name the API will reject. Not tied to a roadmap PR yet; fix
// alongside config validation.
func TestKnownBad_ShortNameNotCapped(t *testing.T) {
	got := ServiceName("src", "x", strings.Repeat("s", 70))
	if len(got) <= 63 {
		t.Fatalf("expected an uncapped name today, got len %d", len(got))
	}
}

func TestSanitize(t *testing.T) {
	cases := map[string]string{
		"Foo_Bar.baz": "foo-bar-baz",
		"--x--":       "x",
		"ok-123":      "ok-123",
		"a b\tc":      "a-b-c",
	}
	for in, want := range cases {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}
