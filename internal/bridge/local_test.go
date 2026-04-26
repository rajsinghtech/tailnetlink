package bridge

import (
	"testing"

	"github.com/rajsinghtech/tailnetlink/internal/config"
)

func TestIsLocalHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"0.0.0.0", true},
		{"192.168.1.5", true},
		{"10.0.0.1", true},
		{"ai.localtailnet.ts.net", false},
		{"local.app.custom.domain", false},
		{"myapp", false},
	}
	for _, c := range cases {
		got := isLocalHost(c.host)
		if got != c.want {
			t.Errorf("isLocalHost(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestLocalSourceEffectiveDNSName(t *testing.T) {
	cases := []struct {
		spec    config.LocalSourceSpec
		want    string
		wantErr bool
	}{
		{config.LocalSourceSpec{Addr: "localhost:11434", DNSName: "ollama.dest.ts.net"}, "ollama.dest.ts.net", false},
		{config.LocalSourceSpec{Addr: "ai.localtailnet.ts.net:8080"}, "ai.localtailnet.ts.net", false},
		{config.LocalSourceSpec{Addr: "local.app.custom.domain:80"}, "local.app.custom.domain", false},
		{config.LocalSourceSpec{Addr: "localhost:11434"}, "", true},
		{config.LocalSourceSpec{Addr: "192.168.1.5:8080"}, "", true},
		{config.LocalSourceSpec{Addr: "localhost:3000", DNSName: "app.dest.ts.net"}, "app.dest.ts.net", false},
	}
	for _, c := range cases {
		got, err := localSourceEffectiveDNSName(c.spec)
		if c.wantErr {
			if err == nil {
				t.Errorf("localSourceEffectiveDNSName(%v): want error, got nil (result %q)", c.spec, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("localSourceEffectiveDNSName(%v): unexpected error: %v", c.spec, err)
			continue
		}
		if got != c.want {
			t.Errorf("localSourceEffectiveDNSName(%v) = %q, want %q", c.spec, got, c.want)
		}
	}
}

func TestLocalSourceShortName(t *testing.T) {
	cases := []struct {
		shortName string
		dnsName   string
		want      string
	}{
		{"myapp", "anything.ts.net", "myapp"},
		{"", "ollama.dest.ts.net", "ollama"},
		{"", "ai.localtailnet.ts.net", "ai"},
		{"", "local.app.custom.domain", "local"},
		{"custom", "ai.ts.net", "custom"},
		{"", "singleword", "singleword"},
	}
	for _, c := range cases {
		got := localSourceShortName(c.shortName, c.dnsName)
		if got != c.want {
			t.Errorf("localSourceShortName(%q, %q) = %q, want %q", c.shortName, c.dnsName, got, c.want)
		}
	}
}

func TestLocalSourceExposePort(t *testing.T) {
	cases := []struct {
		spec config.LocalSourceSpec
		want int
	}{
		{config.LocalSourceSpec{Addr: "localhost:11434", ExposePort: 80}, 80},
		{config.LocalSourceSpec{Addr: "localhost:11434"}, 11434},
		{config.LocalSourceSpec{Addr: "ai.ts.net:8080", ExposePort: 443}, 443},
		{config.LocalSourceSpec{Addr: "ai.ts.net:8080"}, 8080},
	}
	for _, c := range cases {
		got, err := localSourceExposePort(c.spec)
		if err != nil {
			t.Errorf("localSourceExposePort(%v): unexpected error: %v", c.spec, err)
			continue
		}
		if got != c.want {
			t.Errorf("localSourceExposePort(%v) = %d, want %d", c.spec, got, c.want)
		}
	}
}
