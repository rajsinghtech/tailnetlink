package config

import (
	"strings"
	"testing"
)

func TestSplitHost(t *testing.T) {
	cases := []struct {
		name, zone, wantZone, wantLabel, wantErr string
	}{
		{name: "app.corp.example.com", wantZone: "corp.example.com", wantLabel: "app"},
		{name: "app", wantZone: "app", wantLabel: "@"},
		{name: "app.corp.example.com.", wantZone: "corp.example.com", wantLabel: "app"},
		{name: "app.corp.example.com", zone: "app.corp.example.com", wantZone: "app.corp.example.com", wantLabel: "@"},
		{name: "app.corp.example.com", zone: "app.corp.example.com.", wantZone: "app.corp.example.com", wantLabel: "@"},
		{name: "App.Corp.Example.COM", zone: "app.corp.example.com", wantZone: "app.corp.example.com", wantLabel: "@"},
		{name: "a.b.corp.example.com", zone: "corp.example.com", wantZone: "corp.example.com", wantLabel: "a.b"},
		{name: "app.corp.example.com", zone: "example.com", wantZone: "example.com", wantLabel: "app.corp"},
		{name: "app.corp.example.com", zone: "other.example.com", wantErr: "must equal dns_zone"},
		{name: "app.corp.example.com", zone: "corp.example.com.extra", wantErr: "must equal dns_zone"},
		{name: "app.corp.example.com", zone: "ample.com", wantErr: "must equal dns_zone"},
		{name: "app.corp.example.com", zone: "not a zone", wantErr: "invalid character"},
		{name: "", zone: "example.com", wantErr: "dns_name"},
		{name: "app.corp.example.com", zone: ".", wantErr: "dns_zone"},
	}
	for _, c := range cases {
		zone, label, err := SplitHost(c.name, c.zone)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("SplitHost(%q, %q) = %q, %q, %v; want error %q", c.name, c.zone, zone, label, err, c.wantErr)
			}
			continue
		}
		if err != nil || zone != c.wantZone || label != c.wantLabel {
			t.Errorf("SplitHost(%q, %q) = %q, %q, %v; want %q, %q", c.name, c.zone, zone, label, err, c.wantZone, c.wantLabel)
		}
	}
}
