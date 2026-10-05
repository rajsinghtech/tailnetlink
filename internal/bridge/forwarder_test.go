package bridge

import (
	"io"
	"net"
	"testing"
)

func TestReadProxyHeader(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantAddr string
		wantBody string
		wantErr  bool
	}{
		{"tcp4", "PROXY TCP4 100.64.0.1 100.100.0.1 51234 80\r\nhello", "100.64.0.1:51234", "hello", false},
		{"tcp6", "PROXY TCP6 fd7a::1 fd7a::2 5000 443\r\nhi", "[fd7a::1]:5000", "hi", false},
		{"lf only", "PROXY TCP4 1.2.3.4 5.6.7.8 1 2\nx", "1.2.3.4:1", "x", false},
		{"unknown", "PROXY UNKNOWN\r\npayload", "", "payload", false},
		{"not proxy", "GET / HTTP/1.1\r\n", "", "", true},
		{"truncated", "PROXY TCP4 1.2.3.4\r\n", "", "", true},
		{"no newline", "PROXY TCP4 1.2.3.4 5.6.7.8 1 2", "", "", true},
		{"empty", "", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			go func() {
				_, _ = io.WriteString(client, c.input)
				_ = client.Close()
			}()
			conn, addr, err := readProxyHeader(server)
			if c.wantErr {
				if err == nil {
					t.Fatalf("want error, got addr %q", addr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if addr != c.wantAddr {
				t.Errorf("addr = %q, want %q", addr, c.wantAddr)
			}
			body, _ := io.ReadAll(conn)
			if string(body) != c.wantBody {
				t.Errorf("body = %q, want %q", body, c.wantBody)
			}
		})
	}
}

func TestFirstIP(t *testing.T) {
	cases := []struct {
		in   []string
		want string
		ok   bool
	}{
		{[]string{"100.64.0.1", "fd7a::1"}, "100.64.0.1", true},
		{[]string{"100.64.0.1/32"}, "100.64.0.1", true},
		{[]string{"junk", "fd7a::1/128"}, "fd7a::1", true},
		{nil, "", false},
		{[]string{"junk"}, "", false},
	}
	for _, c := range cases {
		got, ok := firstIP(c.in)
		if ok != c.ok || (ok && got.String() != c.want) {
			t.Errorf("firstIP(%v) = %v, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}
