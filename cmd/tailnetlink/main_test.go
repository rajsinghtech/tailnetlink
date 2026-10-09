package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/testutil/fakeapi"
	tsclient "tailscale.com/client/tailscale/v2"
)

// syncBuffer is an io.Writer that tests can read while run writes to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func waitForOutput(t *testing.T, out *syncBuffer, substr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), substr) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %q in output:\n%s", substr, out.String())
}

// borderConfig is a valid border whose API is unreachable, so tailnetlink
// starts, fails to connect and keeps running. extra goes in as is, before
// the links.
func borderConfig(extra string) string {
	return `{"name":"me",` + extra + `
		"tailnets":{
			"home":{"tailnet":"home.example","api_base_url":"http://127.0.0.1:1","auth":{"client_id":"id","client_secret_env":"X"},"tags":["tag:t"]},
			"work":{"tailnet":"work.example","api_base_url":"http://127.0.0.1:1","auth":{"client_id":"id","client_secret_env":"X"},"tags":["tag:t"]}
		},
		"targets":{"l":{"in":"home","tag":"tag:x","ports":[1]}},
		"exports":[{"target":"l","to":["work"]}]
	}`
}

func emptyConfig(t *testing.T) string {
	return filepath.Join(t.TempDir(), "tailnetlink.json") // missing file means empty config
}

// runAsync starts run and returns a channel with its exit code.
func runAsync(args []string, out io.Writer, sig chan os.Signal) chan int {
	code := make(chan int, 1)
	go func() { code <- run(args, out, sig) }()
	return code
}

func TestRunExitsCleanlyOnSignal(t *testing.T) {
	out := &syncBuffer{}
	sig := make(chan os.Signal, 2)
	code := runAsync([]string{"-data", emptyConfig(t), "-metrics-listen", "127.0.0.1:0", "-listen", "127.0.0.1:0"}, out, sig)
	waitForOutput(t, out, "web UI available")

	sig <- syscall.SIGTERM
	select {
	case c := <-code:
		if c != 0 {
			t.Fatalf("exit code %d, output:\n%s", c, out)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after SIGTERM")
	}
	if !strings.Contains(out.String(), "stopped") {
		t.Errorf("no clean stop in output:\n%s", out)
	}
}

func TestRunSecondSignalForcesExit(t *testing.T) {
	forced := make(chan int, 1)
	orig := forceExit
	forceExit = func(c int) { forced <- c }
	t.Cleanup(func() { forceExit = orig })

	out := &syncBuffer{}
	sig := make(chan os.Signal, 2)
	code := runAsync([]string{"-data", emptyConfig(t), "-metrics-listen", "127.0.0.1:0", "-listen", "127.0.0.1:0"}, out, sig)
	waitForOutput(t, out, "web UI available")
	sig <- syscall.SIGTERM
	sig <- syscall.SIGINT
	select {
	case c := <-forced:
		if c != 1 {
			t.Errorf("forced exit code %d", c)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("second signal did not force an exit")
	}
	<-code
}

func TestRunBadConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(p, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := run([]string{"-data", p}, io.Discard, nil); c != 1 {
		t.Errorf("exit code %d, want 1", c)
	}
}

func TestRunListenFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	out := &syncBuffer{}
	code := runAsync([]string{"-data", emptyConfig(t), "-metrics-listen", "127.0.0.1:0", "-listen", ln.Addr().String()}, out, make(chan os.Signal))
	select {
	case c := <-code:
		if c != 1 {
			t.Errorf("exit code %d, want 1", c)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run kept going with its port taken")
	}
}

func TestRunFlags(t *testing.T) {
	if c := run([]string{"-h"}, io.Discard, nil); c != 0 {
		t.Errorf("-h: exit code %d", c)
	}
	if c := run([]string{"-nope"}, io.Discard, nil); c != 2 {
		t.Errorf("unknown flag: exit code %d", c)
	}
}

func TestRunLogLevels(t *testing.T) {
	for _, lvl := range []string{"debug", "warn", "error"} {
		out := &syncBuffer{}
		sig := make(chan os.Signal, 1)
		sig <- syscall.SIGTERM
		if c := run([]string{"-data", emptyConfig(t), "-metrics-listen", "127.0.0.1:0", "-listen", "127.0.0.1:0", "-log-level", lvl}, out, sig); c != 0 {
			t.Errorf("%s: exit code %d:\n%s", lvl, c, out)
		}
	}
}

// TestBinaryExitsOnSIGTERM builds the real binary, starts it with an empty
// config and checks that SIGTERM makes it exit 0 well within the timeout.
func TestBinaryExitsOnSIGTERM(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "tailnetlink")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cmd := exec.Command(bin, "-data", emptyConfig(t), "-metrics-listen", "127.0.0.1:0", "-listen", "127.0.0.1:0", "-shutdown-timeout", "5s")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stdout)
		once := sync.Once{}
		for sc.Scan() {
			if strings.Contains(sc.Text(), "web UI available") {
				once.Do(func() { close(ready) })
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("binary never came up")
	}

	start := time.Now()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("exit: %v", err)
		}
		t.Logf("exited %v after SIGTERM", time.Since(start).Round(time.Millisecond))
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("binary still running 10s after SIGTERM")
	}
}

func TestPruneCommand(t *testing.T) {
	api := fakeapi.New(t)
	api.Tailnet = ""
	api.PutService(tsclient.VIPService{Name: "svc:mine", Addrs: []string{"100.100.0.1"}, Annotations: map[string]string{"tailnetlink/owner": "me"}})
	api.PutService(tsclient.VIPService{Name: "svc:theirs", Annotations: map[string]string{"tailnetlink/owner": "them"}})
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	side := func(key, tailnet string) string {
		return fmt.Sprintf(`%q:{"tailnet":%q,"api_base_url":%q,"auth":{"client_id":"id","client_secret_file":%q},"tags":["tag:t"]}`, key, tailnet, api.URL(), secret)
	}
	cfg := `{"name":"me","tailnets":{` + side("home", "home.example") + `,` + side("work", "work.example") + `},"targets":{"l":{"in":"home","tag":"tag:x","ports":[1]}},"exports":[{"target":"l","to":["work"]}]}`
	p := filepath.Join(dir, "c.json")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if c := run([]string{"prune", "-data", p, "-dry-run"}, &out, nil); c != 0 {
		t.Fatalf("dry run exit %d:\n%s", c, out.String())
	}
	if !strings.Contains(out.String(), "would work: delete service svc:mine") {
		t.Errorf("dry run output:\n%s", out.String())
	}
	if _, ok := api.Service("svc:mine"); !ok {
		t.Fatal("dry run deleted the service")
	}

	out.Reset()
	if c := run([]string{"prune", "-data", p}, &out, nil); c != 0 {
		t.Fatalf("exit %d:\n%s", c, out.String())
	}
	if got := api.ServiceNames(); len(got) != 1 || got[0] != "svc:theirs" {
		t.Errorf("services left = %v", got)
	}

	out.Reset()
	if c := run([]string{"prune", "-data", p}, &out, nil); c != 0 || !strings.Contains(out.String(), "nothing to prune") {
		t.Errorf("second prune exit %d:\n%s", c, out.String())
	}
}

func TestPruneCommandErrors(t *testing.T) {
	if c := run([]string{"prune", "-h"}, io.Discard, nil); c != 0 {
		t.Errorf("-h exit %d", c)
	}
	if c := run([]string{"prune", "-nope"}, io.Discard, nil); c != 2 {
		t.Errorf("bad flag exit %d", c)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(bad, []byte("{"), 0o600)
	if c := run([]string{"prune", "-data", bad}, io.Discard, nil); c != 1 {
		t.Errorf("bad config exit %d", c)
	}
	noName := filepath.Join(t.TempDir(), "empty.json")
	_ = os.WriteFile(noName, []byte("{}"), 0o600)
	if c := run([]string{"prune", "-data", noName}, io.Discard, nil); c != 1 {
		t.Errorf("no name exit %d", c)
	}
}

func TestRunRejectsInlineSecret(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	cfg := strings.Replace(borderConfig(""), `"client_secret_env":"X"`, `"client_secret":"inline-value"`, 1)
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if c := run([]string{"-data", p}, &out, nil); c != 1 {
		t.Fatalf("exit %d, want 1:\n%s", c, out.String())
	}
	if !strings.Contains(out.String(), "auth.client_secret is not supported") || strings.Contains(out.String(), "inline-value") {
		t.Errorf("output:\n%s", out.String())
	}
}

// With -ui=false, or ui.enabled false in the config, nothing listens on the
// UI address.
func TestRunUIOff(t *testing.T) {
	dir := t.TempDir()
	disabled := filepath.Join(dir, "off.json")
	if err := os.WriteFile(disabled, []byte(borderConfig(`"ui": {"enabled": false},`)), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"flag":   {"-data", emptyConfig(t), "-ui=false"},
		"config": {"-data", disabled},
	} {
		t.Run(name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := ln.Addr().String()
			ln.Close()
			out := &syncBuffer{}
			sig := make(chan os.Signal, 2)
			code := runAsync(append(args, "-metrics-listen", "127.0.0.1:0", "-listen", addr), out, sig)
			waitForOutput(t, out, "web UI is off")
			if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
				c.Close()
				t.Errorf("something listens on %s with the UI off", addr)
			}
			sig <- syscall.SIGTERM
			if c := <-code; c != 0 {
				t.Errorf("exit code %d:\n%s", c, out)
			}
		})
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	var last error
	for range 100 {
		resp, err := http.Get(url)
		if err != nil {
			last = err
			time.Sleep(20 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(body)
	}
	t.Fatalf("GET %s: %v", url, last)
	return 0, ""
}

// Health and metrics live on their own listener, not on the UI's, and stay
// up with the UI off.
func TestRunServesHealthOnMetricsListener(t *testing.T) {
	for _, ui := range []string{"-ui=true", "-ui=false"} {
		t.Run(ui, func(t *testing.T) {
			uiAddr, metricsAddr := freeAddr(t), freeAddr(t)
			out := &syncBuffer{}
			sig := make(chan os.Signal, 2)
			code := runAsync([]string{"-data", emptyConfig(t), ui, "-listen", uiAddr, "-metrics-listen", metricsAddr}, out, sig)
			waitForOutput(t, out, "metrics and health listening")

			if c, _ := get(t, "http://"+metricsAddr+"/healthz"); c != 200 {
				t.Errorf("/healthz = %d", c)
			}
			// An empty config is ready as soon as it has been applied.
			deadline := time.Now().Add(5 * time.Second)
			for {
				c, body := get(t, "http://"+metricsAddr+"/readyz")
				if c == 200 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("/readyz = %d %s", c, body)
				}
				time.Sleep(20 * time.Millisecond)
			}
			if c, body := get(t, "http://"+metricsAddr+"/metrics"); c != 200 || !strings.Contains(body, "tailnetlink_bridges{status=\"active\"} 0") {
				t.Errorf("/metrics = %d:\n%s", c, body)
			}
			if ui == "-ui=true" {
				for _, p := range []string{"/healthz", "/readyz", "/metrics"} {
					if c, _ := get(t, "http://"+uiAddr+p); c != 404 {
						t.Errorf("UI listener %s = %d, want 404", p, c)
					}
				}
			}
			sig <- syscall.SIGTERM
			if c := <-code; c != 0 {
				t.Errorf("exit code %d:\n%s", c, out)
			}
		})
	}
}

func TestRunMetricsOff(t *testing.T) {
	out := &syncBuffer{}
	sig := make(chan os.Signal, 2)
	code := runAsync([]string{"-data", emptyConfig(t), "-listen", "127.0.0.1:0", "-metrics-listen", "off"}, out, sig)
	waitForOutput(t, out, "web UI available")
	if strings.Contains(out.String(), "metrics and health listening") {
		t.Error("metrics listener started with -metrics-listen=off")
	}
	sig <- syscall.SIGTERM
	if c := <-code; c != 0 {
		t.Errorf("exit code %d:\n%s", c, out)
	}
}

// A metrics address that's taken is a startup failure, like the UI's.
func TestRunMetricsPortInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	out := &syncBuffer{}
	code := runAsync([]string{"-data", emptyConfig(t), "-ui=false", "-metrics-listen", ln.Addr().String()}, out, make(chan os.Signal))
	select {
	case c := <-code:
		if c != 1 {
			t.Errorf("exit code %d, want 1:\n%s", c, out)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not exit")
	}
}

// A v1 config doesn't start, and the error points at the README.
func TestRunRejectsV1Config(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(p, []byte(`{"instance_id":"me","tailnets":{},"bridges":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if c := run([]string{"-data", p}, &out, nil); c != 1 {
		t.Fatalf("exit %d, want 1:\n%s", c, out.String())
	}
	if !strings.Contains(out.String(), "old config") || !strings.Contains(out.String(), "README") {
		t.Errorf("output:\n%s", out.String())
	}
}

func TestVersionFlag(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })
	Version = "test-ver"
	var out bytes.Buffer
	if c := run([]string{"-version"}, &out, nil); c != 0 {
		t.Fatalf("exit %d", c)
	}
	if got := strings.TrimSpace(out.String()); got != "test-ver" {
		t.Fatalf("version = %q", got)
	}
}
