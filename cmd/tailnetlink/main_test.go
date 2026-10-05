package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
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
	code := runAsync([]string{"-data", emptyConfig(t), "-listen", "127.0.0.1:0"}, out, sig)
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
	code := runAsync([]string{"-data", emptyConfig(t), "-listen", "127.0.0.1:0"}, out, sig)
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
	code := runAsync([]string{"-data", emptyConfig(t), "-listen", ln.Addr().String()}, out, make(chan os.Signal))
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
		if c := run([]string{"-data", emptyConfig(t), "-listen", "127.0.0.1:0", "-log-level", lvl}, out, sig); c != 0 {
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
	cmd := exec.Command(bin, "-data", emptyConfig(t), "-listen", "127.0.0.1:0", "-shutdown-timeout", "5s")
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
