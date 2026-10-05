package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A config with an inline client_secret makes tailnetlink exit non-zero
// before it talks to either tailnet.
func TestInlineSecretExitsBeforeContactingControl(t *testing.T) {
	e2eSetup(t)
	b := newBorder(t)
	data, err := json.Marshal(b.border(b.deviceLink("web", "backend", "", 8080)))
	if err != nil {
		t.Fatal(err)
	}
	// Swap the file reference for the secret itself in the source tailnet.
	inline := strings.Replace(string(data), `"client_secret_file":"`+b.secretFiles[0]+`"`, `"client_secret":"`+b.secrets()[0]+`"`, 1)
	if inline == string(data) {
		t.Fatal("could not inline the secret")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "tailnetlink.json")
	if err := os.WriteFile(path, []byte(inline), 0o600); err != nil {
		t.Fatal(err)
	}

	bin := filepath.Join(dir, "tailnetlink")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/tailnetlink").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-data", path, "-listen", freeAddr(t))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 || ctx.Err() != nil {
		t.Fatalf("run = %v (ctx %v), want a non-zero exit\n%s", err, ctx.Err(), out.String())
	}
	if !strings.Contains(out.String(), "oauth.client_secret is not supported") {
		t.Errorf("output does not explain the error:\n%s", out.String())
	}
	if strings.Contains(out.String(), b.secrets()[0]) {
		t.Errorf("output contains the secret:\n%s", out.String())
	}
	if c := append(b.srcAPI.Calls(), b.dstAPI.Calls()...); len(c) != 0 {
		t.Errorf("admin API calls before exit: %v", c)
	}
	if n := len(b.src.control.AllNodes()) + len(b.dst.control.AllNodes()); n != 0 {
		t.Errorf("%d nodes registered before exit", n)
	}
}
