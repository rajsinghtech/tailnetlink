package bridge

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	tsclient "tailscale.com/client/tailscale/v2"
)

func TestNodeDirPersistent(t *testing.T) {
	m := New(nil, discardLogger(), nil)
	base := t.TempDir()
	dir, err := m.nodeDir("work", config.TailnetConfig{}, base)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(base, "work"); dir != want {
		t.Errorf("dir = %q, want %q", dir, want)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("mode = %v, want 0700", fi.Mode().Perm())
	}
	again, _ := m.nodeDir("work", config.TailnetConfig{}, base)
	if again != dir {
		t.Errorf("second call = %q, want the same dir", again)
	}
}

func TestNodeDirDefaults(t *testing.T) {
	m := New(nil, discardLogger(), nil)
	def := t.TempDir()
	m.SetDefaultStateDir(def)
	dir, err := m.nodeDir("home", config.TailnetConfig{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(dir, def) {
		t.Errorf("dir = %q, want it under the default %q", dir, def)
	}

	t.Chdir(t.TempDir())
	m.SetDefaultStateDir("")
	dir, err = m.nodeDir("home", config.TailnetConfig{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if dir != filepath.Join("tailnetlink-state", "home") {
		t.Errorf("dir = %q", dir)
	}
}

func TestNodeDirEphemeralIsFresh(t *testing.T) {
	m := New(nil, discardLogger(), nil)
	base := t.TempDir()
	a, err := m.nodeDir("work", config.TailnetConfig{Ephemeral: true}, base)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(a)
	b, err := m.nodeDir("work", config.TailnetConfig{Ephemeral: true}, base)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(b)
	if a == b || a == filepath.Join(base, "work") {
		t.Errorf("ephemeral dirs %q and %q should be fresh directories under the state dir", a, b)
	}
	for _, dir := range []string{a, b} {
		rel, err := filepath.Rel(base, dir)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
			t.Errorf("ephemeral dir %q is outside %q", dir, base)
		}
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Errorf("ephemeral dir mode = %v", fi.Mode().Perm())
		}
	}
}

func TestNodeDirError(t *testing.T) {
	m := New(nil, discardLogger(), nil)
	f := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(f, nil, 0o600)
	if _, err := m.nodeDir("work", config.TailnetConfig{}, f); err == nil {
		t.Error("want an error when state_dir is a file")
	}
}

func TestHasNodeState(t *testing.T) {
	dir := t.TempDir()
	if hasNodeState(dir) {
		t.Error("empty dir has state")
	}
	p := filepath.Join(dir, "tailscaled.state")
	_ = os.WriteFile(p, nil, 0o600)
	if hasNodeState(dir) {
		t.Error("empty state file counts as state")
	}
	_ = os.WriteFile(p, []byte("{}"), 0o600)
	if !hasNodeState(dir) {
		t.Error("state file not seen")
	}
}

func uiTestManager(t *testing.T) *testManager {
	tm := newTestManager(t)
	tm.dest.PutService(tsclient.VIPService{
		Name:        config.DefaultUIServiceName,
		Annotations: map[string]string{annotationOwner: testOwner, annotationManaged: "true"},
	})
	return tm
}

// Stopping a tailnet (shutdown, or a changed config) keeps the UI service.
func TestStopTailnetKeepsUIService(t *testing.T) {
	tm := uiTestManager(t)
	tm.dest.ResetCalls()
	tm.m.stopTailnet("dest", false)
	if _, ok := tm.m.servers["dest"]; ok {
		t.Error("server still registered")
	}
	if w := tm.dest.Writes(); len(w) != 0 {
		t.Errorf("stop made writes: %v", w)
	}
	if _, ok := tm.dest.Service(config.DefaultUIServiceName); !ok {
		t.Error("UI service deleted on stop")
	}
}

// Removing a tailnet from the config deletes our UI service there and
// cleans up an ephemeral node's directory.
func TestRemoveTailnetDeletesUIService(t *testing.T) {
	tm := uiTestManager(t)
	dir := t.TempDir()
	tm.m.nodeDirs["dest"] = dir
	tm.m.ephemeral["dest"] = true
	tm.m.stopTailnet("dest", true)
	if _, ok := tm.dest.Service(config.DefaultUIServiceName); ok {
		t.Error("UI service still there after remove")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("ephemeral dir not removed: %v", err)
	}
}

func TestRemoveTailnetLeavesForeignUIService(t *testing.T) {
	tm := newTestManager(t)
	tm.dest.PutService(tsclient.VIPService{
		Name:        config.DefaultUIServiceName,
		Annotations: map[string]string{annotationOwner: "someone-else"},
	})
	dir := t.TempDir()
	tm.m.nodeDirs["dest"] = dir
	tm.m.stopTailnet("dest", true)
	if _, ok := tm.dest.Service(config.DefaultUIServiceName); !ok {
		t.Error("foreign UI service deleted")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("persistent dir removed: %v", err)
	}
}

// Turning ui.enabled off in the config withdraws the UI from every running
// tailnet: our UI service is deleted and nothing else is touched.
func TestReconcileUIDisabledRemovesUIService(t *testing.T) {
	tm := uiTestManager(t)
	tm.m.ui = http.NotFoundHandler()
	tm.m.uiOn = true
	tm.m.cfg.InstanceID = testOwner
	off := false
	cfg := tm.m.cfg.Clone()
	cfg.UI.Enabled = &off
	tm.dest.ResetCalls()
	tm.m.Reconcile(context.Background(), cfg)
	if _, ok := tm.dest.Service(config.DefaultUIServiceName); ok {
		t.Error("UI service still there after ui.enabled=false")
	}
	if tm.m.uiOn {
		t.Error("uiOn still set")
	}
	for _, w := range tm.dest.Writes() {
		if w.Method != http.MethodDelete || !strings.Contains(w.Path, "svc:tailnetlink") {
			t.Errorf("unexpected write %s %s", w.Method, w.Path)
		}
	}
	if _, ok := tm.m.servers["dest"]; !ok {
		t.Error("tailnet stopped; only the UI should go")
	}
}

// A manager without a UI handler never publishes the UI, whatever the
// config says.
func TestReconcileNoUIHandler(t *testing.T) {
	tm := uiTestManager(t)
	tm.m.cfg.InstanceID = testOwner
	tm.dest.ResetCalls()
	tm.m.Reconcile(context.Background(), tm.m.cfg.Clone())
	if tm.m.uiOn {
		t.Error("uiOn set without a handler")
	}
	if w := tm.dest.Writes(); len(w) != 0 {
		t.Errorf("writes = %v", w)
	}
}
