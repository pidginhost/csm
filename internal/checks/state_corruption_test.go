package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A corrupt on-disk state file must not be discarded silently. Each loader
// below previously swallowed the json.Unmarshal error and returned an empty
// value, so an operator whose blocked_ips.json / permblock_tracker.json /
// firewall state.json got truncated lost the data with no signal. These tests
// pin a warning to stderr naming the offending file.

func TestLoadBlockStateWarnsOnCorruptJSON(t *testing.T) {
	old := osFS
	osFS = realOS{}
	t.Cleanup(func() { osFS = old })

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, blockStateFile), []byte("{ not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := captureStderr(t, func() { loadBlockState(dir) })
	if !strings.Contains(out, blockStateFile) {
		t.Errorf("expected a warning naming %q on corrupt state; got %q", blockStateFile, out)
	}
}

func TestLoadPermBlockTrackerWarnsOnCorruptJSON(t *testing.T) {
	old := osFS
	osFS = realOS{}
	t.Cleanup(func() { osFS = old })

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "permblock_tracker.json"), []byte("{ not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := captureStderr(t, func() { loadPermBlockTracker(dir) })
	if !strings.Contains(out, "permblock_tracker.json") {
		t.Errorf("expected a warning naming permblock_tracker.json on corrupt state; got %q", out)
	}
}

func TestLoadAllBlockedIPsWarnsOnCorruptFirewallState(t *testing.T) {
	old := osFS
	osFS = realOS{}
	t.Cleanup(func() { osFS = old })

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "firewall"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "firewall", "state.json"), []byte("{ not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := captureStderr(t, func() { loadAllBlockedIPs(dir) })
	if !strings.Contains(out, "state.json") {
		t.Errorf("expected a warning naming firewall state.json on corrupt suppression state; got %q", out)
	}
}
