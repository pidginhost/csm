package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// withFixPermissionsAllowedRoots scopes the package-level allow-list
// down to one directory so tests can chmod files under t.TempDir without
// rewriting /home.
func withFixPermissionsAllowedRoots(t *testing.T, dir string) {
	t.Helper()
	old := fixPermissionsAllowedRoots
	fixPermissionsAllowedRoots = []string{dir}
	t.Cleanup(func() { fixPermissionsAllowedRoots = old })
}

func TestAutoFixPermissionsDisabledReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	// AutoResponse.Enabled defaults to false → guard returns nil immediately.
	actions, fixed := AutoFixPermissions(cfg, []alert.Finding{
		{Check: "world_writable_php", Message: "Path: /home/x/foo.php"},
	})
	if actions != nil || fixed != nil {
		t.Errorf("disabled auto-response should yield (nil, nil), got actions=%v fixed=%v", actions, fixed)
	}
}

func TestAutoFixPermissionsEnforceFlagOffReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.EnforcePermissions = false
	actions, fixed := AutoFixPermissions(cfg, []alert.Finding{
		{Check: "world_writable_php", Message: "Path: /home/x/foo.php"},
	})
	if actions != nil || fixed != nil {
		t.Errorf("enforce-permissions=false should yield (nil, nil), got actions=%v fixed=%v", actions, fixed)
	}
}

func TestAutoFixPermissionsIgnoresUnrelatedChecks(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.EnforcePermissions = true
	actions, fixed := AutoFixPermissions(cfg, []alert.Finding{
		{Check: "phishing_page", Message: "/home/x/foo.html"},
		{Check: "webshell", Message: "/home/x/shell.php"},
	})
	if len(actions) != 0 || len(fixed) != 0 {
		t.Errorf("unrelated checks should be ignored, got actions=%v fixed=%v", actions, fixed)
	}
}

func TestAutoFixPermissionsSkipsFindingWithoutPath(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.EnforcePermissions = true
	actions, fixed := AutoFixPermissions(cfg, []alert.Finding{
		{Check: "world_writable_php", Message: "no path here at all"},
	})
	if len(actions) != 0 || len(fixed) != 0 {
		t.Errorf("missing path should be skipped, got actions=%v fixed=%v", actions, fixed)
	}
}

func TestAutoFixPermissionsChmodsAndReportsAction(t *testing.T) {
	tmp := t.TempDir()
	withFixPermissionsAllowedRoots(t, tmp)

	target := filepath.Join(tmp, "loose.php")
	if err := os.WriteFile(target, []byte("<?php"), 0666); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.EnforcePermissions = true

	// AutoFixPermissions only recognises paths that include one of the
	// extractFilePath prefixes (/home, /tmp, /dev/shm, /var/tmp). On macOS
	// t.TempDir() returns /var/folders/... which doesn't match, so we
	// assemble a message that contains the absolute target embedded in a
	// recognisable prefix only when the host actually uses /tmp. Otherwise
	// fall back to an exact /home prefix and rely on the inline allowlist
	// override; here we just verify that a path under /tmp on Linux
	// reaches the chmod call and that on other platforms the function
	// degrades gracefully (no actions, no fixed).
	msg := fmt.Sprintf("World-writable PHP file: %s", target)
	actions, fixed := AutoFixPermissions(cfg, []alert.Finding{
		{Check: "world_writable_php", Message: msg},
	})

	if !strings.HasPrefix(target, "/tmp/") && !strings.HasPrefix(target, "/var/tmp/") {
		// On macOS (t.TempDir under /var/folders), extractFilePath returns
		// "" and AutoFixPermissions skips the finding. That's still a valid
		// branch — assert the no-op behaviour.
		if len(actions) != 0 || len(fixed) != 0 {
			t.Errorf("non-recognised tempdir prefix should yield no actions, got %v / %v", actions, fixed)
		}
		return
	}

	if len(actions) != 1 || len(fixed) != 1 {
		t.Fatalf("expected 1 action + 1 fixed key, got actions=%v fixed=%v", actions, fixed)
	}
	if !strings.Contains(actions[0].Message, "644") {
		t.Errorf("action message should mention new mode: %s", actions[0].Message)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("expected mode 0644 after fix, got %o", info.Mode().Perm())
	}
}

// --- extractFilePath ----------------------------------------------------

func TestExtractFilePathParsesAllPrefixes(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"webshell at /home/u/public_html/x.php was found", "/home/u/public_html/x.php"},
		{"dropper /tmp/evil.php deleted", "/tmp/evil.php"},
		{"file in /dev/shm/y.so", "/dev/shm/y.so"},
		// /var/tmp/ must be matched as itself, not have /tmp/ trip first
		// from inside the longer prefix. Regression test for the
		// prefix-ordering fix.
		{"file at /var/tmp/z.php, severity high", "/var/tmp/z.php"},
		{"comma terminator: /home/a/b.php, more", "/home/a/b.php"},
		{"no path mentioned", ""},
	}
	for _, c := range cases {
		if got := extractFilePath(c.in); got != c.want {
			t.Errorf("extractFilePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// --- extractPID --------------------------------------------------------

func TestExtractPIDParsesPattern(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"PID: 12345, exe=/bin/ls", "12345"},
		{"info before PID: 999 trailing", "999"},
		{"PID: 42", "42"},
		{"PID: 7\nlater", "7"},
		{"no pid here", ""},
	}
	for _, c := range cases {
		if got := extractPID(c.in); got != c.want {
			t.Errorf("extractPID(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
