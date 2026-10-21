//go:build linux

package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// autoFixPermissionsFixture returns a world-writable PHP file under /var/tmp,
// one of the prefixes extractFilePath recognizes, and the finding for it.
func autoFixPermissionsFixture(t *testing.T, mode os.FileMode) (*config.Config, string, alert.Finding) {
	t.Helper()
	root, err := os.MkdirTemp("/var/tmp", "csm-autofix-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	withFixPermissionsAllowedRoots(t, root)
	path := filepath.Join(root, "loose.php")
	if err := os.WriteFile(path, []byte("<?php"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	finding := alert.Finding{Check: "world_writable_php", Message: "World-writable PHP file: " + path}
	if got := extractFilePath(finding.Message); got != path {
		t.Fatalf("fixture path %q not extracted from the finding (got %q)", path, got)
	}
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.EnforcePermissions = true
	return cfg, path, finding
}

func TestAutoFixPermissionsDoesNotFollowSwappedFile(t *testing.T) {
	cfg, path, finding := autoFixPermissionsFixture(t, 0o666)
	victim := writeSwapVictim(t)
	withFixAfterPathResolved(t, func(resolved string) {
		if resolved == path {
			replaceWithSymlink(t, resolved, victim)
		}
	})

	actions, fixed := AutoFixPermissions(cfg, []alert.Finding{finding})

	assertSwapVictimUntouched(t, victim)
	if len(actions) != 0 || len(fixed) != 0 {
		t.Fatalf("swapped file reported as fixed: actions=%v fixed=%v", actions, fixed)
	}
}

// A stale finding must not widen access: a file the owner has since made
// private would become world-readable under a blind chmod 0644.
func TestAutoFixPermissionsLeavesNoLongerWritableFileAlone(t *testing.T) {
	cfg, path, finding := autoFixPermissionsFixture(t, 0o600)

	actions, fixed := AutoFixPermissions(cfg, []alert.Finding{finding})

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("compliant file was chmodded to %o", info.Mode().Perm())
	}
	if len(actions) != 0 {
		t.Errorf("no-op reported as an auto-fix action: %v", actions)
	}
	if len(fixed) != 1 {
		t.Errorf("resolved finding not reported as fixed: %v", fixed)
	}
}
