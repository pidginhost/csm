package checks

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// withChmodFunc swaps the package-level chmod used by fixPermissions so tests
// can simulate a read-only mount (EROFS) or other chmod failures without an
// actual read-only filesystem, and assert that an already-compliant file is
// never chmodded at all.
func withChmodFunc(t *testing.T, fn func(string, os.FileMode) error) {
	t.Helper()
	old := chmodFunc
	chmodFunc = fn
	t.Cleanup(func() { chmodFunc = old })
}

// TestFixPermissionsAlreadyCompliantIsResolved covers the operator who has
// already chmodded the flagged file by hand (GitHub issue #23). Clicking
// "Apply automated fix" must recognise the file is no longer world-writable
// and report success WITHOUT touching it, so the finding clears instead of
// erroring.
func TestFixPermissionsAlreadyCompliantIsResolved(t *testing.T) {
	tmp := t.TempDir()
	withFixPermissionsAllowedRoots(t, tmp)
	withChmodFunc(t, func(string, os.FileMode) error {
		t.Error("chmod must not run for an already-compliant file")
		return nil
	})

	target := filepath.Join(tmp, "ok.php")
	if err := os.WriteFile(target, []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}

	res := ApplyFix("world_writable_php", "", "", target)
	if !res.Success {
		t.Fatalf("expected success for already-compliant file, got error %q", res.Error)
	}
	if !strings.Contains(strings.ToLower(res.Action+res.Description), "no longer") &&
		!strings.Contains(strings.ToLower(res.Action+res.Description), "already") {
		t.Errorf("expected already-compliant wording, got action=%q desc=%q", res.Action, res.Description)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("mode changed unexpectedly to %o", info.Mode().Perm())
	}
}

// TestFixPermissionsGroupWritableAlreadyCompliant: a 0644 file has no
// group-write bit, so a group_writable_php finding for it is already resolved.
func TestFixPermissionsGroupWritableAlreadyCompliant(t *testing.T) {
	tmp := t.TempDir()
	withFixPermissionsAllowedRoots(t, tmp)
	withChmodFunc(t, func(string, os.FileMode) error {
		t.Error("chmod must not run for an already-compliant file")
		return nil
	})

	target := filepath.Join(tmp, "g.php")
	if err := os.WriteFile(target, []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}

	res := ApplyFix("group_writable_php", "", "", target)
	if !res.Success {
		t.Fatalf("expected success for already-compliant group file, got error %q", res.Error)
	}
}

// TestFixPermissionsWorldWritableGetsChmodded is the regression guard: a still
// world-writable file is set to 0644.
func TestFixPermissionsWorldWritableGetsChmodded(t *testing.T) {
	tmp := t.TempDir()
	withFixPermissionsAllowedRoots(t, tmp)

	target := filepath.Join(tmp, "loose.php")
	if err := os.WriteFile(target, []byte("<?php"), 0666); err != nil {
		t.Fatal(err)
	}
	// WriteFile perms are masked by umask; force world-writable so the fix
	// genuinely exercises the chmod path rather than short-circuiting.
	if err := os.Chmod(target, 0666); err != nil {
		t.Fatal(err)
	}

	res := ApplyFix("world_writable_php", "", "", target)
	if !res.Success {
		t.Fatalf("expected success, got error %q", res.Error)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("expected mode 0644 after fix, got %o", info.Mode().Perm())
	}
}

// TestFixPermissionsReadOnlyMountFriendlyError covers the issue #23 symptom:
// the flagged file is still world-writable but lives on a read-only mount
// (e.g. a backup snapshot or bind mount). chmod returns EROFS; the operator
// must get a clear explanation, not the raw kernel "read-only file system"
// string.
func TestFixPermissionsReadOnlyMountFriendlyError(t *testing.T) {
	tmp := t.TempDir()
	withFixPermissionsAllowedRoots(t, tmp)

	target := filepath.Join(tmp, "loose.php")
	if err := os.WriteFile(target, []byte("<?php"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0666); err != nil { // defeat umask; stay world-writable
		t.Fatal(err)
	}
	withChmodFunc(t, func(path string, _ os.FileMode) error {
		return &os.PathError{Op: "chmod", Path: path, Err: syscall.EROFS}
	})

	res := ApplyFix("world_writable_php", "", "", target)
	if res.Success {
		t.Fatal("expected failure when the file is on a read-only mount")
	}
	low := strings.ToLower(res.Error)
	if !strings.Contains(low, "read-only mount") {
		t.Errorf("expected a read-only-mount explanation, got %q", res.Error)
	}
	if !strings.Contains(low, "dismiss") && !strings.Contains(low, "suppress") {
		t.Errorf("expected guidance to dismiss/suppress, got %q", res.Error)
	}
}

// TestFixPermissionsOtherChmodErrorSurfaced: a non-EROFS chmod failure still
// surfaces the generic "chmod failed" error.
func TestFixPermissionsOtherChmodErrorSurfaced(t *testing.T) {
	tmp := t.TempDir()
	withFixPermissionsAllowedRoots(t, tmp)

	target := filepath.Join(tmp, "loose.php")
	if err := os.WriteFile(target, []byte("<?php"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0666); err != nil { // defeat umask; stay world-writable
		t.Fatal(err)
	}
	withChmodFunc(t, func(string, os.FileMode) error { return syscall.EPERM })

	res := ApplyFix("world_writable_php", "", "", target)
	if res.Success {
		t.Fatal("expected failure")
	}
	if !strings.Contains(res.Error, "chmod failed") {
		t.Errorf("expected 'chmod failed' wording, got %q", res.Error)
	}
}
