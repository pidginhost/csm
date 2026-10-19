//go:build linux

package learnwatch

import (
	"os"
	"path/filepath"
	"testing"
)

func openTenant(t *testing.T) (Account, *Home) {
	t.Helper()
	a := tenantHome(t)
	h, err := OpenHome(a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return a, h
}

func TestOptInFilePresent(t *testing.T) {
	a, h := openTenant(t)
	writeMsg(t, filepath.Join(a.Home, ".spamassassinenable"), nil)
	if on, reason, err := h.Eligible(false); !on || reason != "" || err != nil {
		t.Fatalf("eligible %v, reason %q, error %v", on, reason, err)
	}
}

func TestOptInAbsent(t *testing.T) {
	_, h := openTenant(t)
	if on, reason, err := h.Eligible(false); on || reason != SkipOptedOut || err != nil {
		t.Fatalf("eligible %v, reason %q, error %v", on, reason, err)
	}
}

func TestOptInSymlinkIsOff(t *testing.T) {
	a, h := openTenant(t)
	target := filepath.Join(a.Home, "real")
	writeMsg(t, target, nil)
	if err := os.Symlink(target, filepath.Join(a.Home, ".spamassassinenable")); err != nil {
		t.Fatal(err)
	}
	if on, reason, err := h.Eligible(false); on || reason != SkipOptInSymlink || err != nil {
		t.Fatalf("eligible %v, reason %q, error %v", on, reason, err)
	}
	dir := filepath.Join(t.TempDir(), "h2")
	if err := os.MkdirAll(filepath.Join(dir, ".spamassassinenable"), 0o700); err != nil {
		t.Fatal(err)
	}
	h2, err := OpenHome(Account{UID: os.Getuid(), Home: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h2.Close() }()
	if on, reason, err := h2.Eligible(false); on || reason != SkipOptInNotRegular || err != nil {
		t.Fatalf("directory: eligible %v, reason %q, error %v", on, reason, err)
	}
}

func TestGlobalOptInMakesAllEligible(t *testing.T) {
	dir := t.TempDir()
	global := filepath.Join(dir, "global_spamassassin_enable")
	if on, err := GlobalOptIn(global); on || err != nil {
		t.Fatalf("absent global: %v, %v", on, err)
	}
	writeMsg(t, global, nil)
	global2, err := GlobalOptIn(global)
	if !global2 || err != nil {
		t.Fatalf("present global: %v, %v", global2, err)
	}
	_, h := openTenant(t)
	if on, reason, err := h.Eligible(global2); !on || reason != "" || err != nil {
		t.Fatalf("eligible %v, reason %q, error %v", on, reason, err)
	}
}

func TestOptInStatErrorIsRetryable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	a, h := openTenant(t)
	if err := os.Chmod(a.Home, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(a.Home, 0o700) })
	if on, _, err := h.Eligible(false); on || err == nil {
		t.Fatalf("stat failure read as %v, error %v", on, err)
	}
	locked := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	if on, err := GlobalOptIn(filepath.Join(locked, "global")); on || err == nil {
		t.Fatalf("global stat failure read as %v, error %v", on, err)
	}
}
