//go:build linux

package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestQuarantineFileTOCTOUSafe_HappyPath asserts the safe helper moves
// a malware file from the original path into quarantine.
func TestQuarantineFileTOCTOUSafe_HappyPath(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "webshell.php")
	if err := os.WriteFile(src, []byte("<?php /* malware */ ?>"), 0644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	info, err := os.Lstat(src)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	dst := filepath.Join(tmp, "quarantine", "ts_webshell.php")
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := quarantineFileTOCTOUSafe(src, dst, info); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("quarantine dest not created: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Errorf("source not removed (or err=%v)", err)
	}
}

// TestQuarantineFileTOCTOUSafe_RefusesSymlink: any attacker-controlled
// directory that swaps the path into a symlink before our second open
// must not lure CSM into quarantining the symlink target.
func TestQuarantineFileTOCTOUSafe_RefusesSymlink(t *testing.T) {
	tmp := t.TempDir()
	victim := filepath.Join(tmp, "victim.txt")
	if err := os.WriteFile(victim, []byte("important"), 0644); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	bait := filepath.Join(tmp, "bait.php")
	if err := os.WriteFile(bait, []byte("<?php"), 0644); err != nil {
		t.Fatalf("write bait: %v", err)
	}
	info, err := os.Lstat(bait)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}

	// Replace bait with a symlink pointing at the victim AFTER the
	// detector captured info. The TOCTOU defence must refuse.
	if err := os.Remove(bait); err != nil {
		t.Fatalf("remove bait: %v", err)
	}
	if err := os.Symlink(victim, bait); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	dst := filepath.Join(tmp, "q", "out.php")
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	err = quarantineFileTOCTOUSafe(bait, dst, info)
	if err == nil {
		t.Fatal("expected refusal of symlinked path, got nil error")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("victim file deleted during quarantine attempt: %v", err)
	}
}

// TestQuarantineFileTOCTOUSafe_DetectsFileSwap: between the detector's
// Lstat and the quarantine helper, the attacker unlinks the malware
// and replaces it with a different regular file. The helper must
// refuse the move because the captured inode no longer matches.
func TestQuarantineFileTOCTOUSafe_DetectsFileSwap(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "drop.php")
	if err := os.WriteFile(src, []byte("<?php /* malware */"), 0644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	info, err := os.Lstat(src)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}

	// Swap: remove the original and replace with a different file that
	// has the same name but a different inode.
	if err := os.Remove(src); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := os.WriteFile(src, []byte("attacker-controlled"), 0644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	dst := filepath.Join(tmp, "q", "out.php")
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	err = quarantineFileTOCTOUSafe(src, dst, info)
	if err == nil {
		t.Fatal("expected refusal after file swap, got nil error")
	}
	if !strings.Contains(err.Error(), "TOCTOU") {
		t.Errorf("error should mention TOCTOU, got %v", err)
	}
	if _, err := os.Stat(dst); err == nil {
		t.Error("attacker-controlled file ended up in quarantine")
	}
}
