//go:build !linux

package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQuarantineFileTOCTOUSafeOtherHappyPath(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "webshell.php")
	original := []byte("<?php /* malware */ ?>")
	if err := os.WriteFile(src, original, 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	info, statErr := os.Lstat(src)
	if statErr != nil {
		t.Fatalf("lstat: %v", statErr)
	}
	dst := filepath.Join(tmp, "quarantine", "ts_webshell.php")
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := quarantineFileTOCTOUSafe(src, dst, info); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("dst content = %q, want original", got)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Errorf("source not removed (or err=%v)", err)
	}
}

func TestQuarantineFileTOCTOUSafeOtherRefusesSymlinkSwap(t *testing.T) {
	tmp := t.TempDir()
	victim := filepath.Join(tmp, "victim.txt")
	if err := os.WriteFile(victim, []byte("important"), 0o644); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	bait := filepath.Join(tmp, "bait.php")
	if err := os.WriteFile(bait, []byte("<?php"), 0o644); err != nil {
		t.Fatalf("write bait: %v", err)
	}
	info, statErr := os.Lstat(bait)
	if statErr != nil {
		t.Fatalf("lstat: %v", statErr)
	}
	if err := os.Remove(bait); err != nil {
		t.Fatalf("remove bait: %v", err)
	}
	if err := os.Symlink(victim, bait); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	dst := filepath.Join(tmp, "q", "out.php")
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	qErr := quarantineFileTOCTOUSafe(bait, dst, info)
	if qErr == nil {
		t.Fatal("expected refusal of symlinked path, got nil error")
	}
	if _, err := os.Lstat(bait); err != nil {
		t.Fatalf("symlink should be left in place: %v", err)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("victim file deleted during quarantine attempt: %v", err)
	}
	if _, err := os.Stat(dst); err == nil {
		t.Fatal("symlink should not be moved into quarantine")
	}
}

func TestQuarantineFileTOCTOUSafeOtherDetectsFileSwap(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "drop.php")
	if err := os.WriteFile(src, []byte("<?php /* malware */"), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	info, statErr := os.Lstat(src)
	if statErr != nil {
		t.Fatalf("lstat: %v", statErr)
	}
	if err := os.Remove(src); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := os.WriteFile(src, []byte("attacker-controlled"), 0o644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	dst := filepath.Join(tmp, "q", "out.php")
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	qErr := quarantineFileTOCTOUSafe(src, dst, info)
	if qErr == nil {
		t.Fatal("expected refusal after file swap, got nil error")
	}
	if !strings.Contains(qErr.Error(), "TOCTOU") {
		t.Errorf("error should mention TOCTOU, got %v", qErr)
	}
	if _, err := os.Stat(dst); err == nil {
		t.Fatal("attacker-controlled file ended up in quarantine")
	}
}
