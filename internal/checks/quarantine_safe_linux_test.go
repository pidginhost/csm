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

	if err := quarantineFileTOCTOUSafe(src, dst, info, []byte("{}")); err != nil {
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
	if rmErr := os.Remove(bait); rmErr != nil {
		t.Fatalf("remove bait: %v", rmErr)
	}
	if linkErr := os.Symlink(victim, bait); linkErr != nil {
		t.Fatalf("symlink: %v", linkErr)
	}

	dst := filepath.Join(tmp, "q", "out.php")
	if mkErr := os.MkdirAll(filepath.Dir(dst), 0700); mkErr != nil {
		t.Fatalf("mkdir: %v", mkErr)
	}

	err = quarantineFileTOCTOUSafe(bait, dst, info, []byte("{}"))
	if err == nil {
		t.Fatal("expected refusal of symlinked path, got nil error")
	}
	if _, statErr := os.Stat(victim); statErr != nil {
		t.Fatalf("victim file deleted during quarantine attempt: %v", statErr)
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
	if rmErr := os.Remove(src); rmErr != nil {
		t.Fatalf("remove: %v", rmErr)
	}
	if wrErr := os.WriteFile(src, []byte("attacker-controlled"), 0644); wrErr != nil {
		t.Fatalf("rewrite: %v", wrErr)
	}

	dst := filepath.Join(tmp, "q", "out.php")
	if mkErr := os.MkdirAll(filepath.Dir(dst), 0700); mkErr != nil {
		t.Fatalf("mkdir: %v", mkErr)
	}

	err = quarantineFileTOCTOUSafe(src, dst, info, []byte("{}"))
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

func TestQuarantineFileTOCTOUSafe_CopyUsesOpenFD(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "drop.php")
	original := []byte("<?php /* original malware */")
	if err := os.WriteFile(src, original, 0644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	info, err := os.Lstat(src)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	dst := filepath.Join(tmp, "q", "out.php")
	if mkErr := os.MkdirAll(filepath.Dir(dst), 0700); mkErr != nil {
		t.Fatalf("mkdir: %v", mkErr)
	}

	oldCopy := quarantineCopyByFD
	quarantineCopyByFD = func(fd *os.File, qPath string, metadata []byte) error {
		if rmErr := os.Remove(src); rmErr != nil {
			return rmErr
		}
		if wrErr := os.WriteFile(src, []byte("replacement"), 0644); wrErr != nil {
			return wrErr
		}
		return oldCopy(fd, qPath, metadata)
	}
	t.Cleanup(func() { quarantineCopyByFD = oldCopy })

	// The hook swapped a replacement into the source path after the fd was
	// opened: the copy must still come from the open fd, and the swap is
	// reported rather than passed off as a completed quarantine.
	qErr := quarantineFileTOCTOUSafe(src, dst, info, []byte("{}"))
	if qErr == nil || !strings.Contains(qErr.Error(), "replaced before unlink") {
		t.Fatalf("swap after open not reported: %v", qErr)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("dst content = %q, want original malware", got)
	}
	replacement, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("replacement path should be left alone: %v", err)
	}
	if string(replacement) != "replacement" {
		t.Fatalf("source replacement = %q, want replacement", replacement)
	}
}
