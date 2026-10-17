//go:build linux

package checks

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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
	quarantineCopyByFD = func(fd *os.File, qPath string, metadata []byte, size int64) error {
		if rmErr := os.Remove(src); rmErr != nil {
			return rmErr
		}
		if wrErr := os.WriteFile(src, []byte("replacement"), 0644); wrErr != nil {
			return wrErr
		}
		return oldCopy(fd, qPath, metadata, size)
	}
	t.Cleanup(func() { quarantineCopyByFD = oldCopy })

	// The hook swapped a replacement into the source path after the fd was
	// opened: the copy must still come from the open fd, and the swap is
	// reported rather than passed off as a completed quarantine.
	qErr := quarantineFileTOCTOUSafe(src, dst, info, []byte("{}"))
	if qErr == nil || !strings.Contains(qErr.Error(), "replaced before atomic capture") {
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

func TestQuarantineFileVersionedTOCTOUSafeRefusesSameInodeRewrite(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "drop.php")
	original := []byte("<?php system($_POST['command']);")
	replacement := []byte("<?php system($_POST['payload']);")
	if err := os.WriteFile(src, original, 0644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(tmp, "q", "out.php")
	if err = os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		t.Fatal(err)
	}

	oldHook := quarantineBeforeLease
	quarantineBeforeLease = func(string) error {
		if writeErr := os.WriteFile(src, replacement, 0644); writeErr != nil {
			return writeErr
		}
		if timeErr := os.Chtimes(src, info.ModTime(), info.ModTime()); timeErr != nil {
			return timeErr
		}
		return nil
	}
	t.Cleanup(func() { quarantineBeforeLease = oldHook })

	err = quarantineFileVersionedTOCTOUSafe(src, dst, info, []byte("{}"), original)
	if err == nil || !strings.Contains(err.Error(), "changed before atomic capture") {
		t.Fatalf("same-inode rewrite was not refused: %v", err)
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Fatalf("untrustworthy quarantine copy remains: %v", statErr)
	}
	got, err := os.ReadFile(src)
	if err != nil || string(got) != string(replacement) {
		t.Fatalf("replacement source=%q, %v", got, err)
	}
}

func TestQuarantineFileVersionedTOCTOUSafePreservesFinalPathReplacement(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "drop.php")
	original := []byte("<?php system($_POST['command']);")
	replacement := []byte("customer content")
	if err := os.WriteFile(src, original, 0644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(tmp, "q", "out.php")
	if err = os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		t.Fatal(err)
	}

	oldHook := quarantineBeforeCapturedUnlink
	quarantineBeforeCapturedUnlink = func(path string) error {
		if writeErr := os.WriteFile(path, replacement, 0644); writeErr != nil {
			return writeErr
		}
		return nil
	}
	t.Cleanup(func() { quarantineBeforeCapturedUnlink = oldHook })

	_ = quarantineFileVersionedTOCTOUSafe(src, dst, info, []byte("{}"), original)
	got, err := os.ReadFile(src)
	if err != nil || string(got) != string(replacement) {
		t.Fatalf("final path replacement was removed: content=%q error=%v", got, err)
	}
	got, err = os.ReadFile(dst)
	if err != nil || string(got) != string(original) {
		t.Fatalf("recovery copy=%q, error=%v", got, err)
	}
}

func TestQuarantineFileVersionedTOCTOUSafeRefusesPreOpenWriter(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "drop.php")
	original := []byte("<?php system($_POST['command']);")
	replacement := []byte("customer content written through an open descriptor")
	if err := os.WriteFile(src, original, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(src)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(src, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	dst := filepath.Join(tmp, "q", "out.php")
	if err = os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		t.Fatal(err)
	}

	oldHook := quarantineBeforeCapturedUnlink
	hookCalled := false
	quarantineBeforeCapturedUnlink = func(string) error {
		hookCalled = true
		if _, writeErr := writer.WriteAt(replacement, 0); writeErr != nil {
			return writeErr
		}
		return writer.Truncate(int64(len(replacement)))
	}
	t.Cleanup(func() { quarantineBeforeCapturedUnlink = oldHook })

	err = quarantineFileVersionedTOCTOUSafe(src, dst, info, []byte("{}"), original)
	if err == nil || !errors.Is(err, errFileResponseRefused) {
		t.Fatalf("pre-open writer was not refused: %v", err)
	}
	if hookCalled {
		t.Fatal("quarantine started deleting while another writable descriptor was open")
	}
	got, readErr := os.ReadFile(src)
	if readErr != nil || string(got) != string(original) {
		t.Fatalf("source=%q, error=%v", got, readErr)
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Fatalf("refused quarantine left a copy: %v", statErr)
	}
}

func TestQuarantineFileVersionedTOCTOUSafeUsesPinnedDescriptorLease(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "drop.php")
	original := []byte("<?php system($_POST['command']);")
	if err := os.WriteFile(src, original, 0600); err != nil {
		t.Fatal(err)
	}
	pinned, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	info, err := pinned.Stat()
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(tmp, "q", "out.php")
	if err = os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		t.Fatal(err)
	}

	err = quarantineFileVersionedTOCTOUSafeFD(src, dst, info, []byte("{}"), int(pinned.Fd()), original)
	if err != nil {
		t.Fatalf("quarantine through pinned descriptor: %v", err)
	}
	if _, statErr := os.Stat(src); !os.IsNotExist(statErr) {
		t.Fatalf("source still present: %v", statErr)
	}
	got, readErr := os.ReadFile(dst)
	if readErr != nil || string(got) != string(original) {
		t.Fatalf("quarantine content=%q, error=%v", got, readErr)
	}
}

// Generic quarantine runs while other descriptors are open: a web server
// worker, a backup reader, or the fanotify event that produced the finding.
// Only the realtime PHP response requires an exclusive lease.
func TestQuarantineFileTOCTOUSafeAllowsOpenReader(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "shell.php")
	original := []byte("<?php /* malware */ ?>")
	if err := os.WriteFile(src, original, 0644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(src)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	dst := filepath.Join(tmp, "q", "out.php")
	if err = os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		t.Fatal(err)
	}

	if err = quarantineFileTOCTOUSafe(src, dst, info, []byte("{}")); err != nil {
		t.Fatalf("quarantine with another reader open: %v", err)
	}
	if _, statErr := os.Lstat(src); !os.IsNotExist(statErr) {
		t.Fatalf("source still present: %v", statErr)
	}
	if got, readErr := os.ReadFile(dst); readErr != nil || string(got) != string(original) {
		t.Fatalf("quarantine content=%q, error=%v", got, readErr)
	}
}

// A dropped miner or backdoor is usually running when it is found. Linux never
// grants a write lease on an executing file, so generic quarantine must not
// depend on one.
func TestQuarantineFileTOCTOUSafeMovesRunningExecutable(t *testing.T) {
	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(sleepPath)
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	src := filepath.Join(tmp, "miner")
	if err = os.WriteFile(src, body, 0700); err != nil {
		t.Fatal(err)
	}
	var cmd *exec.Cmd
	for attempt := 0; ; attempt++ {
		cmd = &exec.Cmd{Path: src, Args: []string{"sleep", "60"}}
		err = cmd.Start()
		// A concurrent fork can briefly inherit the write descriptor (golang/go#22315).
		if !errors.Is(err, syscall.ETXTBSY) || attempt == 20 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	info, err := os.Lstat(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(tmp, "q", "miner")
	if err = os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		t.Fatal(err)
	}

	if err = quarantineFileTOCTOUSafe(src, dst, info, []byte("{}")); err != nil {
		t.Fatalf("quarantine of a running executable: %v", err)
	}
	if _, statErr := os.Lstat(src); !os.IsNotExist(statErr) {
		t.Fatalf("source still present: %v", statErr)
	}
	if got, readErr := os.ReadFile(dst); readErr != nil || string(got) != string(body) {
		t.Fatalf("quarantine copy differs from the executable: error=%v", readErr)
	}
}
