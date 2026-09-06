package emailav

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestQuarantineSpoolSyncFailureKeepsRecoveryMetadata(t *testing.T) {
	oldSync := moveFileSyncDir
	t.Cleanup(func() { moveFileSyncDir = oldSync })
	for _, failAt := range []int{1, 2} {
		t.Run(fmt.Sprintf("sync-%d", failAt), func(t *testing.T) {
			const id = "2jKPFm-000abc-1X"
			spool := setupTestSpool(t, id)
			q := NewQuarantine(filepath.Join(t.TempDir(), "quarantine"))
			calls := 0
			moveFileSyncDir = func(path string) error {
				calls++
				if calls == failAt {
					return syscall.EIO
				}
				return oldSync(path)
			}
			err := q.QuarantineMessage(id, spool, &ScanResult{}, QuarantineEnvelope{})
			if !errors.Is(err, syscall.EIO) || !strings.Contains(err.Error(), "partly applied") {
				t.Fatalf("partial spool move not reported: %v", err)
			}
			meta, err := q.GetMessage(id)
			if err != nil || meta.OriginalSpoolDir != spool {
				t.Fatalf("recovery metadata missing: %+v, error=%v", meta, err)
			}
			if data, err := os.ReadFile(filepath.Join(q.baseDir, id, id+"-H")); err != nil || string(data) != "test header data" {
				t.Fatalf("quarantined header lost: %q, error=%v", data, err)
			}
			if data, err := os.ReadFile(filepath.Join(spool, id+"-D")); err != nil || string(data) != "test body data" {
				t.Fatalf("remaining spool body lost: %q, error=%v", data, err)
			}
		})
	}
}

func TestQuarantineSpoolRollbackFailureRetainsMovedFiles(t *testing.T) {
	const id = "2jKPFm-000abc-1X"
	spool := setupTestSpool(t, id)
	q := NewQuarantine(filepath.Join(t.TempDir(), "quarantine"))
	oldRename := moveFileRename
	t.Cleanup(func() { moveFileRename = oldRename })
	moveFileRename = func(src, dst string) error {
		if filepath.Base(src) == id+"-D" || filepath.Dir(dst) == spool {
			return syscall.EACCES
		}
		return oldRename(src, dst)
	}
	err := q.QuarantineMessage(id, spool, &ScanResult{}, QuarantineEnvelope{})
	if err == nil || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("rollback failure not reported: %v", err)
	}
	if _, err := q.GetMessage(id); err != nil {
		t.Fatalf("rollback failure deleted metadata: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(q.baseDir, id, id+"-H")); err != nil || string(data) != "test header data" {
		t.Fatalf("rollback failure deleted captured header: %q, error=%v", data, err)
	}
}

func TestReleaseSpoolBodySyncFailureDoesNotPublishHeader(t *testing.T) {
	const id = "2jKPFm-000abc-1X"
	spool := setupTestSpool(t, id)
	q := NewQuarantine(filepath.Join(t.TempDir(), "quarantine"))
	q.allowedSpoolDirs = []string{spool}
	if err := q.QuarantineMessage(id, spool, &ScanResult{}, QuarantineEnvelope{}); err != nil {
		t.Fatal(err)
	}
	oldSync := moveFileSyncDir
	t.Cleanup(func() { moveFileSyncDir = oldSync })
	moveFileSyncDir = func(string) error { return syscall.EIO }
	if err := q.ReleaseMessage(id); !errors.Is(err, syscall.EIO) {
		t.Fatalf("release sync failure not reported: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(spool, id+"-H")); !os.IsNotExist(err) {
		t.Fatalf("release published header before body durability: %v", err)
	}
	if _, err := q.GetMessage(id); err != nil {
		t.Fatalf("release failure lost recovery metadata: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(q.baseDir, id, id+"-H")); err != nil || string(data) != "test header data" {
		t.Fatalf("release failure lost header: %q, error=%v", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(spool, id+"-D")); err != nil || string(data) != "test body data" {
		t.Fatalf("release failure lost body: %q, error=%v", data, err)
	}
}
