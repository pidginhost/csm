package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
)

// A restore that fails after it created the destination must not leave a
// partial, root-owned copy at the original path: the quarantine keeps the
// evidence, the list would then hide the entry as already restored, and a
// retry would fail because the destination exists.
func TestQuarantineRestoreFailureRemovesThePartialDestination(t *testing.T) {
	oldSync, oldModTime := syncQuarantineRestoredFile, restoreQuarantineModTime
	t.Cleanup(func() { syncQuarantineRestoredFile, restoreQuarantineModTime = oldSync, oldModTime })

	for _, phase := range []string{"modification-time", "file-sync"} {
		t.Run(phase, func(t *testing.T) {
			syncQuarantineRestoredFile, restoreQuarantineModTime = oldSync, oldModTime
			root := t.TempDir()
			qdir := filepath.Join(root, "quarantine")
			restoreRoot := filepath.Join(root, "account")
			for _, dir := range []string{qdir, restoreRoot} {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			withQuarantineDir(t, qdir)
			withQuarantineRestoreRoots(t, restoreRoot)
			const id = "evidence.php"
			path := filepath.Join(qdir, id)
			destination := filepath.Join(restoreRoot, "restored.php")
			if err := os.WriteFile(path, []byte("recovery content"), 0600); err != nil {
				t.Fatal(err)
			}
			meta, err := json.Marshal(checks.QuarantineMeta{
				OriginalPath: destination, Owner: os.Getuid(), Group: os.Getgid(),
				Mode: "-rw-------", OriginalModTime: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path+".meta", meta, 0600); err != nil {
				t.Fatal(err)
			}
			if phase == "modification-time" {
				restoreQuarantineModTime = func(*os.File, time.Time) error { return syscall.EIO }
			} else {
				syncQuarantineRestoredFile = func(*os.File) error { return syscall.EIO }
			}

			s := newRestoreServer(t)
			w := httptest.NewRecorder()
			s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("failed restore returned %d: %s", w.Code, w.Body.String())
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatalf("partial restore left at the original path: %v", err)
			}
			if data, err := os.ReadFile(path); err != nil || string(data) != "recovery content" {
				t.Fatalf("quarantine evidence changed: %q %v", data, err)
			}

			// With the fault gone the same restore succeeds.
			syncQuarantineRestoredFile, restoreQuarantineModTime = oldSync, oldModTime
			w = httptest.NewRecorder()
			s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
			if w.Code != http.StatusOK {
				t.Fatalf("retry after the fault returned %d: %s", w.Code, w.Body.String())
			}
			if data, err := os.ReadFile(destination); err != nil || string(data) != "recovery content" {
				t.Fatalf("retry did not restore the file: %q %v", data, err)
			}
		})
	}
}

// A file an account owner put at the destination after the restore created
// its own copy is not the restore's to delete.
func TestQuarantineRestoreFailureKeepsAReplacedDestination(t *testing.T) {
	oldSync := syncQuarantineRestoredFile
	t.Cleanup(func() { syncQuarantineRestoredFile = oldSync })
	root := t.TempDir()
	qdir := filepath.Join(root, "quarantine")
	restoreRoot := filepath.Join(root, "account")
	for _, dir := range []string{qdir, restoreRoot} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	withQuarantineDir(t, qdir)
	withQuarantineRestoreRoots(t, restoreRoot)
	const id = "evidence.php"
	path := filepath.Join(qdir, id)
	destination := filepath.Join(restoreRoot, "restored.php")
	if err := os.WriteFile(path, []byte("recovery content"), 0600); err != nil {
		t.Fatal(err)
	}
	meta, _ := json.Marshal(checks.QuarantineMeta{OriginalPath: destination, Owner: os.Getuid(), Group: os.Getgid(), Mode: "-rw-------"})
	if err := os.WriteFile(path+".meta", meta, 0600); err != nil {
		t.Fatal(err)
	}
	syncQuarantineRestoredFile = func(*os.File) error {
		// The owner swaps the name for their own file just before the fault.
		if err := os.Remove(destination); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, []byte("owner file"), 0600); err != nil {
			t.Fatal(err)
		}
		return syscall.EIO
	}
	s := newRestoreServer(t)
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
	if w.Code == http.StatusOK {
		t.Fatalf("restore reported success: %s", w.Body.String())
	}
	if data, err := os.ReadFile(destination); err != nil || string(data) != "owner file" {
		t.Fatalf("restore cleanup removed a file it did not create: %q %v", data, err)
	}
}
