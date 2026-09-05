package webui

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/safepath"
)

func TestQuarantineRestoreDurabilityFailureRetainsEvidence(t *testing.T) {
	oldFileSync, oldParentSync, oldRemove := syncQuarantineRestoredFile, syncQuarantineRestoredParent, removeRestoredQuarantineEvidence
	t.Cleanup(func() {
		syncQuarantineRestoredFile, syncQuarantineRestoredParent, removeRestoredQuarantineEvidence = oldFileSync, oldParentSync, oldRemove
	})
	for _, phase := range []string{"file-sync", "directory-sync", "evidence-removal"} {
		t.Run(phase, func(t *testing.T) {
			syncQuarantineRestoredFile, syncQuarantineRestoredParent, removeRestoredQuarantineEvidence = oldFileSync, oldParentSync, oldRemove
			root := t.TempDir()
			qdir := filepath.Join(root, "quarantine")
			restoreRoot := filepath.Join(root, "account")
			for _, path := range []string{qdir, restoreRoot} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			withQuarantineDir(t, qdir)
			withQuarantineRestoreRoots(t, restoreRoot)
			const id = "evidence.php"
			path := filepath.Join(qdir, id)
			metaPath := path + ".meta"
			destination := filepath.Join(restoreRoot, "restored.php")
			if err := os.WriteFile(path, []byte("recovery content"), 0600); err != nil {
				t.Fatal(err)
			}
			metadata, err := json.Marshal(checks.QuarantineMeta{OriginalPath: destination, Owner: os.Getuid(), Group: os.Getgid(), Mode: "-rw-------"})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(metaPath, metadata, 0600); err != nil {
				t.Fatal(err)
			}
			fileSynced, parentSynced, removeCalled := false, false, false
			syncQuarantineRestoredFile = func(f *os.File) error {
				if phase == "file-sync" {
					return syscall.EIO
				}
				fileSynced = true
				return oldFileSync(f)
			}
			syncQuarantineRestoredParent = func(dir *safepath.Dir) error {
				if !fileSynced {
					t.Error("directory sync preceded file durability")
				}
				if phase == "directory-sync" {
					return syscall.EIO
				}
				parentSynced = true
				return oldParentSync(dir)
			}
			removeRestoredQuarantineEvidence = func(string, string) error {
				removeCalled = true
				if !fileSynced || !parentSynced {
					t.Error("quarantine removal preceded restored file and directory durability")
				}
				return errors.New("restored, but injected evidence removal failed")
			}
			s := newRestoreServer(t)
			w := httptest.NewRecorder()
			s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
			if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), `"status":"restored"`) {
				t.Fatalf("storage failure reported success: %d %s", w.Code, w.Body.String())
			}
			if removeCalled != (phase == "evidence-removal") {
				t.Fatalf("evidence removal called=%v in phase %s", removeCalled, phase)
			}
			for _, entry := range []struct{ path, content string }{{path, "recovery content"}, {metaPath, string(metadata)}} {
				data, readErr := os.ReadFile(entry.path)
				if readErr != nil || string(data) != entry.content {
					t.Fatalf("recovery evidence changed at %s: %q, error=%v", entry.path, data, readErr)
				}
			}
		})
	}
}

func TestQuarantineDirectoryRestoreSyncFailureRetainsRecovery(t *testing.T) {
	oldFileSync, oldParentSync := syncQuarantineRestoredFile, syncQuarantineRestoredParent
	t.Cleanup(func() {
		syncQuarantineRestoredFile, syncQuarantineRestoredParent = oldFileSync, oldParentSync
	})
	for _, phase := range []string{"file-sync", "directory-sync"} {
		t.Run(phase, func(t *testing.T) {
			syncQuarantineRestoredFile, syncQuarantineRestoredParent = oldFileSync, oldParentSync
			qPath := filepath.Join(t.TempDir(), "captured")
			if err := os.Mkdir(qPath, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(qPath, "content"), []byte("directory evidence"), 0600); err != nil {
				t.Fatal(err)
			}
			destinationRoot := t.TempDir()
			target, err := safepath.OpenTarget(destinationRoot, "restored", false)
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			if phase == "file-sync" {
				syncQuarantineRestoredFile = func(*os.File) error { return syscall.EIO }
			} else {
				syncQuarantineRestoredParent = func(*safepath.Dir) error { return syscall.EIO }
			}
			err = restoreQuarantineDirectory(qPath, target, 0700, checks.QuarantineMeta{Owner: os.Getuid(), Group: os.Getgid()})
			if !errors.Is(err, syscall.EIO) {
				t.Fatalf("%s failure not reported: %v", phase, err)
			}
			recovery := qPath
			if phase == "directory-sync" {
				recovery = filepath.Join(destinationRoot, "restored")
				if !strings.Contains(err.Error(), "directory moved") || !strings.Contains(err.Error(), "metadata retained") {
					t.Fatalf("partial directory restore not reported: %v", err)
				}
			}
			data, readErr := os.ReadFile(filepath.Join(recovery, "content"))
			if readErr != nil || string(data) != "directory evidence" {
				t.Fatalf("directory evidence lost: %q, error=%v", data, readErr)
			}
		})
	}
}
