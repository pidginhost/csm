package webui

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// newRestoreServer returns a minimal Server with a writable StatePath so
// the handler's auditLog call doesn't panic.
func newRestoreServer(t *testing.T) *Server {
	t.Helper()
	return &Server{cfg: &config.Config{StatePath: t.TempDir()}}
}

// withQuarantineRestoreRoots scopes the package allow-list of restore
// destinations down to `dir` so tests don't have to write under /home.
func withQuarantineRestoreRoots(t *testing.T, dir string) {
	t.Helper()
	old := quarantineRestoreRoots
	quarantineRestoreRoots = []string{dir}
	t.Cleanup(func() { quarantineRestoreRoots = old })
}

func withQuarantineRestoreAfterCreateHook(t *testing.T, hook func(string)) {
	t.Helper()
	old := quarantineRestoreAfterCreateForTest
	quarantineRestoreAfterCreateForTest = hook
	t.Cleanup(func() { quarantineRestoreAfterCreateForTest = old })
}

// newRestoreRequest builds a POST /api/v1/quarantine-restore with a JSON body.
func newRestoreRequest(t *testing.T, body map[string]string) *http.Request {
	t.Helper()
	buf, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/quarantine-restore", strings.NewReader(string(buf)))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestApiQuarantineRestoreRejectsGET(t *testing.T) {
	s := newRestoreServer(t)
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, httptest.NewRequest(http.MethodGet, "/api/v1/quarantine-restore", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestApiQuarantineRestoreMissingIDReturns400(t *testing.T) {
	s := newRestoreServer(t)
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": ""}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestApiQuarantineRestoreTraversalIDRejected(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineDir(t, tmp)

	s := newRestoreServer(t)
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": ".."}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for traversal id, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestApiQuarantineRestoreMissingMetaReturns404(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineDir(t, tmp)

	s := newRestoreServer(t)
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": "missing-file"}))
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for missing meta, got %d", w.Code)
	}
}

func TestApiQuarantineRestoreInvalidMetaJSONReturns500(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineDir(t, tmp)

	id := "garbage.file"
	if err := os.WriteFile(filepath.Join(tmp, id), []byte("body"), 0600); err != nil {
		t.Fatal(err)
	}
	// Meta file exists but isn't valid JSON.
	if err := os.WriteFile(filepath.Join(tmp, id+".meta"), []byte("{not valid"), 0600); err != nil {
		t.Fatal(err)
	}

	s := newRestoreServer(t)
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for invalid meta, got %d", w.Code)
	}
}

func TestApiQuarantineRestoreBadOriginalPathRejected(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineDir(t, tmp)

	id := "bad-origin.file"
	if err := os.WriteFile(filepath.Join(tmp, id), []byte("body"), 0600); err != nil {
		t.Fatal(err)
	}
	meta := map[string]interface{}{
		"original_path": "relative/path.txt", // not absolute → validate fails
		"owner_uid":     1000,
		"group_gid":     1000,
		"mode":          "-rw-r--r--",
	}
	mj, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(tmp, id+".meta"), mj, 0600); err != nil {
		t.Fatal(err)
	}

	s := newRestoreServer(t)
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-absolute original_path, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestApiQuarantineRestoreRestoresRegularFile(t *testing.T) {
	tmp := t.TempDir()
	qdir := filepath.Join(tmp, "quarantine")
	if err := os.MkdirAll(qdir, 0700); err != nil {
		t.Fatal(err)
	}
	restoreRoot := filepath.Join(tmp, "restore-target")
	if err := os.MkdirAll(restoreRoot, 0755); err != nil {
		t.Fatal(err)
	}
	withQuarantineDir(t, qdir)
	withQuarantineRestoreRoots(t, restoreRoot)

	id := "20260415-120000_file.txt"
	originalPath := filepath.Join(restoreRoot, "alice", "public_html", "file.txt")
	payload := []byte("restored content")
	if err := os.WriteFile(filepath.Join(qdir, id), payload, 0600); err != nil {
		t.Fatal(err)
	}
	meta := map[string]interface{}{
		"original_path": originalPath,
		"owner_uid":     os.Getuid(),
		"group_gid":     os.Getgid(),
		"mode":          "-rw-r--r--",
	}
	mj, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(qdir, id+".meta"), mj, 0600); err != nil {
		t.Fatal(err)
	}

	s := newRestoreServer(t)
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	// Restored file content matches.
	got, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatalf("restored file missing: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("restored content mismatch: got %q, want %q", got, payload)
	}
	// Quarantined item should be gone.
	if _, err := os.Stat(filepath.Join(qdir, id)); !os.IsNotExist(err) {
		t.Errorf("quarantined file should be removed, stat err=%v", err)
	}
}

func restoreTestSHA256(content []byte) string {
	sum := sha256.Sum256(content)
	return fmt.Sprintf("sha256:%x", sum[:])
}

func TestApiQuarantineRestoreRemovesCSMCreatedHtaccess(t *testing.T) {
	tmp := t.TempDir()
	qdir := filepath.Join(tmp, "quarantine")
	preClean := filepath.Join(qdir, "pre_clean")
	restoreRoot := filepath.Join(tmp, "restore-target")
	if err := os.MkdirAll(preClean, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(restoreRoot, 0755); err != nil {
		t.Fatal(err)
	}
	withQuarantineDir(t, qdir)
	withQuarantineRestoreRoots(t, restoreRoot)

	id := "new-htaccess"
	itemPath := filepath.Join(preClean, id)
	if err := os.WriteFile(itemPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(restoreRoot, ".htaccess")
	patched := []byte("# BEGIN CSM exposed-file virtual-patch .env\n<Files \".env\">\nRequire all denied\n</Files>\n# END CSM exposed-file virtual-patch .env\n")
	if err := os.WriteFile(live, patched, 0644); err != nil {
		t.Fatal(err)
	}
	meta := checks.QuarantineMeta{
		OriginalPath:          live,
		Owner:                 os.Getuid(),
		Group:                 os.Getgid(),
		Mode:                  "-rw-r--r--",
		RestoreAction:         checks.QuarantineRestoreRemoveIfUnchanged,
		ExpectedCurrentSHA256: restoreTestSHA256(patched),
	}
	metaJSON, _ := json.Marshal(meta)
	if err := os.WriteFile(itemPath+".meta", metaJSON, 0600); err != nil {
		t.Fatal(err)
	}

	s := newRestoreServer(t)
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": "pre_clean:" + id}))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if _, err := os.Lstat(live); !os.IsNotExist(err) {
		t.Fatalf("CSM-created .htaccess was not removed: %v", err)
	}
}

func TestApiQuarantineRestorePreservesEditToCSMCreatedHtaccess(t *testing.T) {
	tmp := t.TempDir()
	qdir := filepath.Join(tmp, "quarantine")
	preClean := filepath.Join(qdir, "pre_clean")
	restoreRoot := filepath.Join(tmp, "restore-target")
	if err := os.MkdirAll(preClean, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(restoreRoot, 0755); err != nil {
		t.Fatal(err)
	}
	withQuarantineDir(t, qdir)
	withQuarantineRestoreRoots(t, restoreRoot)

	id := "edited-new-htaccess"
	itemPath := filepath.Join(preClean, id)
	if err := os.WriteFile(itemPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(restoreRoot, ".htaccess")
	patched := []byte("Require all denied\n")
	customerEdit := append(append([]byte{}, patched...), []byte("# customer rule\n")...)
	if err := os.WriteFile(live, customerEdit, 0644); err != nil {
		t.Fatal(err)
	}
	meta := checks.QuarantineMeta{
		OriginalPath:          live,
		Owner:                 os.Getuid(),
		Group:                 os.Getgid(),
		Mode:                  "-rw-r--r--",
		RestoreAction:         checks.QuarantineRestoreRemoveIfUnchanged,
		ExpectedCurrentSHA256: restoreTestSHA256(patched),
	}
	metaJSON, _ := json.Marshal(meta)
	if err := os.WriteFile(itemPath+".meta", metaJSON, 0600); err != nil {
		t.Fatal(err)
	}

	s := newRestoreServer(t)
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": "pre_clean:" + id}))
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d body=%s", w.Code, w.Body.String())
	}
	if got, err := os.ReadFile(live); err != nil || string(got) != string(customerEdit) {
		t.Fatalf("customer edit changed during failed removal: %q, %v", got, err)
	}
	if _, err := os.Stat(itemPath); err != nil {
		t.Fatalf("rollback entry removed after conflict: %v", err)
	}
}

func TestApiQuarantineRestoreReplacesUnchangedVirtualPatch(t *testing.T) {
	tmp := t.TempDir()
	qdir := filepath.Join(tmp, "quarantine")
	preClean := filepath.Join(qdir, "pre_clean")
	restoreRoot := filepath.Join(tmp, "restore-target")
	if err := os.MkdirAll(preClean, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(restoreRoot, 0755); err != nil {
		t.Fatal(err)
	}
	withQuarantineDir(t, qdir)
	withQuarantineRestoreRoots(t, restoreRoot)

	id := "existing-htaccess"
	itemPath := filepath.Join(preClean, id)
	original := []byte("Options -Indexes\n")
	patched := append(append([]byte{}, original...), []byte("# BEGIN CSM exposed-file virtual-patch dump.sql\n<Files \"dump.sql\">\nRequire all denied\n</Files>\n# END CSM exposed-file virtual-patch dump.sql\n")...)
	if err := os.WriteFile(itemPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(restoreRoot, ".htaccess")
	if err := os.WriteFile(live, patched, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(live, 0600); err != nil {
		t.Fatal(err)
	}
	meta := checks.QuarantineMeta{
		OriginalPath:          live,
		Owner:                 os.Getuid(),
		Group:                 os.Getgid(),
		Mode:                  "-rw-------",
		RestoreAction:         checks.QuarantineRestoreReplaceIfUnchanged,
		ExpectedCurrentSHA256: restoreTestSHA256(patched),
	}
	metaJSON, _ := json.Marshal(meta)
	if err := os.WriteFile(itemPath+".meta", metaJSON, 0600); err != nil {
		t.Fatal(err)
	}

	s := newRestoreServer(t)
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": "pre_clean:" + id}))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if got, err := os.ReadFile(live); err != nil || string(got) != string(original) {
		t.Fatalf("restored .htaccess = %q, %v", got, err)
	}
	if info, err := os.Stat(live); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("restored mode = %v, %v", info, err)
	}
}

func TestApiQuarantineRestorePreservesPostPatchCustomerEdit(t *testing.T) {
	tmp := t.TempDir()
	qdir := filepath.Join(tmp, "quarantine")
	preClean := filepath.Join(qdir, "pre_clean")
	restoreRoot := filepath.Join(tmp, "restore-target")
	if err := os.MkdirAll(preClean, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(restoreRoot, 0755); err != nil {
		t.Fatal(err)
	}
	withQuarantineDir(t, qdir)
	withQuarantineRestoreRoots(t, restoreRoot)

	id := "changed-htaccess"
	itemPath := filepath.Join(preClean, id)
	if err := os.WriteFile(itemPath, []byte("original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(restoreRoot, ".htaccess")
	patched := []byte("patched\n")
	customerEdit := []byte("patched\n# customer update\n")
	if err := os.WriteFile(live, customerEdit, 0644); err != nil {
		t.Fatal(err)
	}
	meta := checks.QuarantineMeta{
		OriginalPath:          live,
		Owner:                 os.Getuid(),
		Group:                 os.Getgid(),
		Mode:                  "-rw-r--r--",
		RestoreAction:         checks.QuarantineRestoreReplaceIfUnchanged,
		ExpectedCurrentSHA256: restoreTestSHA256(patched),
	}
	metaJSON, _ := json.Marshal(meta)
	if err := os.WriteFile(itemPath+".meta", metaJSON, 0600); err != nil {
		t.Fatal(err)
	}

	s := newRestoreServer(t)
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": "pre_clean:" + id}))
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d body=%s", w.Code, w.Body.String())
	}
	if got, err := os.ReadFile(live); err != nil || string(got) != string(customerEdit) {
		t.Fatalf("customer edit changed during failed restore: %q, %v", got, err)
	}
	if _, err := os.Stat(itemPath); err != nil {
		t.Fatalf("backup removed after restore conflict: %v", err)
	}
}

// TestApiQuarantineRestorePreservesRequestedMode asserts the restored
// file ends at exactly the mode the metadata sidecar requested even
// under a hostile umask. Chmod must run before Chown so the new owner
// never observes a wider-than-intended mode mid-restore.
func TestApiQuarantineRestorePreservesRequestedMode(t *testing.T) {
	prev := syscall.Umask(0o077)
	defer syscall.Umask(prev)

	tmp := t.TempDir()
	qdir := filepath.Join(tmp, "quarantine")
	if err := os.MkdirAll(qdir, 0o700); err != nil {
		t.Fatal(err)
	}
	restoreRoot := filepath.Join(tmp, "restore-target")
	if err := os.MkdirAll(restoreRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	withQuarantineDir(t, qdir)
	withQuarantineRestoreRoots(t, restoreRoot)

	id := "20260527-120000_modecheck.txt"
	originalPath := filepath.Join(restoreRoot, "alice", "public_html", "modecheck.txt")
	if err := os.WriteFile(filepath.Join(qdir, id), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	meta := map[string]interface{}{
		"original_path": originalPath,
		"owner_uid":     os.Getuid(),
		"group_gid":     os.Getgid(),
		"mode":          "-rw-r--r--",
	}
	mj, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(qdir, id+".meta"), mj, 0o600); err != nil {
		t.Fatal(err)
	}

	s := newRestoreServer(t)
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	info, err := os.Stat(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o644); got != want {
		t.Errorf("restored mode = %o, want %o (umask should not bleed through)", got, want)
	}
}

func TestApiQuarantineRestoreRejectsDestinationReplacementDuringRestore(t *testing.T) {
	tmp := t.TempDir()
	qdir := filepath.Join(tmp, "quarantine")
	if err := os.MkdirAll(qdir, 0o700); err != nil {
		t.Fatal(err)
	}
	restoreRoot := filepath.Join(tmp, "restore-target")
	if err := os.MkdirAll(restoreRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	withQuarantineDir(t, qdir)
	withQuarantineRestoreRoots(t, restoreRoot)

	id := "20260527-120100_replace.txt"
	qitem := filepath.Join(qdir, id)
	qmeta := qitem + ".meta"
	originalPath := filepath.Join(restoreRoot, "alice", "public_html", "replace.txt")
	if err := os.WriteFile(qitem, []byte("quarantined"), 0o600); err != nil {
		t.Fatal(err)
	}
	meta := map[string]interface{}{
		"original_path": originalPath,
		"owner_uid":     os.Getuid(),
		"group_gid":     os.Getgid(),
		"mode":          "-rw-r--r--",
	}
	mj, _ := json.Marshal(meta)
	if err := os.WriteFile(qmeta, mj, 0o600); err != nil {
		t.Fatal(err)
	}
	withQuarantineRestoreAfterCreateHook(t, func(path string) {
		if err := os.Remove(path); err != nil {
			t.Fatalf("remove just-created restore path: %v", err)
		}
		if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
			t.Fatalf("write replacement restore path: %v", err)
		}
	})

	s := newRestoreServer(t)
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 for replaced destination, got %d body=%s", w.Code, w.Body.String())
	}
	got, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "replacement" {
		t.Fatalf("replacement file changed: got %q", got)
	}
	info, err := os.Stat(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Errorf("replacement mode = %o, want %o", got, want)
	}
	if _, err := os.Stat(qitem); err != nil {
		t.Errorf("quarantined file should remain after failed restore: %v", err)
	}
	if _, err := os.Stat(qmeta); err != nil {
		t.Errorf("metadata should remain after failed restore: %v", err)
	}
}

func TestApiQuarantineRestoreConflictWhenDestinationExists(t *testing.T) {
	tmp := t.TempDir()
	qdir := filepath.Join(tmp, "quarantine")
	restoreRoot := filepath.Join(tmp, "restore-target")
	if err := os.MkdirAll(qdir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(restoreRoot, 0755); err != nil {
		t.Fatal(err)
	}
	withQuarantineDir(t, qdir)
	withQuarantineRestoreRoots(t, restoreRoot)

	id := "20260415-120001_taken.txt"
	originalPath := filepath.Join(restoreRoot, "bob", "taken.txt")
	if err := os.MkdirAll(filepath.Dir(originalPath), 0755); err != nil {
		t.Fatal(err)
	}
	// Pre-existing destination — restore must refuse to overwrite.
	if err := os.WriteFile(originalPath, []byte("original survivor"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(qdir, id), []byte("quarantined"), 0600); err != nil {
		t.Fatal(err)
	}
	meta := map[string]interface{}{
		"original_path": originalPath,
		"owner_uid":     os.Getuid(),
		"group_gid":     os.Getgid(),
		"mode":          "-rw-r--r--",
	}
	mj, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(qdir, id+".meta"), mj, 0600); err != nil {
		t.Fatal(err)
	}

	s := newRestoreServer(t)
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
	if w.Code != http.StatusConflict {
		t.Errorf("expected 409 when destination exists, got %d body=%s", w.Code, w.Body.String())
	}
	// Original file must still be intact.
	got, _ := os.ReadFile(originalPath)
	if string(got) != "original survivor" {
		t.Errorf("destination file should be untouched, got %q", got)
	}
}
