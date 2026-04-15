package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
