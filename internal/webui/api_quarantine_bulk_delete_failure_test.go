package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A quarantined file that cannot be deleted must keep its metadata sidecar.
// Without it the list, which is built from sidecars, no longer shows the
// archive, so it can neither be deleted again nor restored from the UI.
func TestQuarantineBulkDeleteKeepsMetadataWhenDeletionFails(t *testing.T) {
	dir := t.TempDir()
	withQuarantineDir(t, dir)
	stuck := filepath.Join(dir, "20260902-100000__home_alice_public_html_stuck.php")
	gone := filepath.Join(dir, "20260902-100001__home_alice_public_html_gone.php")
	for _, item := range []string{stuck, gone} {
		if err := os.WriteFile(item, []byte("<?php"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(item+".meta", []byte(`{"original_path":"/home/alice/public_html/x.php"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := removeQuarantineItem
	t.Cleanup(func() { removeQuarantineItem = old })
	removeQuarantineItem = func(path string) error {
		if path == stuck {
			return &os.PathError{Op: "unlinkat", Path: path, Err: syscall.EBUSY}
		}
		return old(path)
	}

	s := newTestServer(t, "tok")
	body := `{"ids":["` + filepath.Base(stuck) + `","` + filepath.Base(gone) + `"]}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineBulkDelete(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
	}
	var resp struct {
		Count  int      `json:"count"`
		Failed []string `json:"failed"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Count != 1 {
		t.Errorf("count = %d, want 1", resp.Count)
	}
	if len(resp.Failed) != 1 || resp.Failed[0] != filepath.Base(stuck) {
		t.Errorf("failed = %v, want the stuck entry", resp.Failed)
	}
	if _, err := os.Stat(stuck + ".meta"); err != nil {
		t.Fatalf("metadata of an undeleted archive was removed: %v", err)
	}
	if _, err := os.Stat(gone + ".meta"); !os.IsNotExist(err) {
		t.Fatalf("metadata of a deleted archive was kept: %v", err)
	}
}
