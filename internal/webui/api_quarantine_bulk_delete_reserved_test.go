package webui

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Quarantine IDs are basenames under the quarantine root, and the root also
// holds the pre_clean and email subtrees. An ID naming one of those resolved
// to the subtree itself and bulk delete removed it whole. Only entries with
// a metadata sidecar are deletable, and reserved names are never entries.
func TestQuarantineBulkDeleteNeverRemovesReservedSubtrees(t *testing.T) {
	dir := t.TempDir()
	old := quarantineDir
	quarantineDir = dir
	t.Cleanup(func() { quarantineDir = old })
	for _, sub := range []string{"pre_clean", "email"} {
		if err := os.MkdirAll(filepath.Join(dir, sub, "keep"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	item := filepath.Join(dir, "20260902-100000__home_alice_public_html_shell.php")
	if err := os.WriteFile(item, []byte("<?php"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(item+".meta", []byte(`{"original_path":"/home/alice/public_html/shell.php"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(dir, "no-sidecar.bin")
	if err := os.WriteFile(stray, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := newTestServer(t, "tok")
	body := `{"ids":["pre_clean","email","no-sidecar.bin","` + filepath.Base(item) + `"]}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineBulkDelete(w, req)
	if w.Code != 200 {
		t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
	}
	for _, sub := range []string{"pre_clean", "email"} {
		if _, err := os.Stat(filepath.Join(dir, sub, "keep")); err != nil {
			t.Fatalf("reserved subtree %s was removed by bulk delete", sub)
		}
	}
	if _, err := os.Stat(stray); err != nil {
		t.Fatal("file without a metadata sidecar was removed")
	}
	if _, err := os.Stat(item); !os.IsNotExist(err) {
		t.Fatal("the real quarantine entry was not removed")
	}
}
