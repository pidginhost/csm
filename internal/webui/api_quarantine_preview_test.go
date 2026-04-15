package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withQuarantineDir redirects the package-level quarantineDir to a temp
// location for the duration of the test, restoring it on cleanup.
func withQuarantineDir(t *testing.T, dir string) {
	t.Helper()
	old := quarantineDir
	quarantineDir = dir
	t.Cleanup(func() { quarantineDir = old })
}

func newPreviewRequest(id string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/quarantine/preview?id="+id, nil)
	return r
}

func TestApiQuarantinePreviewMissingIDReturnsBadRequest(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	s.apiQuarantinePreview(w, newPreviewRequest(""))
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestApiQuarantinePreviewInvalidIDReturnsBadRequest(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	// resolveQuarantineEntry rejects "." and ".." — traversal defence.
	s.apiQuarantinePreview(w, newPreviewRequest(".."))
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for traversal id, got %d", w.Code)
	}
}

func TestApiQuarantinePreviewNotFoundReturns404(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineDir(t, tmp)

	s := &Server{}
	w := httptest.NewRecorder()
	s.apiQuarantinePreview(w, newPreviewRequest("missing.dat"))
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for missing file, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestApiQuarantinePreviewReturnsFileContents(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineDir(t, tmp)

	id := "20260415-120000_test.php"
	payload := []byte("<?php echo 'some content'; ?>")
	if err := os.WriteFile(filepath.Join(tmp, id), payload, 0600); err != nil {
		t.Fatal(err)
	}

	s := &Server{}
	w := httptest.NewRecorder()
	s.apiQuarantinePreview(w, newPreviewRequest(id))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		ID        string `json:"id"`
		Preview   string `json:"preview"`
		Truncated bool   `json:"truncated"`
		TotalSize int64  `json:"total_size"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if got.ID != id {
		t.Errorf("id field mismatch: got %q", got.ID)
	}
	if !strings.Contains(got.Preview, "some content") {
		t.Errorf("preview should contain file content, got %q", got.Preview)
	}
	if got.Truncated {
		t.Errorf("small file should not be truncated, got truncated=%v", got.Truncated)
	}
	if got.TotalSize != int64(len(payload)) {
		t.Errorf("total_size = %d, want %d", got.TotalSize, len(payload))
	}
}

func TestApiQuarantinePreviewTruncatesLargeFile(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineDir(t, tmp)

	id := "20260415-120001_big.bin"
	big := make([]byte, 16*1024) // 16KB — handler reads only first 8KB
	for i := range big {
		big[i] = 'A'
	}
	if err := os.WriteFile(filepath.Join(tmp, id), big, 0600); err != nil {
		t.Fatal(err)
	}

	s := &Server{}
	w := httptest.NewRecorder()
	s.apiQuarantinePreview(w, newPreviewRequest(id))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var got struct {
		Preview   string `json:"preview"`
		Truncated bool   `json:"truncated"`
		TotalSize int64  `json:"total_size"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if !got.Truncated {
		t.Errorf("16KB file should be marked truncated")
	}
	if got.TotalSize != int64(len(big)) {
		t.Errorf("total_size = %d, want %d", got.TotalSize, len(big))
	}
	// Preview should be exactly 8192 bytes (the handler's read buffer).
	if len(got.Preview) != 8192 {
		t.Errorf("preview length = %d, want 8192", len(got.Preview))
	}
}

func TestApiQuarantinePreviewDirectoryEntry(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineDir(t, tmp)

	id := "20260415-120002_LEVIATHAN"
	if err := os.MkdirAll(filepath.Join(tmp, id), 0700); err != nil {
		t.Fatal(err)
	}

	s := &Server{}
	w := httptest.NewRecorder()
	s.apiQuarantinePreview(w, newPreviewRequest(id))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var got struct {
		IsDir   bool   `json:"is_dir"`
		Preview string `json:"preview"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if !got.IsDir {
		t.Errorf("quarantined directory should have is_dir=true")
	}
	if !strings.Contains(got.Preview, "directory") {
		t.Errorf("preview should mention it's a directory, got %q", got.Preview)
	}
}
