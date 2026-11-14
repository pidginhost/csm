package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

// ---------------------------------------------------------------------------
// topMailSenders — file absent returns nil (exercises early-return branch).
// The function reads /var/log/exim_mainlog which typically doesn't exist on
// dev machines. This gives us coverage for the os.Open error branch.
// ---------------------------------------------------------------------------

func TestTopMailSenders_NoLog(t *testing.T) {
	got := topMailSenders(500, 10)
	if _, err := os.Stat(platform.EximMainLog); err != nil {
		// No log to read: no senders, not an empty list.
		if got != nil {
			t.Fatalf("topMailSenders with no log = %+v, want nil", got)
		}
		return
	}
	// A host with a log: at most topK senders, busiest first.
	if len(got) > 10 {
		t.Fatalf("topMailSenders returned %d senders, want at most 10", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Count < got[i].Count {
			t.Fatalf("senders not sorted by count: %+v", got)
		}
	}
}

// ---------------------------------------------------------------------------
// apiAccounts — no /home or empty /home path.
// ---------------------------------------------------------------------------

func TestAPIAccountsNoHome(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiAccounts(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	// Expect an items list, never null. On dev machines without /home, items
	// is either [] or a list of directory entries. Both are valid.
	var accounts []interface{}
	decodeItems(t, w.Body.Bytes(), &accounts)
}

// ---------------------------------------------------------------------------
// apiQuarantineRestore — invalid JSON body returns 400.
// ---------------------------------------------------------------------------

func TestAPIQuarantineRestoreInvalidJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{bogus json`))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineRestore(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON = %d, want 400", w.Code)
	}
}

func TestAPIQuarantineRestoreEmptyObjectRejected(t *testing.T) {
	// JSON body with no ID field → empty string → rejected.
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"other":"field"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineRestore(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty id = %d, want 400", w.Code)
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] == "" {
		t.Errorf("expected error field, got %+v", resp)
	}
}

func TestAPIQuarantineRestoreSlashID(t *testing.T) {
	// IDs with path separators get resolved to basename, which then targets
	// /opt/csm/quarantine/<base>.meta — likely missing → 404.
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"id":"subdir/file"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineRestore(w, req)
	if w.Code != http.StatusNotFound && w.Code != http.StatusBadRequest {
		t.Errorf("slash in id = %d, want 404 or 400", w.Code)
	}
}

// ---------------------------------------------------------------------------
// apiQuarantineRestore — pre_clean: prefix ID resolution.
// ---------------------------------------------------------------------------

func TestAPIQuarantineRestorePreCleanPrefix(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"id":"pre_clean:nonexistent_entry"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineRestore(w, req)
	// The pre_clean branch of resolveQuarantineEntry resolves but then meta
	// file won't exist on disk → 404.
	if w.Code != http.StatusNotFound {
		t.Errorf("pre_clean prefix = %d, want 404", w.Code)
	}
}
