package webui

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/mailfwd/intel"
)

// A flush that deleted mail and then reported an error still deleted mail.
// Skipping the audit record in that path left a destructive action with no
// forensic trail, which is exactly what happened in production: two frozen
// messages were removed and nothing recorded it.
func TestApiEmailFlushBackscatterAuditsPartialRemoval(t *testing.T) {
	s := newTestServer(t, "tok")
	s.queueFlusher = &fakeQueueFlusher{
		res: intel.FlushResult{Removed: 2, Targeted: 3},
		err: errors.New("1 of 3 frozen backscatter messages still queued after removal"),
	}

	w := httptest.NewRecorder()
	s.apiEmailFlushBackscatter(w, httptest.NewRequest(http.MethodPost, "/api/v1/email/queue/flush-backscatter", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}

	data, err := os.ReadFile(filepath.Join(s.cfg.StatePath, uiAuditFile))
	if err != nil {
		t.Fatalf("audit log unreadable: %v", err)
	}
	var entry UIAuditEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("audit log contains invalid JSON: %v", err)
	}
	if entry.Action != "email_flush_backscatter" {
		t.Fatalf("audit action = %q, want email_flush_backscatter", entry.Action)
	}
	const wantDetails = "removal requested for 3 frozen null-sender message(s); 2 confirmed no longer queued afterward"
	if entry.Details != wantDetails {
		t.Fatalf("audit details = %q, want %q", entry.Details, wantDetails)
	}
}

func TestApiEmailFlushBackscatterAuditsUnconfirmedRemovalAttempt(t *testing.T) {
	s := newTestServer(t, "tok")
	s.queueFlusher = &fakeQueueFlusher{
		res: intel.FlushResult{Targeted: 1},
		err: errors.New("removal could not be confirmed: queue re-read failed"),
	}

	w := httptest.NewRecorder()
	s.apiEmailFlushBackscatter(w, httptest.NewRequest(http.MethodPost, "/api/v1/email/queue/flush-backscatter", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	data, err := os.ReadFile(filepath.Join(s.cfg.StatePath, uiAuditFile))
	if err != nil {
		t.Fatalf("audit log unreadable: %v", err)
	}
	var entry UIAuditEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("audit log contains invalid JSON: %v", err)
	}
	if entry.Action != "email_flush_backscatter" {
		t.Fatalf("audit action = %q, want email_flush_backscatter", entry.Action)
	}
	const wantDetails = "removal requested for 1 frozen null-sender message(s); 0 confirmed no longer queued afterward"
	if entry.Details != wantDetails {
		t.Fatalf("audit details = %q, want %q", entry.Details, wantDetails)
	}
}

// The operator needs the underlying reason, not a fixed string. The
// original handler discarded the error entirely, so a failed flush was
// indistinguishable from any other failure.
func TestApiEmailFlushBackscatterSurfacesUnderlyingError(t *testing.T) {
	s := newTestServer(t, "tok")
	s.queueFlusher = &fakeQueueFlusher{err: errors.New("exim unavailable: no such file")}

	w := httptest.NewRecorder()
	s.apiEmailFlushBackscatter(w, httptest.NewRequest(http.MethodPost, "/api/v1/email/queue/flush-backscatter", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	if !strings.Contains(w.Body.String(), "exim unavailable") {
		t.Fatalf("response must carry the underlying reason; body=%s", w.Body.String())
	}
}

// A clean flush that removed nothing must not write an audit record for a
// deletion that did not happen.
func TestApiEmailFlushBackscatterNoAuditWhenNothingRemoved(t *testing.T) {
	s := newTestServer(t, "tok")
	s.queueFlusher = &fakeQueueFlusher{res: intel.FlushResult{Removed: 0}}

	w := httptest.NewRecorder()
	s.apiEmailFlushBackscatter(w, httptest.NewRequest(http.MethodPost, "/api/v1/email/queue/flush-backscatter", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	data, _ := os.ReadFile(filepath.Join(s.cfg.StatePath, uiAuditFile))
	if strings.Contains(string(data), "email_flush_backscatter") {
		t.Fatalf("no mail was deleted, so nothing should be audited; audit=%q", string(data))
	}
}
