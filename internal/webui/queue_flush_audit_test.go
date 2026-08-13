package webui

import (
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
		res: intel.FlushResult{Removed: 2},
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
	audit := string(data)
	if !strings.Contains(audit, "email_flush_backscatter") {
		t.Fatalf("deleted mail was not audit-logged; audit=%q", audit)
	}
	if !strings.Contains(audit, "2") {
		t.Fatalf("audit record must state how many messages were removed; audit=%q", audit)
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
