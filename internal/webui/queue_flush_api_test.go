package webui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/mailfwd/intel"
)

type fakeQueueFlusher struct {
	res intel.FlushResult
	err error
}

func (f fakeQueueFlusher) FlushBackscatter() (intel.FlushResult, error) { return f.res, f.err }

func TestApiEmailFlushBackscatterSuccess(t *testing.T) {
	s := newTestServer(t, "tok")
	s.queueFlusher = fakeQueueFlusher{res: intel.FlushResult{Removed: 3}}

	w := httptest.NewRecorder()
	s.apiEmailFlushBackscatter(w, httptest.NewRequest(http.MethodPost, "/api/v1/email/queue/flush-backscatter", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"removed": 3`) {
		t.Errorf("body missing removed count: %s", w.Body.String())
	}

	// The action must be audit-logged.
	data, _ := os.ReadFile(filepath.Join(s.cfg.StatePath, uiAuditFile))
	if !strings.Contains(string(data), "flush") {
		t.Errorf("flush action not audit-logged; audit=%q", string(data))
	}
}

func TestApiEmailFlushBackscatterMethodNotAllowed(t *testing.T) {
	s := newTestServer(t, "tok")
	s.queueFlusher = intel.EmptyQueueFlusher{}

	w := httptest.NewRecorder()
	s.apiEmailFlushBackscatter(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/queue/flush-backscatter", nil))

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

func TestApiEmailFlushBackscatterReporterError(t *testing.T) {
	s := newTestServer(t, "tok")
	s.queueFlusher = fakeQueueFlusher{err: errForwarderTest}

	w := httptest.NewRecorder()
	s.apiEmailFlushBackscatter(w, httptest.NewRequest(http.MethodPost, "/api/v1/email/queue/flush-backscatter", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestApiEmailFlushBackscatterNotConfigured(t *testing.T) {
	s := newTestServer(t, "tok")
	s.queueFlusher = nil

	w := httptest.NewRecorder()
	s.apiEmailFlushBackscatter(w, httptest.NewRequest(http.MethodPost, "/api/v1/email/queue/flush-backscatter", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}
