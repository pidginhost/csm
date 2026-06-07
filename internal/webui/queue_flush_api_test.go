package webui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/mailfwd/intel"
	"github.com/pidginhost/csm/internal/platform"
)

type fakeQueueFlusher struct {
	res   intel.FlushResult
	err   error
	calls int
}

func (f *fakeQueueFlusher) FlushBackscatter() (intel.FlushResult, error) {
	f.calls++
	return f.res, f.err
}

func TestSelectQueueFlusherUnavailableOffCPanel(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	panel := platform.PanelNone
	if !platform.SetOverrides(platform.Overrides{Panel: &panel}) {
		t.Fatal("platform override rejected before Detect")
	}

	if got := selectQueueFlusher(); got != nil {
		t.Fatalf("selectQueueFlusher returned %T, want nil off cPanel", got)
	}
}

func TestSelectQueueFlusherUsesEximOnCPanel(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	panel := platform.PanelCPanel
	if !platform.SetOverrides(platform.Overrides{Panel: &panel}) {
		t.Fatal("platform override rejected before Detect")
	}

	if _, ok := selectQueueFlusher().(*intel.EximQueueFlusher); !ok {
		t.Fatalf("selectQueueFlusher returned %T, want *EximQueueFlusher", selectQueueFlusher())
	}
}

func TestApiEmailFlushBackscatterSuccess(t *testing.T) {
	s := newTestServer(t, "tok")
	s.queueFlusher = &fakeQueueFlusher{res: intel.FlushResult{Removed: 3}}

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
	flusher := &fakeQueueFlusher{}
	s.queueFlusher = flusher

	w := httptest.NewRecorder()
	s.apiEmailFlushBackscatter(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/queue/flush-backscatter", nil))

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
	if flusher.calls != 0 {
		t.Fatalf("GET called flusher %d time(s), want 0", flusher.calls)
	}
}

func TestApiEmailFlushBackscatterReporterError(t *testing.T) {
	s := newTestServer(t, "tok")
	s.queueFlusher = &fakeQueueFlusher{err: errForwarderTest}

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

func TestApiEmailFlushBackscatterRouteRequiresCSRF(t *testing.T) {
	const tok = "tok"
	s := newTestServer(t, tok)
	flusher := &fakeQueueFlusher{res: intel.FlushResult{Removed: 1}}
	s.queueFlusher = flusher

	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/queue/flush-backscatter", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "csm_auth", Value: tok})
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if flusher.calls != 0 {
		t.Fatalf("POST without CSRF called flusher %d time(s), want 0", flusher.calls)
	}
}

func TestApiEmailFlushBackscatterRouteGetDoesNotFlush(t *testing.T) {
	const tok = "tok"
	s := newTestServer(t, tok)
	flusher := &fakeQueueFlusher{res: intel.FlushResult{Removed: 1}}
	s.queueFlusher = flusher

	req := httptest.NewRequest(http.MethodGet, "/api/v1/email/queue/flush-backscatter", nil)
	req.AddCookie(&http.Cookie{Name: "csm_auth", Value: tok})
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
	if flusher.calls != 0 {
		t.Fatalf("GET called flusher %d time(s), want 0", flusher.calls)
	}
}
