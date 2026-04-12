package webui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// --- handleLogin ------------------------------------------------------

func TestHandleLoginGETRendersPage(t *testing.T) {
	s := newTestServerWithTemplates(t, "test-secret")
	w := httptest.NewRecorder()
	s.handleLogin(w, httptest.NewRequest("GET", "/login", nil))
	if w.Code != http.StatusOK {
		t.Errorf("GET login = %d, want 200", w.Code)
	}
}

func TestHandleLoginPOSTSuccess(t *testing.T) {
	s := newTestServerWithTemplates(t, "test-secret")
	form := url.Values{"token": {"test-secret"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleLogin(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("successful login = %d, want 302", w.Code)
	}
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "csm_auth" && c.Value == "test-secret" {
			found = true
		}
	}
	if !found {
		t.Error("csm_auth cookie not set")
	}
}

func TestHandleLoginPOSTBadToken(t *testing.T) {
	s := newTestServerWithTemplates(t, "test-secret")
	form := url.Values{"token": {"wrong-token"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleLogin(w, req)

	// Bad token re-renders login with error (200 OK, not redirect)
	if w.Code != http.StatusOK {
		t.Errorf("bad token = %d, want 200", w.Code)
	}
}

func TestHandleLoginDeleteRejected(t *testing.T) {
	s := newTestServerWithTemplates(t, "test-secret")
	w := httptest.NewRecorder()
	s.handleLogin(w, httptest.NewRequest("DELETE", "/login", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE login = %d, want 405", w.Code)
	}
}

func TestHandleLoginAlreadyAuthenticated(t *testing.T) {
	s := newTestServerWithTemplates(t, "test-secret")
	req := httptest.NewRequest("GET", "/login", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	w := httptest.NewRecorder()
	s.handleLogin(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("authenticated user = %d, want redirect 302", w.Code)
	}
}

func TestHandleLoginRateLimit(t *testing.T) {
	s := newTestServerWithTemplates(t, "test-secret")
	// Exhaust 5 attempts
	for i := 0; i < 5; i++ {
		form := url.Values{"token": {"wrong"}}
		req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "203.0.113.5:1234"
		w := httptest.NewRecorder()
		s.handleLogin(w, req)
	}
	// 6th attempt should be rate-limited
	form := url.Values{"token": {"wrong"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.5:1234"
	w := httptest.NewRecorder()
	s.handleLogin(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("rate-limited = %d, want 429", w.Code)
	}
}

// --- securityHeaders --------------------------------------------------

func TestSecurityHeadersSet(t *testing.T) {
	s := newTestServer(t, "tok")
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := s.securityHeaders(inner)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	headers := map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"X-XSS-Protection":       "1; mode=block",
	}
	for key, want := range headers {
		if got := w.Header().Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

// pruneLoginAttempts is a blocking goroutine (runs on a ticker) — not testable directly.
