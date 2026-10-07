package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func bearerReq(path, token, remote string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.RemoteAddr = remote
	return r
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
}

// A wrong bearer token is a credential guess like a wrong login form, so both
// spend the same per-client budget and a spent budget holds both off.
func TestFailedBearerTokensShareTheLoginBudget(t *testing.T) {
	s := newTestServer(t, "tok")
	h := s.requireAuth(okHandler())
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, bearerReq("/api/v1/status", "wrong", "203.0.113.9:4000"))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i+1, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("/api/v1/status", "wrong", "203.0.113.9:4001"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("sixth wrong token = %d, want 429", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("/api/v1/status", "tok", "203.0.113.9:4002"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("right token from a blocked client = %d, want 429 (no oracle while blocked)", w.Code)
	}

	login := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("token=tok"))
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	login.RemoteAddr = "203.0.113.9:5000"
	w = httptest.NewRecorder()
	s.handleLogin(w, login)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("login form from a client that guessed tokens = %d, want 429", w.Code)
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("/api/v1/status", "tok", "203.0.113.10:4000"))
	if w.Code != http.StatusOK {
		t.Fatalf("another client = %d, want 200", w.Code)
	}
}

func TestValidBearerRequestsDoNotSpendTheCredentialBudget(t *testing.T) {
	s := newTestServer(t, "tok")
	h := s.requireAuth(okHandler())
	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, bearerReq("/api/v1/status", "tok", "203.0.113.11:4000"))
		if w.Code != http.StatusOK {
			t.Fatalf("valid request %d = %d, want 200", i+1, w.Code)
		}
	}
}

func TestRequestsWithoutABearerTokenAreNotCountedAsGuesses(t *testing.T) {
	s := newTestServer(t, "tok")
	h := s.requireAuth(okHandler())
	for i := 0; i < 10; i++ {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		r.RemoteAddr = "203.0.113.12:4000"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous request %d = %d, want 401", i+1, w.Code)
		}
	}
}

func TestRequireReadCountsFailedBearerTokens(t *testing.T) {
	s := newTestServer(t, "tok")
	h := s.requireRead(okHandler())
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, bearerReq("/api/v1/status", "wrong", "203.0.113.13:4000"))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i+1, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("/api/v1/status", "wrong", "203.0.113.13:4000"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("sixth wrong token = %d, want 429", w.Code)
	}
}

func TestMetricsCountsFailedBearerTokens(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.WebUI.MetricsToken = "metrics-secret-value-0123456789abcdef"
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		s.handleMetrics(w, bearerReq("/metrics", "wrong", "203.0.113.14:4000"))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i+1, w.Code)
		}
	}
	w := httptest.NewRecorder()
	s.handleMetrics(w, bearerReq("/metrics", "wrong", "203.0.113.14:4000"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("sixth wrong metrics token = %d, want 429", w.Code)
	}
}

// A real token used outside its scope is an authorization refusal, not a
// guess; counting it would lock a read-only client out of its own routes.
func TestKnownTokenOutsideItsScopeIsNotAGuess(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.WebUI.Tokens = append(s.cfg.WebUI.Tokens, config.WebUIToken{Name: "ro", Token: "reader-token-value", Scope: "read"})
	h := s.requireAuth(okHandler())
	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, bearerReq("/api/v1/settings/alerts", "reader-token-value", "203.0.113.15:4000"))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("read token on admin route, attempt %d = %d, want 401", i+1, w.Code)
		}
	}
	w := httptest.NewRecorder()
	s.requireRead(okHandler()).ServeHTTP(w, bearerReq("/api/v1/status", "reader-token-value", "203.0.113.15:4000"))
	if w.Code != http.StatusOK {
		t.Fatalf("read token on its own route after scope refusals = %d, want 200", w.Code)
	}
}
