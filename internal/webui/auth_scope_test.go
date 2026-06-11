package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestRequireScope_AllowsAdminEverywhere(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	s.cfg.WebUI.Tokens = []config.WebUIToken{{Name: "a", Token: "admin-tok", Scope: "admin"}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	req.Header.Set("Authorization", "Bearer admin-tok")
	if !s.tokenHasScope(req, "read") {
		t.Fatal("admin should have read scope")
	}
	if !s.tokenHasScope(req, "admin") {
		t.Fatal("admin should have admin scope")
	}
}

func TestRequireScope_ReadDeniesAdmin(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	s.cfg.WebUI.Tokens = []config.WebUIToken{{Name: "p", Token: "read-tok", Scope: "read"}}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer read-tok")
	if !s.tokenHasScope(req, "read") {
		t.Fatal("read token should pass read")
	}
	if s.tokenHasScope(req, "admin") {
		t.Fatal("read token must not satisfy admin")
	}
}

func TestRequireScope_UnknownTokenFails(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	s.cfg.WebUI.Tokens = []config.WebUIToken{{Name: "a", Token: "x", Scope: "admin"}}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer wrong-tok")
	if s.tokenHasScope(req, "read") {
		t.Fatal("unknown token must not have read scope")
	}
}

func TestRequireScope_EmptyConfiguredTokenDoesNotAuthenticate(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	s.cfg.WebUI.Tokens = []config.WebUIToken{{Name: "bad", Token: "", Scope: "admin"}}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer ")
	if s.tokenHasScope(req, "read") {
		t.Fatal("empty bearer must not match an empty configured token")
	}
	req.AddCookie(&http.Cookie{Name: "csm_auth", Value: ""})
	if s.tokenHasScope(req, "admin") {
		t.Fatal("empty cookie must not match an empty configured token")
	}
}

func TestCSRFSecretUsesAdminScopedToken(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	s.cfg.WebUI.Tokens = []config.WebUIToken{
		{Name: "read", Token: "read-secret", Scope: "read"},
		{Name: "admin", Token: "admin-secret", Scope: "admin"},
	}
	if got := s.csrfSecret(); got != "admin-secret" {
		t.Fatalf("csrfSecret = %q, want admin token", got)
	}
}

func TestCSRFSecretIgnoresLegacyAuthTokenWhenScopedTokensConfigured(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	s.cfg.WebUI.AuthToken = "rotated-legacy-secret"
	s.cfg.WebUI.Tokens = []config.WebUIToken{
		{Name: "read", Token: "read-secret", Scope: "read"},
		{Name: "admin", Token: "admin-secret", Scope: "admin"},
	}
	if got := s.csrfSecret(); got != "admin-secret" {
		t.Fatalf("csrfSecret = %q, want active admin token", got)
	}

	s.cfg.WebUI.Tokens = []config.WebUIToken{{Name: "read", Token: "read-secret", Scope: "read"}}
	if got := s.csrfSecret(); got != "" {
		t.Fatalf("csrfSecret with no active admin token = %q, want empty", got)
	}
}

func TestRequireReadRejectsWriteMethods(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	s.cfg.WebUI.Tokens = []config.WebUIToken{{Name: "read", Token: "read-secret", Scope: "read"}}
	called := false
	handler := s.requireRead(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer read-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if called {
		t.Fatal("write method reached read-scope handler")
	}
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code = %d, want 405", rec.Code)
	}
}

func TestRequireCSRFDoesNotLetReadBearerBypassAdminCookie(t *testing.T) {
	s := newTestServer(t, "")
	s.cfg.WebUI.Tokens = []config.WebUIToken{
		{Name: "admin", Token: "admin-secret", Scope: "admin"},
		{Name: "read", Token: "read-secret", Scope: "read"},
	}
	called := false
	handler := s.requireAuth(s.requireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})))

	req := httptest.NewRequest(http.MethodPut, "/api/v1/prefs/user", nil)
	req.AddCookie(&http.Cookie{Name: "csm_auth", Value: "admin-secret"})
	req.Header.Set("Authorization", "Bearer read-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if called {
		t.Fatal("handler ran without CSRF")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
}

func TestRequireScope_LegacyAuthTokenStillWorks(t *testing.T) {
	// Backward compat: a config with only the legacy auth_token (migrated by
	// applyDefaults into Tokens) must still authenticate.
	s := &Server{cfg: &config.Config{}}
	s.cfg.WebUI.AuthToken = "legacy"
	s.cfg.WebUI.Tokens = []config.WebUIToken{{Name: "legacy-auth-token", Token: "legacy", Scope: "admin"}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	req.Header.Set("Authorization", "Bearer legacy")
	if !s.tokenHasScope(req, "admin") {
		t.Fatal("migrated legacy token should authorize admin")
	}
	if !s.tokenHasScope(req, "read") {
		t.Fatal("migrated legacy token should authorize read")
	}
}
