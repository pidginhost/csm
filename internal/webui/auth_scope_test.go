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
