package webui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// Every HTML page needs an admin credential; a read-only token gets the
// login page. The layout therefore has no read-only variant of the nav.
func TestHTMLPagesRequireAdminScope(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.WebUI.UIDir = "../../ui"
	cfg.WebUI.Tokens = []config.WebUIToken{
		{Name: "admin", Token: "admin-secret", Scope: "admin"},
		{Name: "reader", Token: "read-secret", Scope: "read"},
	}
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s, err := New(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	if !s.HasUI() {
		t.Fatal("the UI templates did not load")
	}
	pages := []string{
		"/", "/dashboard", "/findings", "/history", "/quarantine", "/cleanup-history", "/blocked",
		"/firewall", "/threat", "/rules", "/audit", "/account", "/incident", "/email",
		"/performance", "/hardening", "/settings", "/sessions", "/modsec", "/modsec/rules",
		"/verified-bots",
	}
	for _, path := range pages {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer read-secret")
		w := httptest.NewRecorder()
		s.httpSrv.Handler.ServeHTTP(w, req)
		if w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
			t.Errorf("%s with a read-only token: status %d, location %q; want the login page", path, w.Code, w.Header().Get("Location"))
		}
	}
}
