package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

func addPolicyToken(s *Server, tok config.WebUIToken) {
	if tok.IssuedAt == "" {
		tok.IssuedAt = time.Now().UTC().Format(time.RFC3339)
	}
	s.cfg.WebUI.Tokens = append(s.cfg.WebUI.Tokens, tok)
}

// An unban token reaches the two routes an account panel needs and nothing
// else: no other firewall route, no read route, no browser login.
func TestUnbanScopeReachesOnlyCheckAndUnban(t *testing.T) {
	s := newUIServer(t)
	unban := randomBrowserCredential()
	addPolicyToken(s, config.WebUIToken{Name: "panel", Token: unban, Scope: "unban"})
	serve := func(method, path, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+unban)
		w := httptest.NewRecorder()
		s.httpSrv.Handler.ServeHTTP(w, req)
		return w.Code
	}
	// An invalid address reaches the handler, which answers 400; auth and
	// CSRF failures would answer 401 or 403 first.
	if got := serve(http.MethodGet, "/api/v1/firewall/check?ip=bad", ""); got != http.StatusBadRequest {
		t.Errorf("check = %d, want 400 from the handler", got)
	}
	if got := serve(http.MethodPost, "/api/v1/firewall/unban", `{"ip":"bad"}`); got != http.StatusBadRequest {
		t.Errorf("unban = %d, want 400 from the handler", got)
	}
	// Use the complete registration inventory, including method-qualified
	// patterns and registrations outside server.go.
	for _, route := range registeredAPIRoutes(t) {
		method := strings.ToUpper(route.Method)
		want := http.StatusUnauthorized
		if (route.Path == "/api/v1/firewall/check" && method == http.MethodGet) ||
			(route.Path == "/api/v1/firewall/unban" && method == http.MethodPost) {
			want = http.StatusBadRequest
		}
		for _, rawCookie := range []bool{false, true} {
			req := httptest.NewRequest(method, route.Path+"?ip=bad", strings.NewReader(`{"ip":"bad"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+unban)
			if rawCookie {
				req.AddCookie(&http.Cookie{Name: "csm_auth", Value: unban})
			}
			w := httptest.NewRecorder()
			s.httpSrv.Handler.ServeHTTP(w, req)
			if w.Code != want {
				t.Errorf("%s %s (raw cookie=%v) = %d, want %d", method, route.Path, rawCookie, w.Code, want)
			}
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		if got := serve(method, "/metrics", ""); got != http.StatusUnauthorized {
			t.Errorf("%s /metrics = %d, want 401", method, got)
		}
	}
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/firewall/check"},
		{http.MethodHead, "/api/v1/firewall/check"},
		{http.MethodGet, "/api/v1/firewall/unban"},
		{http.MethodDelete, "/api/v1/firewall/unban"},
	} {
		if got := serve(route.method, route.path, `{}`); got != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d, want 405", route.method, route.path, got)
		}
	}
	login := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("token="+unban))
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleLogin(w, login)
	if w.Code == http.StatusFound || len(w.Result().Cookies()) != 0 {
		t.Fatal("unban token started a browser session")
	}
}

// Admin tokens can unban; read tokens cannot.
func TestUnbanRoutesStillAcceptAdmin(t *testing.T) {
	s := newUIServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/firewall/unban", strings.NewReader(`{"ip":"bad"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer admin-secret")
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("admin unban = %d, want 400 from the handler", w.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/firewall/unban", strings.NewReader(`{"ip":"bad"}`))
	req.Header.Set("Authorization", "Bearer read-secret")
	w = httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("read unban = %d, want 401", w.Code)
	}
}

// Cookie-first authorization still needs CSRF with a scoped bearer beside it.
func TestUnbanBearerDoesNotExemptCookieWrites(t *testing.T) {
	s := newUIServer(t)
	admin, unban := randomBrowserCredential(), randomBrowserCredential()
	addPolicyToken(s, config.WebUIToken{Name: "browser-admin", Token: admin, Scope: "admin"})
	addPolicyToken(s, config.WebUIToken{Name: "panel", Token: unban, Scope: "unban"})
	cookie := loginBrowser(t, s, admin, nil)
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/firewall/unban"},
		{http.MethodPost, "/api/v1/firewall/flush"},
		{http.MethodPost, "/api/v1/scan-jobs"},
		{http.MethodPut, "/api/v1/prefs/user"},
		{http.MethodDelete, "/api/v1/sessions"},
	} {
		req := httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`))
		req.AddCookie(cookie)
		req.Header.Set("Authorization", "Bearer "+unban)
		w := httptest.NewRecorder()
		s.httpSrv.Handler.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s with cookie, unban bearer and no CSRF = %d, want 403", route.method, route.path, w.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/firewall/unban", strings.NewReader(`{"ip":"bad"}`))
	req.AddCookie(cookie)
	req.Header.Set("Authorization", "Bearer "+unban)
	req.Header.Set("X-CSRF-Token", s.csrfTokenFor(req))
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("cookie unban with valid CSRF = %d, want 400 from the handler", w.Code)
	}
}

// Valid scoped calls are not credential guesses, so a busy panel never
// spends the per-client guess budget.
func TestUnbanCallsDoNotSpendGuessBudget(t *testing.T) {
	for _, path := range []string{"/api/v1/firewall/check?ip=bad", "/api/v1/status", "/api/v1/events", "/api/v1/firewall/status", "/api/v1/unknown", "/metrics"} {
		t.Run(path, func(t *testing.T) {
			s := newUIServer(t)
			unban := randomBrowserCredential()
			addPolicyToken(s, config.WebUIToken{Name: "panel", Token: unban, Scope: "unban", AllowedIPs: []string{"::ffff:203.0.113.0/120"}})
			want := http.StatusUnauthorized
			if strings.HasPrefix(path, "/api/v1/firewall/check?") {
				want = http.StatusBadRequest
			}
			for i := range 2 * credentialAttemptsPerMinute {
				req := bearerReq(path, unban, "203.0.113.20:4000")
				w := httptest.NewRecorder()
				s.httpSrv.Handler.ServeHTTP(w, req)
				if w.Code != want {
					t.Fatalf("call %d = %d, want %d", i+1, w.Code, want)
				}
			}
			s.loginMu.Lock()
			attempts := len(s.loginAttempts["203.0.113.20"])
			s.loginMu.Unlock()
			if attempts != 0 {
				t.Fatalf("valid token spent %d guesses", attempts)
			}
		})
	}
}

func TestDisallowedTokenSourceSpendsGuessBudget(t *testing.T) {
	s := newUIServer(t)
	unban := randomBrowserCredential()
	addPolicyToken(s, config.WebUIToken{Name: "panel", Token: unban, Scope: "unban", AllowedIPs: []string{"203.0.113.20"}})
	for i := range credentialAttemptsPerMinute + 1 {
		req := bearerReq("/api/v1/firewall/check?ip=bad", unban, "[::ffff:192.0.2.20]:4000")
		req.Header.Set("X-Forwarded-For", "203.0.113.20")
		req.Header.Set("X-Real-IP", "203.0.113.20")
		req.Header.Set("Forwarded", "for=203.0.113.20")
		w := httptest.NewRecorder()
		s.httpSrv.Handler.ServeHTTP(w, req)
		want := http.StatusUnauthorized
		if i == credentialAttemptsPerMinute {
			want = http.StatusTooManyRequests
		}
		if w.Code != want {
			t.Fatalf("disallowed source call %d = %d, want %d", i+1, w.Code, want)
		}
	}
}

func TestTokenSourceAddresses(t *testing.T) {
	s := newTestServerWithTemplates(t, "")
	token := randomBrowserCredential()
	addPolicyToken(s, config.WebUIToken{Name: "panel", Token: token, Scope: "admin",
		AllowedIPs: []string{"203.0.113.10", "198.51.100.0/24", "2001:db8:1::/48"}})
	h := s.requireAuth(okHandler())
	for _, tc := range []struct {
		remote string
		want   int
	}{
		{"203.0.113.10:5000", http.StatusOK},
		{"198.51.100.77:5000", http.StatusOK},
		{"[::ffff:203.0.113.10]:5000", http.StatusOK},
		{"[2001:db8:1::5]:5000", http.StatusOK},
		{"203.0.113.11:5000", http.StatusUnauthorized},
		{"[2001:db8:2::5]:5000", http.StatusUnauthorized},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, bearerReq("/api/v1/status", token, tc.remote))
		if w.Code != tc.want {
			t.Errorf("bearer from %s = %d, want %d", tc.remote, w.Code, tc.want)
		}
	}

	refused := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("token="+token))
	refused.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refused.RemoteAddr = "192.0.2.50:5000"
	w := httptest.NewRecorder()
	s.handleLogin(w, refused)
	if w.Code == http.StatusFound || len(w.Result().Cookies()) != 0 {
		t.Fatal("login from an address outside the token's sources started a session")
	}

	allowed := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("token="+token))
	allowed.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	allowed.RemoteAddr = "203.0.113.10:5000"
	w = httptest.NewRecorder()
	s.handleLogin(w, allowed)
	cookies := w.Result().Cookies()
	if w.Code != http.StatusFound || len(cookies) != 1 {
		t.Fatalf("login from an allowed address = %d", w.Code)
	}
	cookie := cookies[0]
	inside := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	inside.AddCookie(cookie)
	inside.RemoteAddr = "203.0.113.10:6000"
	if !s.isAuthenticated(inside) {
		t.Fatal("session from an allowed address rejected")
	}
	outside := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	outside.AddCookie(cookie)
	outside.RemoteAddr = "192.0.2.50:6000"
	if s.isAuthenticated(outside) {
		t.Fatal("session cookie accepted from an address outside the token's sources")
	}
}

func TestExplicitExpiryAuthenticates(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		name, expires string
		want          int
	}{
		{"future", now.Add(300 * 24 * time.Hour).Format(time.RFC3339), http.StatusNoContent},
		{"past", now.Add(-time.Second).Format(time.RFC3339), http.StatusUnauthorized},
		{"default", "", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := randomBrowserCredential()
			s := newTestServer(t, "")
			s.sessionNow = func() time.Time { return now }
			addPolicyToken(s, config.WebUIToken{Name: "panel", Token: token, Scope: "read",
				IssuedAt: now.Add(-30 * 24 * time.Hour).Format(time.RFC3339), ExpiresAt: tc.expires})
			req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			s.requireRead(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})).ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestMetricsTokenExplicitExpiry(t *testing.T) {
	prior := config.Active()
	t.Cleanup(func() { config.SetActive(prior) })
	token := randomBrowserCredential()
	s := newTestServer(t, "")
	now := time.Now().UTC().Truncate(time.Second)
	s.sessionNow = func() time.Time { return now }
	issued := now.Add(-30 * 24 * time.Hour).Format(time.RFC3339)
	for _, tc := range []struct {
		expires string
		allowed bool
	}{
		{now.Add(time.Hour).Format(time.RFC3339), true},
		{now.Format(time.RFC3339), false},
		{"", false},
	} {
		cfg := &config.Config{}
		cfg.WebUI.MetricsToken = token
		cfg.WebUI.MetricsTokenIssuedAt = issued
		cfg.WebUI.MetricsTokenExpiresAt = tc.expires
		config.SetActive(cfg)
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		if s.isMetricsAuthenticated(req) != tc.allowed {
			t.Errorf("metrics authentication for expires_at %q: want allowed=%v", tc.expires, tc.allowed)
		}
	}
}
