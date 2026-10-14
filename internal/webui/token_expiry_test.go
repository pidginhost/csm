package webui

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/broadcast"
	"github.com/pidginhost/csm/internal/config"
	sessionstore "github.com/pidginhost/csm/internal/store"
)

func configureExpiringToken(t *testing.T, s *Server, token, scope, issued, expires string) {
	t.Helper()
	data := fmt.Sprintf("tokens:\n  - name: audit\n    token: %q\n    scope: %s\n    issued_at: %q\n    expires_at: %q\n", token, scope, issued, expires)
	if err := yaml.Unmarshal([]byte(data), &s.cfg.WebUI); err != nil {
		t.Fatal("cannot configure test credential")
	}
}

func TestAccessTokenExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, scope := range []string{"admin", "read"} {
		at := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
		for _, tc := range []struct {
			name, issued, expires string
			allowed               bool
		}{
			{"new", at(0), "", true},
			{"issued long ago", at(-365 * 24 * time.Hour), "", true},
			{"undated", "", "", true},
			{"last second", at(-time.Hour), at(time.Second), true},
			{"exact deadline", at(-time.Hour), at(0), false},
			{"expired", "", at(-time.Second), false},
			{"future", at(time.Second), "", false},
			{"malformed issue", "not-a-date", "", false},
			{"malformed expiry", at(-time.Hour), "not-a-date", false},
		} {
			t.Run(scope+"/"+tc.name, func(t *testing.T) {
				token := randomBrowserCredential()
				s := newTestServer(t, token)
				s.sessionNow = func() time.Time { return now }
				configureExpiringToken(t, s, token, scope, tc.issued, tc.expires)
				req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				rec := httptest.NewRecorder()
				s.requireRead(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNoContent)
				})).ServeHTTP(rec, req)
				want := http.StatusUnauthorized
				if tc.allowed {
					want = http.StatusNoContent
				}
				if rec.Code != want {
					t.Fatalf("status = %d, want %d", rec.Code, want)
				}
			})
		}
	}
}

func TestBrowserSessionCannotOutliveCredential(t *testing.T) {
	token := randomBrowserCredential()
	s := newTestServerWithTemplates(t, token)
	now := time.Now().UTC().Truncate(time.Second)
	s.sessionNow = func() time.Time { return now }
	configureExpiringToken(t, s, token, "admin", "", now.Add(time.Minute).Format(time.RFC3339))
	cookie := loginBrowser(t, s, token, nil)
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(cookie)
	if !s.isAuthenticated(req) {
		t.Fatal("fresh browser session rejected")
	}
	now = now.Add(time.Minute)
	if s.isAuthenticated(req) {
		t.Fatal("browser session outlived its credential")
	}
	if records, err := s.sessions.List(now); err != nil || len(records) != 0 {
		t.Fatal("expired credential left an active browser session")
	}
}

func TestExpiredTokenCannotLogin(t *testing.T) {
	token := randomBrowserCredential()
	s := newTestServerWithTemplates(t, token)
	now := time.Now().UTC().Truncate(time.Second)
	s.sessionNow = func() time.Time { return now }
	configureExpiringToken(t, s, token, "admin", "", now.Format(time.RFC3339))
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("token="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleLogin(w, req)
	if w.Code == http.StatusFound || len(w.Result().Cookies()) != 0 {
		t.Fatal("expired token created a browser session")
	}
	if records, err := s.sessions.List(now); err != nil || len(records) != 0 {
		t.Fatal("expired login persisted a browser session")
	}
}

func TestMetricsTokenExpiryAndReload(t *testing.T) {
	prior := config.Active()
	t.Cleanup(func() { config.SetActive(prior) })
	token := randomBrowserCredential()
	s := newTestServer(t, "")
	now := time.Now().UTC().Truncate(time.Second)
	s.sessionNow = func() time.Time { return now }
	for _, tc := range []struct {
		issued, expires string
		allowed         bool
	}{
		{now.Format(time.RFC3339), "", true},
		{now.Add(-365 * 24 * time.Hour).Format(time.RFC3339), "", true},
		{"", "", true},
		{now.Add(time.Hour).Format(time.RFC3339), "", false},
		{"", now.Format(time.RFC3339), false},
	} {
		cfg := &config.Config{}
		data := fmt.Sprintf("metrics_token: %q\nmetrics_token_issued_at: %q\nmetrics_token_expires_at: %q\n", token, tc.issued, tc.expires)
		if err := yaml.Unmarshal([]byte(data), &cfg.WebUI); err != nil {
			t.Fatal("cannot configure metrics credential")
		}
		config.SetActive(cfg)
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		if s.isMetricsAuthenticated(req) != tc.allowed {
			t.Errorf("metrics authentication for issued_at %q expires_at %q: want allowed=%v", tc.issued, tc.expires, tc.allowed)
		}
	}
}

func TestBearerStreamStopsAtCredentialExpiry(t *testing.T) {
	token := randomBrowserCredential()
	s := newTestServer(t, token)
	now := time.Now().UTC().Truncate(time.Second)
	var clock atomic.Int64
	clock.Store(now.Unix())
	s.sessionNow = func() time.Time { return time.Unix(clock.Load(), 0) }
	configureExpiringToken(t, s, token, "read", "", now.Add(time.Minute).Format(time.RFC3339))
	bus := broadcast.NewBus(8)
	defer bus.Close()
	s.SetFindingBus(bus)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := newDeadlineRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.requireRead(http.HandlerFunc(s.apiEvents)).ServeHTTP(rec, req)
	}()
	waitForRecorderFlush(t, rec, 1)
	bus.Publish(alert.Finding{Check: "before_expiry", Severity: alert.High})
	waitForRecorderBodyContains(t, rec, `"check":"before_expiry"`)
	clock.Store(now.Add(time.Minute).Unix())
	bus.Publish(alert.Finding{Check: "after_expiry", Severity: alert.High})
	select {
	case <-done:
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("bearer event stream remained open after credential expiry")
	}
	body, _, _ := rec.snapshot()
	if strings.Contains(body, "after_expiry") {
		t.Fatal("event leaked after credential expiry")
	}
}

func TestCSRFUsesCurrentCredential(t *testing.T) {
	s := newTestServer(t, "")
	now := time.Now().UTC().Truncate(time.Second)
	s.sessionNow = func() time.Time { return now }
	expired, current := randomBrowserCredential(), randomBrowserCredential()
	s.cfg.WebUI.Tokens = []config.WebUIToken{
		{Name: "expired", Token: expired, Scope: "admin", ExpiresAt: now.Format(time.RFC3339)},
		{Name: "current", Token: current, Scope: "admin"},
	}
	cookie := testBrowserCookie(t, s, current)
	if s.csrfSecret(cookie.Value) != current {
		t.Fatal("expired credential still signs CSRF tokens")
	}
	s.cfg.WebUI.Tokens = nil
	s.cfg.WebUI.AuthToken = expired
	s.cfg.WebUI.AuthTokenExpiresAt = now.Format(time.RFC3339)
	if s.csrfSecret(cookie.Value) != "" {
		t.Fatal("expired legacy credential still signs CSRF tokens")
	}
}

func TestCSRFSurvivesAnotherAdminCredentialExpiry(t *testing.T) {
	s := newTestServerWithTemplates(t, "")
	now := time.Now().UTC().Truncate(time.Second)
	s.sessionNow = func() time.Time { return now }
	first, second := randomBrowserCredential(), randomBrowserCredential()
	s.cfg.WebUI.Tokens = []config.WebUIToken{
		{Name: "first", Token: first, Scope: "admin", ExpiresAt: now.Add(time.Minute).Format(time.RFC3339)},
		{Name: "second", Token: second, Scope: "admin"},
	}
	firstCookie := loginBrowser(t, s, first, nil)
	secondCookie := loginBrowser(t, s, second, nil)
	firstRequest := sessionPost("/api/test", firstCookie.Value)
	secondRequest := sessionPost("/api/test", secondCookie.Value)
	setSessionCSRF(s, firstRequest)
	setSessionCSRF(s, secondRequest)
	handler := s.requireAuth(s.requireCSRF(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	check := func(req *http.Request, want int) {
		t.Helper()
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("write status = %d, want %d", w.Code, want)
		}
	}
	check(firstRequest, http.StatusNoContent)
	check(secondRequest, http.StatusNoContent)
	now = now.Add(time.Minute)
	check(secondRequest, http.StatusNoContent)
	check(firstRequest, http.StatusUnauthorized)
}

func TestBearerStreamExpiryBetweenAuthorizationAndOpen(t *testing.T) {
	token := randomBrowserCredential()
	s := newTestServer(t, token)
	now := time.Now().UTC().Truncate(time.Second)
	s.sessionNow = func() time.Time { return now }
	configureExpiringToken(t, s, token, "read", "", now.Add(time.Second).Format(time.RFC3339))
	bus := broadcast.NewBus(8)
	defer bus.Close()
	s.SetFindingBus(bus)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := newDeadlineRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.requireRead(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			now = now.Add(time.Second)
			s.apiEvents(w, r)
		})).ServeHTTP(rec, req)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("token expiring during authorization opened an unbounded stream")
	}
	if rec.status != http.StatusOK {
		t.Fatalf("stream was not reached: status %d", rec.status)
	}
}

func TestUndatedCredentialLogsIn(t *testing.T) {
	token := randomBrowserCredential()
	s := newTestServerWithTemplates(t, token)
	configureExpiringToken(t, s, token, "admin", "", "")
	cookie := loginBrowser(t, s, token, nil)
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(cookie)
	if !s.isAuthenticated(req) {
		t.Fatal("credential without dates cannot log in")
	}
}

func TestUndatedConfigurationAuthPaths(t *testing.T) {
	previous := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(previous) })
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%v", legacy), func(t *testing.T) {
			admin, metricsToken := randomBrowserCredential(), randomBrowserCredential()
			credentials := fmt.Sprintf("  tokens:\n    - name: operator\n      token: %q\n      scope: admin\n", admin)
			if legacy {
				credentials = fmt.Sprintf("  auth_token: %q\n", admin)
			}
			cfg, err := config.LoadBytes(fmt.Appendf(nil,
				"webui:\n  session_lifetime: 720h\n  session_idle_timeout: 720h\n  metrics_token: %q\n%s", metricsToken, credentials))
			if err != nil {
				t.Fatal("older configuration failed to load:", err)
			}
			for _, result := range config.Validate(cfg) {
				if strings.HasPrefix(result.Field, "webui.") {
					t.Fatalf("older configuration has a web UI diagnostic: %s: %s", result.Field, result.Message)
				}
			}
			base := newTestServer(t, "")
			cfg.WebUI.UIDir = base.cfg.WebUI.UIDir
			db, err := sessionstore.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			priorStore := sessionstore.Global()
			sessionstore.SetGlobal(db)
			t.Cleanup(func() { sessionstore.SetGlobal(priorStore); _ = db.Close() })
			s, err := New(cfg, base.store)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
			now := time.Now().UTC().Truncate(time.Second)
			s.sessionNow = func() time.Time { return now }
			cookie := loginBrowser(t, s, admin, nil)
			if cookie.MaxAge != int((720 * time.Hour).Seconds()) {
				t.Fatal("configured browser lifetime was not preserved")
			}
			csrf := s.csrfTokenForSession(cookie.Value)
			if csrf == "" {
				t.Fatal("undated credential did not sign a CSRF token")
			}
			now = now.Add(720*time.Hour - time.Second)
			for _, via := range []string{"bearer", "cookie", "metrics"} {
				req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
				switch via {
				case "bearer":
					req.Header.Set("Authorization", "Bearer "+admin)
				case "cookie":
					req.AddCookie(cookie)
				case "metrics":
					req.Header.Set("Authorization", "Bearer "+metricsToken)
				}
				rec := httptest.NewRecorder()
				s.handleMetrics(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("undated %s metrics authentication: status %d", via, rec.Code)
				}
				if via == "metrics" {
					continue
				}
				req.Method = http.MethodPost
				req.URL.Path = "/api/test"
				req.Header.Set("X-CSRF-Token", csrf)
				rec = httptest.NewRecorder()
				s.requireAuth(s.requireCSRF(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNoContent)
				}))).ServeHTTP(rec, req)
				if rec.Code != http.StatusNoContent {
					t.Fatalf("undated %s write authentication: status %d", via, rec.Code)
				}
				bus := broadcast.NewBus(8)
				s.SetFindingBus(bus)
				ctx, cancel := context.WithCancel(context.Background())
				stream := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil).WithContext(ctx)
				stream.Header = req.Header.Clone()
				streamRec := newDeadlineRecorder()
				done := make(chan struct{})
				go func() {
					defer close(done)
					s.requireRead(http.HandlerFunc(s.apiEvents)).ServeHTTP(streamRec, stream)
				}()
				t.Cleanup(func() { cancel(); <-done; bus.Close() })
				waitForRecorderFlush(t, streamRec, 1)
				bus.Publish(alert.Finding{Check: "undated_credential", Severity: alert.High})
				waitForRecorderBodyContains(t, streamRec, `"check":"undated_credential"`)
				cancel()
				<-done
			}
			now = now.Add(time.Second)
			req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
			req.AddCookie(cookie)
			if s.isAuthenticated(req) || s.csrfSecret(cookie.Value) != "" {
				t.Fatal("undated credential bypassed the browser session deadline")
			}
			req.Header.Set("Authorization", "Bearer "+admin)
			if !s.isAuthenticated(req) {
				t.Fatal("browser session expiry disabled the undated API credential")
			}
		})
	}
}
