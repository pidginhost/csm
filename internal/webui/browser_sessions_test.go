package webui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/broadcast"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/session"
	sessionstore "github.com/pidginhost/csm/internal/store"
)

func randomBrowserCredential() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func loginBrowser(t *testing.T, s *Server, token string, old *http.Cookie) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{"token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if old != nil {
		req.AddCookie(old)
	}
	w := httptest.NewRecorder()
	s.handleLogin(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("login status = %d", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "csm_auth" && c.Value != "" {
			return c
		}
	}
	t.Fatal("login did not issue a session cookie")
	return nil
}

func TestBrowserSessionCookieDoesNotContainAdminToken(t *testing.T) {
	token := randomBrowserCredential()
	s := newTestServerWithTemplates(t, token)
	cookie := loginBrowser(t, s, token, nil)
	if cookie.Value == token {
		t.Fatal("login exposed the reusable API credential in a cookie")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.AddCookie(cookie)
	if !s.tokenHasScope(req, "admin") {
		t.Fatal("issued session cannot authenticate")
	}
}

func TestBrowserSessionRejectsLegacyCredentialCookie(t *testing.T) {
	token := randomBrowserCredential()
	s := newTestServer(t, token)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.AddCookie(&http.Cookie{Name: "csm_auth", Value: token})
	if s.tokenHasScope(req, "admin") {
		t.Fatal("legacy credential cookie still authenticates")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if !s.tokenHasScope(req, "admin") {
		t.Fatal("API bearer authentication changed")
	}
}

func TestBrowserSessionReauthenticationRotatesAndRevokes(t *testing.T) {
	token := randomBrowserCredential()
	s := newTestServerWithTemplates(t, token)
	first := loginBrowser(t, s, token, nil)
	second := loginBrowser(t, s, token, first)
	if second.Value == first.Value {
		t.Fatal("reauthentication reused session")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(first)
	if s.tokenHasScope(req, "admin") {
		t.Fatal("old session survived reauthentication")
	}
}

func TestBrowserSessionIdleAndAbsoluteExpiry(t *testing.T) {
	token := randomBrowserCredential()
	s := newTestServerWithTemplates(t, token)
	now := s.sessionNow()
	s.sessionNow = func() time.Time { return now }
	cookie := loginBrowser(t, s, token, nil)
	now = now.Add(30 * time.Minute)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	if s.tokenHasScope(req, "admin") {
		t.Fatal("idle session authorized")
	}
}

func TestBrowserSessionManagementRequiresAdminAndCSRF(t *testing.T) {
	token := randomBrowserCredential()
	s := newTestServerWithTemplates(t, token)
	first := loginBrowser(t, s, token, nil)
	second := loginBrowser(t, s, token, nil)
	request := func(method, path string, c *http.Cookie, csrf bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		if c != nil {
			req.AddCookie(c)
		}
		if csrf {
			req.Header.Set("X-CSRF-Token", s.csrfToken())
		}
		w := httptest.NewRecorder()
		s.httpSrv.Handler.ServeHTTP(w, req)
		return w
	}
	w := request(http.MethodGet, "/api/v1/sessions", first, false)
	if w.Code != http.StatusOK {
		t.Fatalf("list status: %d", w.Code)
	}
	var response struct {
		Sessions []struct {
			ID      string `json:"id"`
			Current bool   `json:"current"`
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Sessions) != 2 {
		t.Fatal("missing active sessions")
	}
	if strings.Contains(w.Body.String(), token) || strings.Contains(w.Body.String(), first.Value) || strings.Contains(w.Body.String(), session.Hash(first.Value)) {
		t.Fatal("session API disclosed a credential or verifier")
	}
	target := ""
	for _, rec := range response.Sessions {
		if !rec.Current {
			target = rec.ID
		}
	}
	if target == "" {
		t.Fatal("current session was not identified")
	}
	if w := request(http.MethodDelete, "/api/v1/sessions/"+target, first, false); w.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF: %d", w.Code)
	}
	if w := request(http.MethodDelete, "/api/v1/sessions/"+target, first, true); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d", w.Code)
	}
	if w := request(http.MethodGet, "/api/v1/sessions", second, false); w.Code != http.StatusUnauthorized {
		t.Fatal("revoked remote session still works")
	}
	if w := request(http.MethodDelete, "/api/v1/sessions", first, true); w.Code != http.StatusOK {
		t.Fatalf("revoke all: %d", w.Code)
	}
	if w := request(http.MethodGet, "/api/v1/sessions", first, false); w.Code != http.StatusUnauthorized {
		t.Fatal("logout-all retained current session")
	}
}

func TestBrowserSessionLogoutRevokesAndRejectsGET(t *testing.T) {
	token := randomBrowserCredential()
	s := newTestServerWithTemplates(t, token)
	cookie := loginBrowser(t, s, token, nil)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req := httptest.NewRequest(method, "/logout", nil)
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		s.httpSrv.Handler.ServeHTTP(w, req)
		if method == http.MethodGet && w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET logout: %d", w.Code)
		}
		if method == http.MethodPost && w.Code != http.StatusForbidden {
			t.Fatalf("logout without CSRF: %d", w.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", s.csrfToken())
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("logout status: %d", w.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	if s.tokenHasScope(req, "admin") {
		t.Fatal("logout cleared only the cookie")
	}
}

func TestBrowserSessionPageRendersRealTemplate(t *testing.T) {
	token := randomBrowserCredential()
	s := newTestServer(t, token)
	page, err := template.New("sessions.html").Funcs(template.FuncMap{
		"csrfToken": s.csrfToken, "formatTime": formatTime,
	}).ParseFiles("../../ui/templates/sessions.html")
	if err != nil {
		t.Fatal(err)
	}
	page, err = page.New("layout").Parse(`{{template "content" .}}`)
	if err != nil {
		t.Fatal(err)
	}
	s.templates = map[string]*template.Template{"sessions.html": page}
	w := httptest.NewRecorder()
	s.handleSessions(w, httptest.NewRequest(http.MethodGet, "/sessions", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("session page: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Log out all sessions") {
		t.Fatal("session management missing")
	}
}

func TestBrowserSessionStreamStopsAfterRevocation(t *testing.T) {
	token := randomBrowserCredential()
	s := newTestServerWithTemplates(t, token)
	cookie := loginBrowser(t, s, token, nil)
	bus := broadcast.NewBus(8)
	defer bus.Close()
	s.SetFindingBus(bus)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil).WithContext(ctx)
	req.AddCookie(cookie)
	rec := newDeadlineRecorder()
	done := make(chan struct{})
	go func() { s.httpSrv.Handler.ServeHTTP(rec, req); close(done) }()
	waitForRecorderFlush(t, rec, 1)
	if err := s.sessions.RevokeAll(); err != nil {
		t.Fatal(err)
	}
	bus.Publish(alert.Finding{Check: "after-session-revocation", Severity: alert.High})
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("revoked session kept its event stream open")
	}
	body, _, _ := rec.snapshot()
	if strings.Contains(body, "after-session-revocation") {
		t.Fatal("revoked browser received new findings")
	}
}

func testBrowserCookie(t *testing.T, s *Server, token string) *http.Cookie {
	t.Helper()
	name := ""
	for _, tok := range s.cfg.WebUI.Tokens {
		if tok.Token == token && tok.Scope == "admin" {
			name = tok.Name
		}
	}
	if name == "" {
		t.Fatal("test login credential is not configured")
	}
	secret, _, err := s.sessions.Create(name, session.Hash(token), "", "192.0.2.1", "test browser", s.sessionNow())
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: "csm_auth", Value: secret}
}

func TestBrowserSessionIdleStreamStopsBeforeHeartbeat(t *testing.T) {
	token := randomBrowserCredential()
	s := newTestServerWithTemplates(t, token)
	cookie := loginBrowser(t, s, token, nil)
	bus := broadcast.NewBus(8)
	defer bus.Close()
	s.SetFindingBus(bus)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil).WithContext(ctx)
	req.AddCookie(cookie)
	rec := newDeadlineRecorder()
	done := make(chan struct{})
	go func() { s.httpSrv.Handler.ServeHTTP(rec, req); close(done) }()
	waitForRecorderFlush(t, rec, 1)
	if err := s.sessions.RevokeAll(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("revoked idle stream stayed open")
	}
	body, _, _ := rec.snapshot()
	if strings.Contains(body, "keepalive") {
		t.Fatal("revoked browser received a heartbeat")
	}
}

func TestBrowserSessionManagementRejectsAnonymousAndReadBearer(t *testing.T) {
	s := newTestServer(t, randomBrowserCredential())
	read := randomBrowserCredential()
	s.cfg.WebUI.Tokens = append(s.cfg.WebUI.Tokens, config.WebUIToken{Name: "reader", Token: read, Scope: "read"})
	for _, bearer := range []string{"", read} {
		for _, operation := range []struct{ method, path string }{
			{http.MethodGet, "/api/v1/sessions"},
			{http.MethodDelete, "/api/v1/sessions"},
			{http.MethodDelete, "/api/v1/sessions/00000000000000000000000000000000"},
		} {
			req := httptest.NewRequest(operation.method, operation.path, nil)
			if bearer != "" {
				req.Header.Set("Authorization", "Bearer "+bearer)
			}
			w := httptest.NewRecorder()
			s.httpSrv.Handler.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s: %d", operation.method, operation.path, w.Code)
			}
		}
	}
}

func TestBrowserSessionCredentialChangesInvalidateLogin(t *testing.T) {
	for _, change := range []string{"remove", "rotate", "downgrade", "rename"} {
		t.Run(change, func(t *testing.T) {
			token := randomBrowserCredential()
			s := newTestServerWithTemplates(t, token)
			cookie := loginBrowser(t, s, token, nil)
			switch change {
			case "remove":
				s.cfg.WebUI.Tokens = nil
			case "rotate":
				s.cfg.WebUI.Tokens[0].Token = randomBrowserCredential()
			case "downgrade":
				s.cfg.WebUI.Tokens[0].Scope = "read"
			case "rename":
				s.cfg.WebUI.Tokens[0].Name = "renamed"
			}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
			req.AddCookie(cookie)
			w := httptest.NewRecorder()
			s.httpSrv.Handler.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Fatal("changed credential left browser authorized")
			}
			if _, err := s.sessions.Access(cookie.Value, s.sessionNow(), false); err == nil {
				t.Fatal("invalid credential binding retained session")
			}
		})
	}
}

func TestBrowserSessionConfiguredPolicyAndRestart(t *testing.T) {
	base := newTestServer(t, randomBrowserCredential())
	db, err := sessionstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	previous := sessionstore.Global()
	sessionstore.SetGlobal(db)
	t.Cleanup(func() { sessionstore.SetGlobal(previous); _ = db.Close() })
	base.cfg.WebUI.SessionLifetime = "2h"
	base.cfg.WebUI.SessionIdleTimeout = "5m"
	s, err := New(base.cfg, base.store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	now := time.Now()
	s.sessionNow = func() time.Time { return now }
	cookie := testBrowserCookie(t, s, base.cfg.WebUI.Tokens[0].Token)
	record, err := s.sessions.Access(cookie.Value, now, false)
	if err != nil {
		t.Fatal(err)
	}
	if !record.Expires.Equal(now.Add(2 * time.Hour)) {
		t.Fatal("configured lifetime ignored")
	}
	if _, err = s.sessions.Access(cookie.Value, now.Add(5*time.Minute), false); err == nil {
		t.Fatal("configured idle timeout ignored")
	}
	restarted, err := New(base.cfg, base.store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Shutdown(context.Background()) })
	if _, err = restarted.sessions.Access(cookie.Value, now, false); err == nil {
		t.Fatal("server restart retained session")
	}
}

// At capacity the operator cannot reach the Sessions page, so the login
// response itself must say why it failed and how to make room.
func TestBrowserSessionLoginExplainsCapacity(t *testing.T) {
	token := randomBrowserCredential()
	s := newTestServerWithTemplates(t, token)
	for range session.MaxSessions {
		testBrowserCookie(t, s, token)
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{"token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleLogin(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("login at capacity returned %d, want 503", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "session limit") || !strings.Contains(body, "API") {
		t.Fatalf("login at capacity did not explain recovery: %q", body)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("login at capacity issued a cookie")
	}
}

// Login exchanges a credential the browser must already hold, so an origin
// gate adds nothing there. It did lock out operators who reach the UI by an
// unlisted address and could previously log in for read-only use. Logout and
// session revocation change server state and follow the API origin policy.
func TestBrowserSessionOriginPolicy(t *testing.T) {
	s := newTestServer(t, randomBrowserCredential())
	s.cfg.WebUI.Listen = ":9443"
	s.cfg.Hostname = "myhost.example.com"
	probe := func(path, origin string) int {
		inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		s.securityHeaders(inner).ServeHTTP(w, req)
		return w.Code
	}
	if code := probe("/login", "https://203.0.113.10:9443"); code != http.StatusOK {
		t.Fatalf("login from an unlisted origin blocked with %d", code)
	}
	for _, path := range []string{"/logout", "/sessions/revoke"} {
		if code := probe(path, "https://evil.example.com"); code != http.StatusForbidden {
			t.Fatalf("%s accepted a foreign origin with %d", path, code)
		}
	}
}

type failingBrowserSessionAccess struct {
	session.Repository
	failure error
}

func (repo *failingBrowserSessionAccess) AccessBrowserSession(key string, now time.Time, idle time.Duration, touch bool) (session.Record, error) {
	if repo.failure != nil {
		return session.Record{}, repo.failure
	}
	return repo.Repository.AccessBrowserSession(key, now, idle, touch)
}

func TestBrowserSessionLoginFailsClosedOnAccessError(t *testing.T) {
	token := randomBrowserCredential()
	s := newTestServerWithTemplates(t, token)
	db, err := sessionstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := &failingBrowserSessionAccess{Repository: db}
	s.sessions, err = session.New(repo, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	cookie := loginBrowser(t, s, token, nil)
	repo.failure = errors.New("session read failed")
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{"token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.handleLogin(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("login with failed session lookup returned %d, want 503", w.Code)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("failed session lookup replaced the browser cookie")
	}
	records, err := s.sessions.List(s.sessionNow())
	if err != nil || len(records) != 1 {
		t.Errorf("failed rotation created another session: count=%d err=%v", len(records), err)
	}
}
