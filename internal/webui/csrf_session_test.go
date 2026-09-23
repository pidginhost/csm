package webui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// setSessionCSRF sets the CSRF header the browser session r carries would send.
func setSessionCSRF(s *Server, r *http.Request) {
	r.Header.Set("X-CSRF-Token", s.csrfTokenFor(r))
}

func sessionPost(target, sessionSecret string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, nil)
	if sessionSecret != "" {
		req.AddCookie(&http.Cookie{Name: "csm_auth", Value: sessionSecret})
	}
	return req
}

// The CSRF token was one value per daemon start, shared by every operator and
// browser. It is now derived from the browser session, so one session's token
// is useless in another, and a new login gets a new token.
func TestCSRFTokenIsBoundToTheBrowserSession(t *testing.T) {
	s := newTestServer(t, "tok")
	a, b := s.csrfTokenForSession("session-a"), s.csrfTokenForSession("session-b")
	if a == "" || b == "" || a == b {
		t.Fatal("expected two different non-empty CSRF tokens")
	}
	if a != s.csrfTokenForSession("session-a") {
		t.Fatal("a session's token changed between calls")
	}

	req := sessionPost("/api/x", "session-a")
	req.Header.Set("X-CSRF-Token", a)
	if !s.validateCSRF(req) {
		t.Fatal("a session's own token was refused")
	}
	req = sessionPost("/api/x", "session-b")
	req.Header.Set("X-CSRF-Token", a)
	if s.validateCSRF(req) {
		t.Fatal("another session's token was accepted")
	}
	req = sessionPost("/api/x", "")
	req.Header.Set("X-CSRF-Token", a)
	if s.validateCSRF(req) {
		t.Fatal("a token was accepted without a browser session")
	}
}

// A form token belongs in the POST body. Accepting it from the query string
// put it in URLs, logs and Referer headers.
func TestCSRFFormTokenMustComeFromTheBody(t *testing.T) {
	s := newTestServer(t, "tok")
	token := s.csrfTokenForSession("session-a")

	req := sessionPost("/sessions/revoke?csrf_token="+url.QueryEscape(token), "session-a")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if s.validateCSRF(req) {
		t.Fatal("a token in the query string was accepted")
	}

	req = httptest.NewRequest(http.MethodPost, "/sessions/revoke", strings.NewReader("csrf_token="+url.QueryEscape(token)))
	req.AddCookie(&http.Cookie{Name: "csm_auth", Value: "session-a"})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !s.validateCSRF(req) {
		t.Fatal("a token in the form body was refused")
	}
}

// Pages embed the token of the session that loaded them.
func TestPagesEmbedTheSessionCSRFToken(t *testing.T) {
	s := newRealUIServer(t)
	req := httptest.NewRequest(http.MethodGet, "/hardening", nil)
	req.AddCookie(&http.Cookie{Name: "csm_auth", Value: "session-a"})
	w := httptest.NewRecorder()
	s.handleHardening(w, req)
	want := `<meta name="csrf-token" content="` + s.csrfTokenForSession("session-a") + `">`
	if !strings.Contains(w.Body.String(), want) {
		t.Fatal("page does not carry its session CSRF token")
	}
}

func TestSessionCSRFFormsRotationAndConcurrentRenders(t *testing.T) {
	credential := randomBrowserCredential()
	auth := newTestServer(t, credential)
	s := newRealUIServer(t)
	s.sessions = auth.sessions
	s.cfg.WebUI.Tokens = auth.cfg.WebUI.Tokens
	first := loginBrowser(t, s, credential, nil)
	second := loginBrowser(t, s, credential, nil)
	csrfField := regexp.MustCompile(`name="csrf_token" value="([^"]*)"`)
	render := func(cookie *http.Cookie) string {
		req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
		req.AddCookie(cookie)
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		w := httptest.NewRecorder()
		s.httpSrv.Handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("sessions page status = %d", w.Code)
			return ""
		}
		fields := csrfField.FindAllStringSubmatch(w.Body.String(), -1)
		// Logout, both session rows, and revoke-all each need a form token.
		if len(fields) != 4 {
			t.Errorf("sessions page has %d CSRF fields, want 4", len(fields))
			return ""
		}
		expected := s.csrfTokenForSession(cookie.Value)
		for _, field := range fields {
			if field[1] != expected {
				t.Error("render mixed tokens from different browser sessions")
			}
		}
		return fields[0][1]
	}
	firstCSRF, secondCSRF := render(first), render(second)
	if firstCSRF == "" || secondCSRF == "" || firstCSRF == secondCSRF {
		t.Fatal("forms do not distinguish sessions")
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		cookie := first
		if i%2 == 1 {
			cookie = second
		}
		wg.Go(func() { render(cookie) })
	}
	wg.Wait()
	if s.templateFuncs()["csrfToken"].(func() string)() != "" {
		t.Fatal("template defaults retain a request's token")
	}

	postForm := func(path string, cookie *http.Cookie, values url.Values) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
		req.AddCookie(cookie)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.httpSrv.Handler.ServeHTTP(w, req)
		return w.Code
	}
	if code := postForm("/logout", second, url.Values{"csrf_token": {firstCSRF}}); code != http.StatusForbidden {
		t.Fatalf("logout accepted another session's form: %d", code)
	}
	if code := postForm("/logout", second, url.Values{"csrf_token": {secondCSRF}}); code != http.StatusFound {
		t.Fatalf("logout form rejected: %d", code)
	}
	replacement := loginBrowser(t, s, credential, first)
	replacementCSRF := s.csrfTokenForSession(replacement.Value)
	if replacementCSRF == firstCSRF {
		t.Fatal("reauthentication reused CSRF token")
	}
	if code := sessionGet(s, first, "/api/v1/status", false); code != http.StatusUnauthorized {
		t.Fatalf("stale cookie authorized: %d", code)
	}
	if code := postForm("/sessions/revoke", replacement, url.Values{"csrf_token": {firstCSRF}, "id": {"all"}}); code != http.StatusForbidden {
		t.Fatalf("replacement session accepted stale form: %d", code)
	}
	if code := postForm("/sessions/revoke?csrf_token="+url.QueryEscape(replacementCSRF), replacement, url.Values{"id": {"all"}}); code != http.StatusForbidden {
		t.Fatalf("revocation accepted query token: %d", code)
	}
	if code := postForm("/sessions/revoke", replacement, url.Values{"csrf_token": {replacementCSRF}, "id": {"all"}}); code != http.StatusSeeOther {
		t.Fatalf("revocation form rejected: %d", code)
	}
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.AddCookie(replacement)
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `id="login-form"`) {
		t.Fatal("stale cookie cannot reach login page")
	}
}
