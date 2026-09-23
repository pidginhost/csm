package webui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
		t.Fatalf("tokens %q and %q, want two different non-empty tokens", a, b)
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
		t.Fatalf("page does not carry the session token %s", want)
	}
}
