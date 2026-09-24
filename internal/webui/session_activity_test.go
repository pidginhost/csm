package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func sessionGet(s *Server, cookie *http.Cookie, path string, active bool) int {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(cookie)
	if !strings.HasPrefix(path, "/api/") {
		req.Header.Set("Sec-Fetch-Mode", "navigate")
	}
	if active {
		req.Header.Set("X-CSM-Active", "1")
	}
	w := httptest.NewRecorder()
	if strings.HasPrefix(path, "/api/") {
		s.httpSrv.Handler.ServeHTTP(w, req)
	} else {
		// Page routes need the UI directory; the middleware they share is
		// what decides whether the request counts as activity.
		s.requireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, req)
	}
	return w.Code
}

func TestSessionActivityAcrossAuthPaths(t *testing.T) {
	for _, tc := range []struct {
		name, path, mode, accept, auth string
		active, touch                  bool
	}{
		{name: "metrics poll", path: "/metrics", auth: "metrics"},
		{name: "marked metrics poll", path: "/metrics", auth: "metrics", active: true},
		{name: "sessions poll", path: "/sessions", mode: "cors", accept: "text/html", auth: "admin"},
		{name: "sessions navigation", path: "/sessions", mode: "navigate", auth: "admin", touch: true},
		{name: "legacy navigation", path: "/dashboard", accept: "text/html", auth: "admin", touch: true},
		{name: "login poll", path: "/login", mode: "same-origin", auth: "login"},
		{name: "login navigation", path: "/login", mode: "navigate", auth: "login", touch: true},
		{name: "read API poll", path: "/api/v1/status", auth: "read"},
		{name: "read API input", path: "/api/v1/status", auth: "read", active: true, touch: true},
		{name: "admin API poll", path: "/api/v1/sessions", auth: "admin"},
		{name: "admin API input", path: "/api/v1/sessions", auth: "admin", active: true, touch: true},
		{name: "event stream", path: "/api/v1/events", auth: "read", active: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			credential := randomBrowserCredential()
			s := newTestServerWithTemplates(t, credential)
			_, idle, err := s.cfg.BrowserSessionDurations()
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			now := start
			s.sessionNow = func() time.Time { return now }
			cookie := loginBrowser(t, s, credential, nil)
			now = start.Add(idle / 2)
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.AddCookie(cookie)
			req.Header.Set("Sec-Fetch-Mode", tc.mode)
			req.Header.Set("Accept", tc.accept)
			if tc.active {
				req.Header.Set("X-CSM-Active", "1")
			}
			inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
			var handler http.Handler
			switch tc.auth {
			case "metrics":
				handler = http.HandlerFunc(s.handleMetrics)
			case "login":
				handler = http.HandlerFunc(s.handleLogin)
			case "read":
				handler = s.requireRead(inner)
			default:
				handler = s.requireAuth(inner)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			want := http.StatusOK
			if tc.auth == "login" {
				want = http.StatusFound
			}
			if w.Code != want {
				t.Fatalf("request status = %d, want %d", w.Code, want)
			}
			now = start.Add(idle + time.Second)
			want = http.StatusUnauthorized
			if tc.touch {
				want = http.StatusOK
			}
			if code := sessionGet(s, cookie, "/api/v1/status", false); code != want {
				t.Fatalf("session status after idle deadline = %d, want %d", code, want)
			}
		})
	}
}

// Pages poll the API on timers. Those requests must not keep a browser
// session alive, or a dashboard left open never reaches the idle timeout.
// Page loads and API calls the operator made (marked X-CSM-Active by the
// UI) still count as activity.
func TestBackgroundPollsDoNotExtendIdleSessions(t *testing.T) {
	token := randomBrowserCredential()
	s := newTestServerWithTemplates(t, token)
	_, idle, err := s.cfg.BrowserSessionDurations()
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	now := start
	s.sessionNow = func() time.Time { return now }

	// A background poll halfway through the idle period does not count.
	cookie := loginBrowser(t, s, token, nil)
	now = start.Add(idle / 2)
	if code := sessionGet(s, cookie, "/api/v1/status", false); code != http.StatusOK {
		t.Fatalf("poll inside the idle period: %d", code)
	}
	now = start.Add(idle + time.Second)
	if code := sessionGet(s, cookie, "/api/v1/status", false); code != http.StatusUnauthorized {
		t.Fatalf("session kept alive by background polling: %d", code)
	}

	// An operator's request and a page load do count.
	for _, tc := range []struct {
		name   string
		path   string
		active bool
	}{
		{"marked api request", "/api/v1/status", true},
		{"page load", "/dashboard", false},
	} {
		now = start
		cookie := loginBrowser(t, s, token, nil)
		now = start.Add(idle / 2)
		if code := sessionGet(s, cookie, tc.path, tc.active); code != http.StatusOK {
			t.Fatalf("%s: %d", tc.name, code)
		}
		now = start.Add(idle + time.Second)
		if code := sessionGet(s, cookie, "/api/v1/status", false); code != http.StatusOK {
			t.Fatalf("%s did not extend the session: %d", tc.name, code)
		}
	}
}
