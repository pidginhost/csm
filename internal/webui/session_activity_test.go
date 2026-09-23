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
