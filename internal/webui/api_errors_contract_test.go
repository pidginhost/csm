package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/incident"
	"github.com/pidginhost/csm/internal/session"
	"github.com/pidginhost/csm/internal/state"
	sessionstore "github.com/pidginhost/csm/internal/store"
)

// newUIServer starts a server with the real UI loaded, so page routes and the
// "/" catch-all are registered the way they are in production.
func newUIServer(t *testing.T) *Server {
	t.Helper()
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
	db, err := sessionstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if s.sessions, err = session.New(db, 24*time.Hour, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	s.SetIncidentCorrelator(incident.NewCorrelator(incident.CorrelatorConfig{OpenThreshold: 1}))
	return s
}

// assertJSONError checks the one error shape of the API: the status code,
// a JSON content type and a non-empty "error" message.
func assertJSONError(t *testing.T, name string, w *httptest.ResponseRecorder, code int) {
	t.Helper()
	if w.Code != code {
		t.Errorf("%s: status = %d, want %d; body %q", name, w.Code, code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("%s: Content-Type = %q, want application/json; body %q", name, ct, w.Body.String())
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Error == "" {
		t.Errorf("%s: body %q is not {\"error\": ...}", name, w.Body.String())
	}
}

// Every failure on /api/v1, from middleware or handler, is a non-2xx JSON
// {"error": ...}; none is plain text and no unknown path serves a page.
func TestAPIFailuresAreJSONErrors(t *testing.T) {
	s := newUIServer(t)
	serve := func(method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.httpSrv.Handler.ServeHTTP(w, req)
		return w
	}
	admin := map[string]string{"Authorization": "Bearer admin-secret"}

	assertJSONError(t, "unknown path", serve("GET", "/api/v1/no-such-route", "", admin), http.StatusNotFound)
	assertJSONError(t, "trailing slash typo", serve("GET", "/api/v1/findings/", "", admin), http.StatusNotFound)
	assertJSONError(t, "foreign origin", serve("GET", "/api/v1/status", "", map[string]string{
		"Authorization": "Bearer read-secret", "Origin": "https://attacker.example",
	}), http.StatusForbidden)
	for _, path := range []string{
		"/api/v1/firewall/allow-ip", "/api/v1/firewall/remove-allow", "/api/v1/firewall/deny-subnet",
		"/api/v1/firewall/remove-subnet", "/api/v1/firewall/flush", "/api/v1/firewall/cphulk-clear",
		"/api/v1/firewall/unban", "/api/v1/geoip/batch",
	} {
		assertJSONError(t, "GET "+path, serve("GET", path, "", admin), http.StatusMethodNotAllowed)
	}
	assertJSONError(t, "unknown incident", serve("GET", "/api/v1/incidents/inc_missing", "", admin), http.StatusNotFound)
	assertJSONError(t, "unknown incident status", serve("POST", "/api/v1/incidents/inc_missing/status", `{"status":"resolved"}`, admin), http.StatusNotFound)
	assertJSONError(t, "bad incident body", serve("POST", "/api/v1/incidents/inc_missing/status", `{bad`, admin), http.StatusBadRequest)

	// A browser session without its CSRF token.
	cookie := loginBrowser(t, s, "admin-secret", nil)
	req := httptest.NewRequest("POST", "/api/v1/dismiss", strings.NewReader(`{"key":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	assertJSONError(t, "missing CSRF token", w, http.StatusForbidden)

	// Over the per-client request budget.
	s.apiMu.Lock()
	burst := make([]time.Time, 600)
	for i := range burst {
		burst[i] = time.Now()
	}
	s.apiRequests[rateLimitKey("192.0.2.1:1234")] = burst
	s.apiMu.Unlock()
	assertJSONError(t, "rate limit", serve("GET", "/api/v1/status", "", map[string]string{"Authorization": "Bearer read-secret"}), http.StatusTooManyRequests)
}

// The event stream answers errors before the stream starts in the same shape.
func TestEventStreamErrorsAreJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	s.findingBus = nil
	w := httptest.NewRecorder()
	s.apiEvents(w, httptest.NewRequest("GET", "/api/v1/events", nil))
	assertJSONError(t, "no event bus", w, http.StatusServiceUnavailable)
}

// Settings validation failures keep their per-field list next to the one
// error message every failure carries.
func TestValidationErrorsCarryAnErrorMessage(t *testing.T) {
	w := httptest.NewRecorder()
	writeValidationErrors(w, []fieldError{{Field: "alerts.email", Message: "must be an address"}})
	assertJSONError(t, "validation", w, http.StatusUnprocessableEntity)
	var body struct {
		Errors []fieldError `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || len(body.Errors) != 1 || body.Errors[0].Field != "alerts.email" {
		t.Errorf("field errors lost: %q", w.Body.String())
	}
}

// Read routes answer only GET. Admin reads used to run their handler for any
// method, so a DELETE on /api/v1/quarantine listed the quarantine.
func TestAdminReadRoutesRefuseOtherMethods(t *testing.T) {
	s := newUIServer(t)
	for _, path := range []string{
		"/api/v1/quarantine", "/api/v1/history/csv", "/api/v1/accounts", "/api/v1/account",
		"/api/v1/export", "/api/v1/finding-detail", "/api/v1/quarantine-preview",
		"/api/v1/db-object-backups", "/api/v1/incident", "/api/v1/incidents", "/api/v1/modsec/rules",
		"/api/v1/email/stats", "/api/v1/performance", "/api/v1/hardening", "/api/v1/threat/stats",
		"/api/v1/threat/top-attackers", "/api/v1/threat/ip", "/api/v1/threat/events",
		"/api/v1/threat/db-stats", "/api/v1/threat/whitelist", "/api/v1/rules/status",
		"/api/v1/rules/list", "/api/v1/audit", "/api/v1/firewall/status", "/api/v1/firewall/allowed",
		"/api/v1/firewall/audit", "/api/v1/firewall/subnets", "/api/v1/firewall/check", "/api/v1/geoip",
	} {
		for _, method := range []string{http.MethodPost, http.MethodDelete} {
			req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
			req.Header.Set("Authorization", "Bearer admin-secret")
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			s.httpSrv.Handler.ServeHTTP(w, req)
			assertJSONError(t, method+" "+path, w, http.StatusMethodNotAllowed)
			if got := w.Header().Get("Allow"); got != "GET" {
				t.Errorf("%s %s: Allow = %q, want GET", method, path, got)
			}
		}
	}
}

