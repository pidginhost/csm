package webui

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

type unbanBodyReader struct {
	io.Reader
	beforeRead func()
}

func (r *unbanBodyReader) Read(p []byte) (int, error) {
	if r.beforeRead != nil {
		r.beforeRead()
		r.beforeRead = nil
	}
	return r.Reader.Read(p)
}

// A slow body can outlive the credential that authorized the request. Its
// release must still match that authorization, just like its audit actor.
func TestUnbanKeepsAuthorizedScopeThroughExpiry(t *testing.T) {
	for _, mode := range []string{"admin bearer", "admin session", "admin session with unban bearer", "unban bearer"} {
		t.Run(mode, func(t *testing.T) {
			s := newUIServer(t)
			now := time.Now().UTC().Truncate(time.Second)
			s.sessionNow = func() time.Time { return now }
			expires := now.Add(time.Minute)
			admin, unban := randomBrowserCredential(), randomBrowserCredential()
			for _, tok := range []config.WebUIToken{
				{Name: "operator", Token: admin, Scope: "admin"},
				{Name: "panel", Token: unban, Scope: "unban"},
			} {
				tok.IssuedAt = now.Add(-time.Hour).Format(time.RFC3339)
				tok.ExpiresAt = expires.Format(time.RFC3339)
				addPolicyToken(s, tok)
			}
			fb := newFullBlocker()
			fb.blocked["203.0.113.5"] = "mail login spray"
			s.blocker = fb
			body := &unbanBodyReader{
				Reader:     strings.NewReader(`{"ip":"::ffff:203.0.113.5"}`),
				beforeRead: func() { now = expires.Add(time.Second) },
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/firewall/unban", body)
			req.Header.Set("Content-Type", "application/json")
			wantActor, wantVia := "operator", "api"
			switch mode {
			case "admin bearer":
				req.Header.Set("Authorization", "Bearer "+admin)
			case "unban bearer":
				req.Header.Set("Authorization", "Bearer "+unban)
				wantActor = "panel"
			default:
				req.AddCookie(loginBrowser(t, s, admin, nil))
				req.Header.Set("X-CSRF-Token", s.csrfTokenFor(req))
				wantVia = "browser"
				if mode == "admin session with unban bearer" {
					req.Header.Set("Authorization", "Bearer "+unban)
				}
			}
			w := httptest.NewRecorder()
			s.httpSrv.Handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK || !now.After(expires) {
				t.Fatalf("unban status = %d, body read past expiry = %v", w.Code, now.After(expires))
			}
			want := []string{"203.0.113.5"}
			unblocked, unbanned := want, []string(nil)
			if mode == "unban bearer" {
				unblocked, unbanned = nil, want
			}
			if !slices.Equal(fb.unblocked, unblocked) || !slices.Equal(fb.unbanned, unbanned) {
				t.Errorf("unblocked %q, unbanned %q; want %q, %q", fb.unblocked, fb.unbanned, unblocked, unbanned)
			}
			if _, blocked := fb.blocked[want[0]]; blocked {
				t.Error("successful release kept the block")
			}
			entries := readUIAuditLog(s.cfg.StatePath, 1)
			if len(entries) != 1 || entries[0].Actor != wantActor || entries[0].Via != wantVia {
				t.Fatalf("audit did not retain the authorizing identity: %+v", entries)
			}
		})
	}
}

func TestUnbanScopeRejectsOperatorBody(t *testing.T) {
	s := newUIServer(t)
	token := randomBrowserCredential()
	addPolicyToken(s, config.WebUIToken{Name: "panel", Token: token, Scope: "unban"})
	fb := newFullBlocker()
	s.blocker = fb
	req := httptest.NewRequest(http.MethodPost, "/api/v1/firewall/unban",
		strings.NewReader(`{"ip":"203.0.113.5","scope":"admin","release_kind":"operator"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	assertJSONError(t, "operator fields", w, http.StatusBadRequest)
	if len(fb.unblocked) != 0 || len(fb.unbanned) != 0 {
		t.Fatalf("invalid body reached a release: %q, %q", fb.unblocked, fb.unbanned)
	}
}

type failingUnbanBlocker struct{ *fullBlocker }

func (b *failingUnbanBlocker) UnbanIP(ip string) error {
	b.unbanned = append(b.unbanned, ip)
	return errors.New("firewall unavailable")
}

func (b *failingUnbanBlocker) UnblockIP(ip string) error {
	b.unblocked = append(b.unblocked, ip)
	return errors.New("firewall unavailable")
}

func TestUnbanFailureKeepsBlockAndThreatState(t *testing.T) {
	for _, tc := range []struct {
		name, scope string
		unsupported bool
		status      int
	}{
		{name: "panel failure", scope: "unban", status: http.StatusInternalServerError},
		{name: "operator failure", scope: "admin", status: http.StatusInternalServerError},
		{name: "unsupported panel release", scope: "unban", unsupported: true, status: http.StatusNotImplemented},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := randomBrowserCredential()
			s := newTestServerWithBbolt(t, "")
			addPolicyToken(s, config.WebUIToken{Name: "caller", Token: token, Scope: tc.scope})
			t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))
			const ip = "203.0.113.7"
			fb := newFullBlocker()
			fb.blocked[ip] = "mail login spray"
			s.blocker = &failingUnbanBlocker{fb}
			if tc.unsupported {
				// Expose only the base interface, with no self-service method.
				s.blocker = struct{ IPBlocker }{fb}
			}
			tdb := checks.GetThreatDB()
			tdb.AddTemporary(ip, "mail login spray", time.Hour)
			if _, ok := store.Global().GetPermanentBlock(ip); !ok {
				t.Fatal("setup: missing persisted threat row")
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/firewall/unban", strings.NewReader(`{"ip":"`+ip+`"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			s.httpSrv.Handler.ServeHTTP(w, req)
			assertJSONError(t, tc.name, w, tc.status)
			if _, ok := tdb.Lookup(ip); !ok {
				t.Error("failed unban removed in-memory threat state")
			}
			if _, ok := store.Global().GetPermanentBlock(ip); !ok {
				t.Error("failed unban removed persisted threat state")
			}
			if _, ok := fb.blocked[ip]; !ok {
				t.Error("failed unban changed the block")
			}
			var unblocked, unbanned []string
			if !tc.unsupported {
				if tc.scope == "admin" {
					unblocked = []string{ip}
				} else {
					unbanned = []string{ip}
				}
			}
			if !slices.Equal(fb.unblocked, unblocked) || !slices.Equal(fb.unbanned, unbanned) {
				t.Errorf("release calls = %q, %q; want %q, %q", fb.unblocked, fb.unbanned, unblocked, unbanned)
			}
			if entries := readUIAuditLog(s.cfg.StatePath, 0); len(entries) != 0 {
				t.Fatalf("failed unban logged a successful action: %+v", entries)
			}
		})
	}
}
