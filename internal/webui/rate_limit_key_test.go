package webui

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRateLimitKeyGroupsIPv6By64(t *testing.T) {
	cases := map[string]string{
		"203.0.113.9:443":                   "203.0.113.9",
		"[2001:db8:1:2:aaaa::1]:443":        "2001:db8:1:2::/64",
		"[2001:db8:1:2:bbbb:cccc:dddd:2]:1": "2001:db8:1:2::/64",
		"[::ffff:203.0.113.9]:443":          "203.0.113.9",
		"not-an-address":                    "not-an-address",
	}
	for in, want := range cases {
		if got := rateLimitKey(in); got != want {
			t.Errorf("rateLimitKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// One IPv6 client owns a whole /64 and can rotate addresses inside it; the
// API budget counts the /64, not each address.
func TestAPIRateLimitCountsAnIPv6Prefix(t *testing.T) {
	s := newTestServer(t, "tok")
	var last int
	for i := 0; i < 601; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.RemoteAddr = fmt.Sprintf("[2001:db8:1:2::%x]:40000", i+1)
		req.Header.Set("Authorization", "Bearer tok")
		w := httptest.NewRecorder()
		s.httpSrv.Handler.ServeHTTP(w, req)
		last = w.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("request 601 from one /64 got %d, want 429", last)
	}
}

func TestLoginRateLimitCountsAnIPv6Prefix(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	limited := false
	for i := 0; i < 20 && !limited; i++ {
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{"token": {"wrong"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = fmt.Sprintf("[2001:db8:1:2::%x]:40000", i+1)
		w := httptest.NewRecorder()
		s.handleLogin(w, req)
		limited = w.Code == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("failed logins from one /64 were never limited")
	}
}
