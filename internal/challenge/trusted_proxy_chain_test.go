package challenge

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestServerTrustMatchesConnectingPeer(t *testing.T) {
	for _, tc := range []struct {
		entry, peer string
		trusted     bool
	}{
		{"192.0.2.10", "192.0.2.10", true},
		{" 192.0.2.10 ", "::ffff:192.0.2.10", true},
		{"::ffff:192.0.2.10", "192.0.2.10", true},
		{"192.0.2.0/24", "::ffff:192.0.2.10", true},
		{"::ffff:192.0.2.0/120", "192.0.2.10", true},
		{"2001:db8::/32", "2001:db8::1", true},
		// Loopback is never trusted: any local account can connect from it.
		{"::1", "::1", false},
		{"192.0.2.0/24", "198.51.100.10", false},
		{"", "192.0.2.10", false},
		{"  ", "192.0.2.10", false},
		{"localhost", "127.0.0.1", false},
		{"[::1]", "::1", false},
		{"192.0.2.0/99", "192.0.2.10", false},
	} {
		t.Run(tc.entry+"/"+tc.peer, func(t *testing.T) {
			entries := []string{tc.entry}
			got := extractVia(t, entries, net.JoinHostPort(tc.peer, "1234"), "203.0.113.20")
			want := canonicalIP(tc.peer)
			if tc.trusted {
				want = "203.0.113.20"
			}
			if got != want {
				t.Errorf("server used %q, want %q", got, want)
			}
		})
	}
}

func TestDoctorGateRequestIsReadOnly(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		for _, pending := range []bool{false, true} {
			name := fmt.Sprintf("trusted=%v/pending=%v", trusted, pending)
			t.Run(name, func(t *testing.T) {
				cfg := baseCfg()
				if trusted {
					cfg.Challenge.TrustedProxies = []string{"198.51.100.2"}
				}
				s, list := newTestServer(t, cfg)
				const visitor = "192.0.2.1"
				if pending {
					list.Add(visitor, "test", time.Hour)
				}
				beforeEntry := list.ips[visitor]
				beforeMap, err := os.ReadFile(list.path)
				if err != nil {
					t.Fatal(err)
				}
				for range 2 {
					req := httptest.NewRequest(http.MethodHead, "/challenge/gate", nil)
					req.RemoteAddr = "198.51.100.2:1234"
					req.Header.Set("X-Forwarded-For", visitor)
					rec := httptest.NewRecorder()
					s.srv.Handler.ServeHTTP(rec, req)
					want := http.StatusNoContent
					if trusted && pending {
						want = http.StatusUnauthorized
					}
					if rec.Code != want {
						t.Fatalf("gate = %d, want %d", rec.Code, want)
					}
					if len(rec.Result().Cookies()) != 0 {
						t.Fatal("probe issued a cookie")
					}
				}
				if list.Contains(visitor) != pending || !reflect.DeepEqual(beforeEntry, list.ips[visitor]) {
					t.Fatal("probe changed pending challenge state")
				}
				afterMap, err := os.ReadFile(list.path)
				if err != nil {
					t.Fatal(err)
				}
				if string(afterMap) != string(beforeMap) || len(s.verified) != 0 || len(s.adminFailures) != 0 {
					t.Fatal("probe changed list, verification or authentication state")
				}
			})
		}
	}
}

func extractVia(t *testing.T, trusted []string, peer, xff string) string {
	t.Helper()
	cfg := baseCfg()
	cfg.Challenge.TrustedProxies = trusted
	s := New(cfg, nil)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = peer
	req.Header.Set("X-Forwarded-For", xff)
	return s.extractIP(req)
}

// A catch-all entry is never trusted: a forwarded request names nobody, so
// no visitor's pass is issued for an address a header could forge, and a
// direct request is its own client.
func TestExtractIPNamesNobodyBehindARefusedCatchAll(t *testing.T) {
	for _, tc := range []struct{ entry, peer, client string }{
		{"0.0.0.0/0", "198.51.100.10:1234", "198.51.100.10"},
		{"::ffff:0:0/96", "198.51.100.10:1234", "198.51.100.10"},
		{"::ffff:192.0.2.10/0", "[2001:db8::10]:1234", "2001:db8::10"},
	} {
		if got := extractVia(t, []string{tc.entry}, tc.peer, "203.0.113.20"); got != "" {
			t.Errorf("%s: forwarded request resolved to %q, want nobody", tc.entry, got)
		}
		if got := extractVia(t, []string{tc.entry}, tc.peer, ""); got != tc.client {
			t.Errorf("%s: direct request resolved to %q, want %s", tc.entry, got, tc.client)
		}
	}
}

func TestExtractIPTrustedProxyCIDR(t *testing.T) {
	for _, tc := range []struct{ cidr, peer string }{
		{"192.0.2.0/24", "192.0.2.7:1234"},
		{"192.0.2.0/24", "[::ffff:192.0.2.7]:1234"},
		{"::ffff:192.0.2.0/120", "192.0.2.7:1234"},
		{"2001:db8:1::/48", "[2001:db8:1::7]:1234"},
	} {
		t.Run(tc.cidr+"/"+tc.peer, func(t *testing.T) {
			if got := extractVia(t, []string{tc.cidr}, tc.peer, "203.0.113.10"); got != "203.0.113.10" {
				t.Errorf("got %q, want the client behind a proxy inside the trusted range", got)
			}
		})
	}
}

func TestExtractIPStopsAtUnreadableEntry(t *testing.T) {
	for _, xff := range []string{"198.51.100.7, unknown", "198.51.100.7, , ", "198.51.100.7,203.0.113.10:80"} {
		if got := extractVia(t, []string{"192.0.2.1"}, "192.0.2.1:1234", xff); got != "" {
			t.Errorf("XFF %q: got %q, want no client: an unreadable hop ends the chain, never at the proxy", xff, got)
		}
	}
}

func TestExtractIPSkipsTrustedHops(t *testing.T) {
	if got := extractVia(t, []string{"192.0.2.1", "192.0.2.2"}, "192.0.2.1:1234", "203.0.113.10, 192.0.2.2"); got != "203.0.113.10" {
		t.Errorf("got %q, want the client past the trusted hop", got)
	}
}

func TestExtractIPAcrossHeaderLines(t *testing.T) {
	cfg := baseCfg()
	cfg.Challenge.TrustedProxies = []string{"192.0.2.0/24", "2001:db8:1::/48"}
	s := New(cfg, nil)
	for _, tc := range []struct {
		name string
		xff  []string
		want string
	}{
		{"appended client", []string{"198.51.100.7", "203.0.113.10"}, "203.0.113.10"},
		{"trusted suffix", []string{"198.51.100.7", "203.0.113.10, 192.0.2.2"}, "203.0.113.10"},
		{"trusted separate line", []string{"198.51.100.7, 203.0.113.10", "192.0.2.2"}, "203.0.113.10"},
		{"unreadable suffix", []string{"198.51.100.7", "unknown, 192.0.2.2"}, ""},
		{"empty final line", []string{"198.51.100.7", ""}, ""},
		{"empty middle line", []string{"198.51.100.7", "", "192.0.2.2"}, ""},
		{"unreadable client text", []string{"unknown", "203.0.113.10"}, "203.0.113.10"},
		{"all trusted", []string{"192.0.2.2", "192.0.2.3"}, ""},
		{"absent", nil, ""},
		{"mapped IPv4", []string{"198.51.100.7", "::ffff:203.0.113.10, ::ffff:192.0.2.2"}, "203.0.113.10"},
		{"IPv6", []string{"198.51.100.7", "2001:db8:2::1, 2001:db8:1::2"}, "2001:db8:2::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
			req.RemoteAddr = "192.0.2.1:1234"
			for _, line := range tc.xff {
				req.Header.Add("X-Forwarded-For", line)
			}
			if got := s.extractIP(req); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
			req.RemoteAddr = "198.51.100.200:1234"
			if got := s.extractIP(req); got != "198.51.100.200" {
				t.Errorf("untrusted peer: got %q, want peer", got)
			}
		})
	}
}

type proxyTestCaptcha struct{ calls int }

func (*proxyTestCaptcha) Name() string { return "turnstile" }

func (p *proxyTestCaptcha) Verify(context.Context, string, string) (bool, error) {
	p.calls++
	return true, nil
}

// Even valid credentials must not turn an unidentified visitor into a
// verified proxy, or every visitor sharing that proxy can use the bypass.
func TestChallengeHandlersRejectProxyFallback(t *testing.T) {
	for _, trusted := range [][]string{{"192.0.2.1", "192.0.2.2"}, {"192.0.2.0/24"}} {
		for _, chain := range []struct {
			name string
			xff  []string
		}{
			{"absent", nil},
			{"empty", []string{""}},
			{"unreadable", []string{"198.51.100.7, unknown"}},
			{"all trusted", []string{"192.0.2.2"}},
			{"all trusted lines", []string{"192.0.2.2", "192.0.2.1"}},
			{"unreadable past trusted", []string{"198.51.100.7, unknown, 192.0.2.2"}},
		} {
			for _, endpoint := range []struct {
				name, method, path, cookie string
			}{
				{"page", http.MethodGet, "/challenge", ""},
				{"proof of work", http.MethodPost, "/challenge/verify", ""},
				{"captcha", http.MethodPost, "/challenge/captcha-verify", ""},
				{"admin token", http.MethodPost, "/challenge/admin-token", ""},
				{"gate", http.MethodGet, "/challenge/gate", ""},
				{"verify cookie page", http.MethodGet, "/challenge", "csm_verified"},
				{"verify cookie gate", http.MethodGet, "/challenge/gate", "csm_verified"},
				{"admin cookie page", http.MethodGet, "/challenge", "csm_admin_session"},
				{"admin cookie gate", http.MethodGet, "/challenge/gate", "csm_admin_session"},
			} {
				t.Run(trusted[0]+"/"+chain.name+"/"+endpoint.name, func(t *testing.T) {
					cfg := baseCfg()
					cfg.Challenge.TrustedProxies = trusted
					cfg.Challenge.VerifiedSession.Enabled = true
					cfg.Challenge.VerifiedSession.AdminSecret = generateNonce()
					s, list := newTestServer(t, cfg)
					provider := &proxyTestCaptcha{}
					s.captcha = provider
					const peer = "192.0.2.1"
					list.Add(peer, "test", time.Hour)
					list.Add("192.0.2.2", "test", time.Hour)
					form := verifyForm(s, peer)
					form.Set("secret", cfg.Challenge.VerifiedSession.AdminSecret)
					form.Set("captcha-token", generateNonce())
					req := httptest.NewRequest(endpoint.method, endpoint.path, strings.NewReader(form.Encode()))
					req.RemoteAddr = "[::ffff:192.0.2.1]:1234"
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					for _, line := range chain.xff {
						req.Header.Add("X-Forwarded-For", line)
					}
					if endpoint.cookie != "" {
						signer := s.verifySigner
						if endpoint.cookie == "csm_admin_session" {
							signer = s.sessionSigner
						}
						req.AddCookie(&http.Cookie{Name: endpoint.cookie, Value: signer.Issue(peer)})
					}
					rec := httptest.NewRecorder()
					s.srv.Handler.ServeHTTP(rec, req)
					if rec.Code != http.StatusBadRequest {
						t.Errorf("status = %d, want 400", rec.Code)
					}
					if len(rec.Result().Cookies()) != 0 || strings.Contains(rec.Body.String(), "nonce") {
						t.Error("unidentified visitor received a cookie or puzzle")
					}
					if !list.Contains(peer) || !list.Contains("192.0.2.2") {
						t.Error("unidentified visitor cleared a proxy's pending challenge")
					}
					if provider.calls != 0 || len(s.verified) != 0 || len(s.adminFailures) != 0 {
						t.Error("unidentified visitor reached verification or authentication")
					}
				})
			}
		}
	}
}

func TestVerifyRepeatedHeadersOnlyClearsObservedClient(t *testing.T) {
	const client, forged = "203.0.113.10", "198.51.100.7"
	cfg := baseCfg()
	cfg.Challenge.TrustedProxies = []string{"192.0.2.0/24"}
	s, list := newTestServer(t, cfg)
	list.Add(client, "test", time.Hour)
	list.Add(forged, "test", time.Hour)
	for _, ip := range []string{forged, client} {
		form := verifyForm(s, ip)
		req := httptest.NewRequest(http.MethodPost, "/challenge/verify", strings.NewReader(form.Encode()))
		req.RemoteAddr = "192.0.2.1:1234"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Add("X-Forwarded-For", forged)
		req.Header.Add("X-Forwarded-For", client+", 192.0.2.2")
		rec := httptest.NewRecorder()
		s.srv.Handler.ServeHTTP(rec, req)
		if !list.Contains(forged) {
			t.Error("client-written address was unchallenged")
		}
		if ip == forged {
			if rec.Code != http.StatusForbidden || !list.Contains(client) || len(rec.Result().Cookies()) != 0 {
				t.Error("token for a client-written address was accepted")
			}
			continue
		}
		if rec.Code != http.StatusOK || list.Contains(client) {
			t.Errorf("observed client did not pass: status = %d", rec.Code)
		}
		cookies := rec.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Name != "csm_verified" {
			t.Fatal("expected one verification cookie")
		}
		if s.verifySigner.Verify(cookies[0].Value, client) != nil || s.verifySigner.Verify(cookies[0].Value, forged) == nil {
			t.Error("cookie is not bound to the observed client")
		}
	}
}

func TestGateRejectsProxyFallbackWithoutChallengeList(t *testing.T) {
	cfg := baseCfg()
	cfg.Challenge.TrustedProxies = []string{"2001:db8:1::/48"}
	s := New(cfg, nil)
	req := httptest.NewRequest(http.MethodGet, "/challenge/gate", nil)
	req.RemoteAddr = "[2001:db8:1::7]:1234"
	rec := httptest.NewRecorder()
	s.srv.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unidentified visitor without a challenge list: status = %d, want 400", rec.Code)
	}
}
