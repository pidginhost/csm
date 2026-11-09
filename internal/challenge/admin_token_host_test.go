package challenge

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/netutil"
)

func adminTokenServer(t *testing.T, trusted ...string) *Server {
	t.Helper()
	cfg := baseCfg()
	cfg.Challenge.TrustedProxies = trusted
	cfg.Challenge.VerifiedSession.Enabled = true
	cfg.Challenge.VerifiedSession.AdminSecret = generateNonce()
	s, _ := newTestServer(t, cfg)
	return s
}

func postAdminToken(s *Server, remote, xff, secret string) *httptest.ResponseRecorder {
	form := url.Values{"secret": {secret}}
	req := httptest.NewRequest(http.MethodPost, "/challenge/admin-token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = remote
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	rr := httptest.NewRecorder()
	s.handleAdminToken(rr, req)
	return rr
}

// Every local account can send from loopback and this host's addresses, so
// a per-address failure budget there gives one account millions of guesses.
func TestAdminTokenRefusesThisHostsAddresses(t *testing.T) {
	const proxy = "198.51.100.2"
	for _, tc := range []struct {
		name, remote, xff string
		trusted           []string
	}{
		{"loopback", "127.0.0.1:5000", "", nil},
		{"other loopback", "127.0.0.77:5000", "", nil},
		{"ipv6 loopback", "[::1]:5000", "", nil},
		{"mapped loopback", "[::ffff:127.0.0.2]:5000", "", nil},
		{"host address", net.JoinHostPort(testHostAddr, "5000"), "", nil},
		{"loopback via proxy", proxy + ":5000", "127.0.0.9", []string{proxy}},
		{"host address via proxy", proxy + ":5000", testHostAddr, []string{proxy}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := adminTokenServer(t, tc.trusted...)
			rr := postAdminToken(s, tc.remote, tc.xff, s.cfg.Challenge.VerifiedSession.AdminSecret)
			if rr.Code != http.StatusForbidden || len(rr.Result().Cookies()) != 0 {
				t.Fatalf("correct secret: status %d, cookie count %d, want 403 and none", rr.Code, len(rr.Result().Cookies()))
			}
			for i := 0; i < adminMaxFailuresInWindow+2; i++ {
				if rr := postAdminToken(s, tc.remote, tc.xff, "wrong"); rr.Code != http.StatusForbidden {
					t.Fatalf("wrong secret %d: status %d, want 403", i, rr.Code)
				}
			}
			s.adminFailuresMu.Lock()
			n := len(s.adminFailures)
			s.adminFailuresMu.Unlock()
			if n != 0 {
				t.Errorf("refused requests left %d failure entries; want none", n)
			}
		})
	}

	t.Run("remote visitor still served", func(t *testing.T) {
		s := adminTokenServer(t)
		if rr := postAdminToken(s, "198.51.100.20:5000", "", s.cfg.Challenge.VerifiedSession.AdminSecret); rr.Code != http.StatusNoContent {
			t.Fatalf("status %d, want 204", rr.Code)
		}
	})
}

func TestAdminTokenRefusesWhenHostAddressesUnknown(t *testing.T) {
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		return nil, errors.New("interface lookup unavailable")
	}))
	s := adminTokenServer(t)
	rr := postAdminToken(s, "198.51.100.20:5000", "", s.cfg.Challenge.VerifiedSession.AdminSecret)
	if rr.Code != http.StatusServiceUnavailable || len(rr.Result().Cookies()) != 0 {
		t.Fatalf("status %d, cookie count %d, want 503 and none", rr.Code, len(rr.Result().Cookies()))
	}
}

type adminTokenBody struct {
	io.Reader
	reads int
}

func (b *adminTokenBody) Read(p []byte) (int, error) {
	b.reads++
	return b.Reader.Read(p)
}

// The proxy appends the observed sender after client-written headers. Local
// senders must not gain a fresh failure budget by supplying a remote prefix.
func TestAdminTokenChecksForwardedVisitorBeforeReadingSecret(t *testing.T) {
	const hostV6 = "2001:db8::250"
	pinHost(t, testHostAddr, hostV6)
	for _, transport := range []string{"tcp", "unix"} {
		t.Run(transport, func(t *testing.T) {
			for _, tc := range []struct {
				name, ip string
				local    bool
			}{
				{"loopback", "127.0.0.77", true},
				{"ipv6 loopback", "::1", true},
				{"mapped loopback", "::ffff:127.0.0.77", true},
				{"host ipv4", testHostAddr, true},
				{"mapped host ipv4", "::ffff:" + testHostAddr, true},
				{"host ipv6", hostV6, true},
				{"remote ipv4", "192.0.2.20", false},
				{"remote ipv6", "2001:db8::20", false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					cfg := baseCfg()
					cfg.Challenge.TrustedProxies = []string{"198.51.100.0/24"}
					cfg.Challenge.VerifiedSession.Enabled = true
					cfg.Challenge.VerifiedSession.AdminSecret = generateNonce()
					if transport == "unix" {
						cfg.Challenge.ListenAddr = "unix:" + filepath.Join(t.TempDir(), "challenge.sock")
					}
					s, _ := newTestServer(t, cfg)
					form := url.Values{"secret": {cfg.Challenge.VerifiedSession.AdminSecret}}
					body := &adminTokenBody{Reader: strings.NewReader(form.Encode())}
					req := httptest.NewRequest(http.MethodPost, "/challenge/admin-token", body)
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					req.RemoteAddr = "198.51.100.2:5000"
					if transport == "unix" {
						req.RemoteAddr = "@"
					}
					req.Header.Add("X-Forwarded-For", "192.0.2.99")
					req.Header.Add("X-Forwarded-For", tc.ip+", 198.51.100.3")
					rr := httptest.NewRecorder()
					s.srv.Handler.ServeHTTP(rr, req)
					cookies := rr.Result().Cookies()
					if len(s.adminFailures) != 0 {
						t.Error("request left admin failure entries")
					}
					if tc.local {
						if rr.Code != http.StatusForbidden || len(cookies) != 0 || body.reads != 0 {
							t.Fatalf("local visitor: status %d, cookies %d, body reads %d; want 403, 0, 0", rr.Code, len(cookies), body.reads)
						}
						return
					}
					if rr.Code != http.StatusNoContent || len(cookies) != 1 || body.reads == 0 {
						t.Fatalf("remote visitor: status %d, cookies %d, body reads %d; want 204, 1, nonzero", rr.Code, len(cookies), body.reads)
					}
					if err := s.sessionSigner.Verify(cookies[0].Value, tc.ip); err != nil {
						t.Fatalf("cookie must bind to the resolved visitor: %v", err)
					}
				})
			}
		})
	}
}

func TestAdminTokenSocketRefusesLocalSender(t *testing.T) {
	group, _ := ownGroup(t)
	path := filepath.Join(shortSocketDir(t), "c.sock")
	cfg := socketCfg(path, group)
	cfg.Challenge.VerifiedSession.Enabled = true
	cfg.Challenge.VerifiedSession.AdminSecret = generateNonce()
	serveSocket(t, cfg, nil)
	client := socketClient(path)
	t.Cleanup(client.CloseIdleConnections)
	for _, ip := range []string{"127.0.0.77", "::1", testHostAddr, "192.0.2.20"} {
		t.Run(ip, func(t *testing.T) {
			form := url.Values{"secret": {cfg.Challenge.VerifiedSession.AdminSecret}}
			req, err := http.NewRequest(http.MethodPost, "http://csm-challenge/challenge/admin-token", strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-Forwarded-For", "192.0.2.99, "+ip)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			wantStatus, wantCookies := http.StatusForbidden, 0
			if ip == "192.0.2.20" {
				wantStatus, wantCookies = http.StatusNoContent, 1
			}
			if resp.StatusCode != wantStatus || len(resp.Cookies()) != wantCookies {
				t.Fatalf("status %d, cookies %d; want %d, %d", resp.StatusCode, len(resp.Cookies()), wantStatus, wantCookies)
			}
		})
	}
}
