package challenge

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/netutil"
)

const adminTestSecret = "admin-secret-for-host-tests"

func adminTokenServer(t *testing.T, trusted ...string) *Server {
	t.Helper()
	cfg := baseCfg()
	cfg.Challenge.TrustedProxies = trusted
	cfg.Challenge.VerifiedSession.Enabled = true
	cfg.Challenge.VerifiedSession.AdminSecret = adminTestSecret
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
			rr := postAdminToken(s, tc.remote, tc.xff, adminTestSecret)
			if rr.Code != http.StatusForbidden || len(rr.Result().Cookies()) != 0 {
				t.Fatalf("correct secret: status %d cookies %v, want 403 and none", rr.Code, rr.Result().Cookies())
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
		if rr := postAdminToken(s, "198.51.100.20:5000", "", adminTestSecret); rr.Code != http.StatusNoContent {
			t.Fatalf("status %d, want 204", rr.Code)
		}
	})
}

func TestAdminTokenRefusesWhenHostAddressesUnknown(t *testing.T) {
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		return nil, errors.New("interface lookup unavailable")
	}))
	s := adminTokenServer(t)
	rr := postAdminToken(s, "198.51.100.20:5000", "", adminTestSecret)
	if rr.Code != http.StatusServiceUnavailable || len(rr.Result().Cookies()) != 0 {
		t.Fatalf("status %d cookies %v, want 503 and none", rr.Code, rr.Result().Cookies())
	}
}
