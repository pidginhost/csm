package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func originProbe(t *testing.T, s *Server, origin string) int {
	t.Helper()
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	req := httptest.NewRequest("POST", "/api/v1/status", nil)
	req.Host = "myhost.example.com:9443"
	req.Header.Set("Origin", origin)
	w := httptest.NewRecorder()
	s.securityHeaders(inner).ServeHTTP(w, req)
	return w.Code
}

// The only accepted origin was https://<hostname>:<port>. An operator on an
// SSH tunnel (https://localhost:9443) or on a second name for the host got a
// read-only UI: every POST was rejected as cross-origin. webui.allowed_origins
// lists further names; loopback origins are accepted as the request's own
// origin (TestLoopbackOriginsMustMatchTheRequestHost), and this probe sends
// Host myhost.example.com:9443, so here they are foreign.
func TestSecurityHeadersAcceptsLoopbackAndListedOrigins(t *testing.T) {
	prevActive := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(prevActive) })

	s := newTestServer(t, "tok")
	s.cfg.WebUI.Listen = ":9443"
	s.cfg.Hostname = "myhost.example.com"
	s.cfg.WebUI.AllowedOrigins = []string{"https://ops.example.net:9443"}

	for _, origin := range []string{"https://ops.example.net:9443", "https://myhost.example.com:9443"} {
		if code := originProbe(t, s, origin); code != http.StatusOK {
			t.Fatalf("origin %s rejected with %d", origin, code)
		}
	}
	for _, origin := range []string{"https://evil.example.com", "https://ops.example.net", "http://localhost:9443", "https://localhost.evil.example:9443", "https://127.0.0.1.evil:9443", "https://localhost:9443", "https://[::1]:9443"} {
		if code := originProbe(t, s, origin); code != http.StatusForbidden {
			t.Fatalf("origin %s accepted with %d", origin, code)
		}
	}
}

func originProbeHost(t *testing.T, s *Server, origin, host string) int {
	t.Helper()
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	req := httptest.NewRequest("POST", "/api/v1/status", nil)
	req.Host = host
	req.Header.Set("Origin", origin)
	w := httptest.NewRecorder()
	s.securityHeaders(inner).ServeHTTP(w, req)
	return w.Code
}

// A loopback origin is trusted only as the same origin the request was sent
// to, which is what an SSH tunnel on any local port produces. Another local
// service (https://localhost:1234) reaching the Web UI through the same
// browser shares its cookies, since cookies ignore the port; it must not get
// credentialed cross-origin access.
func TestLoopbackOriginsMustMatchTheRequestHost(t *testing.T) {
	prevActive := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(prevActive) })
	s := newTestServer(t, "tok")
	s.cfg.WebUI.Listen = ":9443"
	s.cfg.Hostname = "myhost.example.com"

	for _, tc := range []struct{ origin, host string }{
		{"https://localhost:9443", "localhost:9443"},
		{"https://localhost:18443", "localhost:18443"},
		{"https://127.0.0.1:9443", "127.0.0.1:9443"},
		{"https://[::1]:8443", "[::1]:8443"},
		{"https://[::ffff:127.0.0.1]:9443", "[::ffff:127.0.0.1]:9443"},
	} {
		if code := originProbeHost(t, s, tc.origin, tc.host); code != http.StatusOK {
			t.Errorf("tunnel origin %s to %s rejected with %d", tc.origin, tc.host, code)
		}
	}
	for _, tc := range []struct{ origin, host string }{
		{"https://localhost:1234", "localhost:9443"},
		{"https://127.0.0.1:1234", "127.0.0.1:9443"},
		{"https://localhost:9443", "myhost.example.com:9443"},
	} {
		if code := originProbeHost(t, s, tc.origin, tc.host); code != http.StatusForbidden {
			t.Errorf("loopback origin %s to %s accepted with %d", tc.origin, tc.host, code)
		}
	}
}

func TestCanonicalLoopbackOriginStillRequiresMatchingHost(t *testing.T) {
	s := newTestServer(t, randomBrowserCredential())
	s.cfg.Hostname = "localhost"
	s.cfg.WebUI.Listen = ":9443"
	if code := originProbeHost(t, s, "https://localhost:9443", "localhost:18443"); code != http.StatusForbidden {
		t.Fatalf("canonical loopback origin bypassed Host check: %d", code)
	}
	for _, tc := range []struct{ origin, host string }{
		{"https://localhost", "LOCALHOST:443"},
		{"https://localhost:18443", "LOCALHOST:18443"},
	} {
		if code := originProbeHost(t, s, tc.origin, tc.host); code != http.StatusOK {
			t.Fatalf("same-origin tunnel rejected: %d", code)
		}
	}
}
