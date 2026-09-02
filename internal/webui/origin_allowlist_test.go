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
// read-only UI: every POST was rejected as cross-origin. Loopback origins are
// always local, and webui.allowed_origins lists any further names.
func TestSecurityHeadersAcceptsLoopbackAndListedOrigins(t *testing.T) {
	prevActive := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(prevActive) })

	s := newTestServer(t, "tok")
	s.cfg.WebUI.Listen = ":9443"
	s.cfg.Hostname = "myhost.example.com"
	s.cfg.WebUI.AllowedOrigins = []string{"https://ops.example.net:9443"}

	for _, origin := range []string{"https://localhost:9443", "https://127.0.0.1:9443", "https://[::1]:9443", "https://[::ffff:127.0.0.1]:9443", "https://ops.example.net:9443", "https://myhost.example.com:9443"} {
		if code := originProbe(t, s, origin); code != http.StatusOK {
			t.Fatalf("origin %s rejected with %d", origin, code)
		}
	}
	for _, origin := range []string{"https://evil.example.com", "https://ops.example.net", "http://localhost:9443", "https://localhost.evil.example:9443", "https://127.0.0.1.evil:9443"} {
		if code := originProbe(t, s, origin); code != http.StatusForbidden {
			t.Fatalf("origin %s accepted with %d", origin, code)
		}
	}
}
