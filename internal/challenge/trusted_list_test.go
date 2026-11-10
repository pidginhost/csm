package challenge

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/clientaddr"
	"github.com/pidginhost/csm/internal/netutil"
)

// web_server.trusted_proxies and challenge.trusted_proxies are one list: a
// proxy trusted for the sites is trusted here too.
func TestExtractIPTrustsWebServerProxies(t *testing.T) {
	cfg := baseCfg()
	cfg.WebServer.TrustedProxies = []string{"192.0.2.0/24"}
	s := New(cfg, nil)
	req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.7, 203.0.113.10")
	if got := s.extractIP(req); got != "203.0.113.10" {
		t.Fatalf("got %q, want the client a web_server trusted proxy appended", got)
	}
}

// A chain over 32 hops or 4 KiB names no client, so the handlers refuse it.
func TestExtractIPRefusesOverlongChains(t *testing.T) {
	cfg := baseCfg()
	cfg.Challenge.TrustedProxies = []string{"192.0.2.0/24"}
	s := New(cfg, nil)
	for name, xff := range map[string]string{
		"33 hops":   strings.Repeat("198.51.100.7, ", clientaddr.MaxHops) + "203.0.113.10",
		"over 4KiB": strings.Repeat(" ", clientaddr.MaxChainBytes) + "203.0.113.10",
	} {
		req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
		req.RemoteAddr = "192.0.2.1:1234"
		req.Header.Set("X-Forwarded-For", xff)
		if got := s.extractIP(req); got != "" {
			t.Errorf("%s: got %q, want no client", name, got)
		}
		rec := httptest.NewRecorder()
		s.handleChallenge(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: handler status %d, want 400", name, rec.Code)
		}
	}
}

// A listed proxy is never a visitor, even while the host's interfaces cannot
// be read and so its header is not trusted: the handlers refuse it.
func TestChallengeRefusesAListedPeerWhoseTrustIsUnknown(t *testing.T) {
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) { return nil, errors.New("no interface list") }))
	cfg := baseCfg()
	cfg.WebServer.TrustedProxies = []string{"192.0.2.0/24"}
	s := New(cfg, nil)
	req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	rec := httptest.NewRecorder()
	s.handleChallenge(rec, req)
	if rec.Code != http.StatusBadRequest || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("listed peer with unknown trust: status %d, cookies %d; want 400 and none", rec.Code, len(rec.Result().Cookies()))
	}
}
