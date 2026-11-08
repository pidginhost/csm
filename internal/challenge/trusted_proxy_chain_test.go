package challenge

import (
	"net/http/httptest"
	"testing"
)

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

func TestExtractIPTrustedProxyCIDR(t *testing.T) {
	if got := extractVia(t, []string{"10.0.0.0/24"}, "10.0.0.7:1234", "203.0.113.10"); got != "203.0.113.10" {
		t.Errorf("got %q, want the client behind a proxy inside the trusted range", got)
	}
}

func TestExtractIPStopsAtUnreadableEntry(t *testing.T) {
	for _, xff := range []string{"198.51.100.7, unknown", "198.51.100.7, , ", "198.51.100.7,203.0.113.10:80"} {
		if got := extractVia(t, []string{"10.0.0.1"}, "10.0.0.1:1234", xff); got == "198.51.100.7" {
			t.Errorf("XFF %q: took the client-supplied entry past an unreadable one", xff)
		}
	}
}

func TestExtractIPSkipsTrustedHops(t *testing.T) {
	if got := extractVia(t, []string{"10.0.0.1", "10.0.0.2"}, "10.0.0.1:1234", "203.0.113.10, 10.0.0.2"); got != "203.0.113.10" {
		t.Errorf("got %q, want the client past the trusted hop", got)
	}
}
