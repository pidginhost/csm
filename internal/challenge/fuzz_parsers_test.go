package challenge

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Arbitrary client header text cannot override the suffix observed by proxies,
// including when a proxy appends another field line instead of merging them.
func FuzzExtractIPClientPrefix(f *testing.F) {
	for _, prefix := range []string{"", "198.51.100.7", "unknown", "192.0.2.2\n198.51.100.7", "2001:db8::7, "} {
		f.Add(prefix)
	}
	cfg := baseCfg()
	cfg.Challenge.TrustedProxies = []string{"192.0.2.0/24"}
	s := New(cfg, nil)
	f.Fuzz(func(t *testing.T, prefix string) {
		for _, suffix := range []struct{ text, want string }{
			{"203.0.113.10, 192.0.2.2", "203.0.113.10"},
			{"unknown, 192.0.2.2", "192.0.2.1"},
			{", 192.0.2.2", "192.0.2.1"},
		} {
			req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
			req.RemoteAddr = "192.0.2.1:1234"
			for _, line := range strings.Split(prefix, "\n") {
				req.Header.Add("X-Forwarded-For", line)
			}
			req.Header.Add("X-Forwarded-For", suffix.text)
			if got := s.extractIP(req); got != suffix.want {
				t.Fatalf("prefix %q: got %q, want %q", prefix, got, suffix.want)
			}
		}
	})
}
