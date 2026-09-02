package netutil

import (
	"net"
	"testing"
)

func FuzzParseIPToken(f *testing.F) {
	for _, seed := range []string{
		"203.0.113.5",
		"[2001:db8::1]:443,",
		"2001:db8:::",
		"not-an-address",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, token string) {
		got, ok := ParseIPToken(token)
		if !ok {
			return
		}
		ip := net.ParseIP(got)
		if ip == nil {
			t.Fatalf("ParseIPToken(%q) returned invalid IP %q", token, got)
		}
		if canonical := ip.String(); got != canonical {
			t.Fatalf("ParseIPToken(%q) = %q, want canonical %q", token, got, canonical)
		}
	})
}
