package checks

import (
	"net/netip"
	"strings"
	"testing"
)

func FuzzParseStaleSessionRequest(f *testing.F) {
	f.Add(staleSessionAccessLine("198.51.100.7", "alice", "04/12/2026:07:00:05", staleTabPath, "401"))
	f.Add(staleSessionAccessLine("2001:db8::7", "-", "04/12/2026:07:00:05", staleTabPath, "401"))
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) {
		r, ok := ParseStaleSessionRequest(line)
		if !ok {
			if r != (StaleSessionRequest{}) {
				t.Fatal("rejected line returned partial evidence")
			}
			return
		}
		ip, err := netip.ParseAddr(r.IP)
		if err != nil || ip.String() != r.IP || r.Token == "" || r.User == "" || r.At.Nanosecond() != 0 {
			t.Fatalf("invalid session request: %+v", r)
		}
		if strings.Trim(r.Token, "0123456789") != "" {
			t.Fatalf("non-numeric URL token: %q", r.Token)
		}
	})
}

func FuzzParseSessionTokenDenial(f *testing.F) {
	f.Add(staleSessionDeniedLine)
	f.Add(strings.Replace(staleSessionDeniedLine, "198.51.100.7", "2001:db8::7", 1))
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) {
		d, ok := ParseSessionTokenDenial(line)
		if !ok {
			if d != (SessionTokenDenial{}) {
				t.Fatal("rejected line returned partial evidence")
			}
			return
		}
		ip, err := netip.ParseAddr(d.IP)
		if err != nil || ip.String() != d.IP || d.Account == "" || d.At.Nanosecond() != 0 {
			t.Fatalf("invalid token denial: %+v", d)
		}
	})
}
