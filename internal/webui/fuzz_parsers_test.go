package webui

import (
	"net/netip"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// FuzzHistoryAttribution exercises the legacy account/IP extractors that read
// attacker-controlled finding message and detail text when structured fields
// are absent. They must never panic, and any IP the endpoint attributes from
// that text must parse back as a valid address or prefix (it is run through
// netip before being returned).
func FuzzHistoryAttribution(f *testing.F) {
	f.Add("email_auth_failure_realtime", "Mail auth brute force from 198.51.100.12: 10 failed", "set_id=legacy@example.com [2001:db8::3]:465")
	f.Add("mail_bruteforce", "", "rip=2001:db8::4, lip=10.0.0.1")
	f.Add("webshell", "Account ignored@example.net from 192.0.2.44", "")
	f.Add("smtp_probe", "from [::1]:25 for a@b", "Domain: example.org")
	f.Add("email_suspicious_geo", "login for geo@example.com from ZZ", "rip=]]]:::not-an-ip")

	f.Fuzz(func(t *testing.T, check, message, details string) {
		out := withAccountIP([]alert.Finding{{Check: check, Message: message, Details: details}})
		if len(out) != 1 {
			t.Fatalf("withAccountIP returned %d findings, want 1", len(out))
		}
		// SourceIP is left empty above, so any returned IP came from text
		// parsing and must be a valid netip address or prefix.
		if ip := out[0].IP; ip != "" {
			if _, errA := netip.ParseAddr(ip); errA != nil {
				if _, errP := netip.ParsePrefix(ip); errP != nil {
					t.Errorf("findingIP returned non-IP %q from message=%q details=%q", ip, message, details)
				}
			}
		}
	})
}
