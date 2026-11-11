package checks

import (
	"net"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestDirectSMTPEgressUsesLoadedSenderDefaults(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		allowed    map[string]bool
	}{
		{"omitted", "", map[string]bool{"cpanel": true, "mailman": true}},
		{"null", "firewall:\n  smtp_allow_users:\n", map[string]bool{"cpanel": true, "mailman": true}},
		{"empty", "firewall:\n  smtp_allow_users: []\n", nil},
		{"custom", "firewall:\n  smtp_allow_users: [alice]\n", map[string]bool{"alice": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.LoadBytes([]byte("detection:\n  direct_smtp_egress:\n    enabled: true\n" + tc.yaml))
			if err != nil {
				t.Fatal(err)
			}
			for _, user := range []string{"cpanel", "mailman", "alice", ""} {
				if got := SMTPAllowedUser(cfg, user); got != tc.allowed[user] {
					t.Errorf("SMTPAllowedUser(%q) = %t, want %t", user, got, tc.allowed[user])
				}
				_, found := EvaluateDirectSMTPEgress(cfg, DirectSMTPEgressInput{
					UID: 1001, User: user,
					DstIP: net.ParseIP("203.0.113.10"), DstPort: 587,
					MTA: sampleMTA(),
				})
				// Mailman's MTA exemption is independent of the extra sender list.
				wantFinding := !tc.allowed[user] && user != "mailman"
				if found != wantFinding {
					t.Errorf("direct egress finding for %q = %t, want %t", user, found, wantFinding)
				}
			}
		})
	}
}
