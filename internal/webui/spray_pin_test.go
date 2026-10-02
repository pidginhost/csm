package webui

import (
	"maps"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A mail or SMTP password spray names a subnet, not an address. The history
// row and the email groups show that subnet today; moving it to a structured
// field must keep what an operator sees.
func TestSprayPinHistoryRowShowsTheSubnet(t *testing.T) {
	for _, check := range []string{"mail_subnet_spray", "smtp_subnet_spray"} {
		t.Run(check, func(t *testing.T) {
			rows := withAccountIP([]alert.Finding{
				{Check: check, Severity: alert.Critical, SourceIP: "203.0.113.0/24", Message: "Password spray from 198.51.100.0/24"},
				{Check: check, Severity: alert.Critical, Message: "Password spray from 198.51.100.0/24"},
				{Check: check, Severity: alert.Critical, Details: "Password spray from 192.0.2.0/24"},
			})
			if len(rows) != 3 {
				t.Fatalf("got %d history rows, want 3", len(rows))
			}
			for i, want := range []string{"203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"} {
				if rows[i].IP != want || rows[i].Account != "" {
					t.Errorf("row %d: ip %q account %q, want %q and no account", i, rows[i].IP, rows[i].Account, want)
				}
			}
		})
	}
}

func TestSprayPinEmailGroupsKeyOnTheSubnet(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	in := []alert.Finding{
		emailFinding("mail_subnet_spray", alert.Critical, "", "", "203.0.113.0/24", now.Add(-3*time.Minute)),
		emailFinding("smtp_subnet_spray", alert.Critical, "", "", "203.0.113.0/24", now.Add(-2*time.Minute)),
		emailFinding("mail_subnet_spray", alert.Critical, "", "", "198.51.100.0/24", now.Add(-time.Minute)),
	}
	groups := buildEmailGroups(in, now.Add(-time.Hour), now, "")
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2: %+v", len(groups), groups)
	}
	got := map[string]int{}
	for _, g := range groups {
		if g.Kind != "auth_failure" || g.Subject != "ip" || len(g.IPs) != 1 || g.IPs[0] != g.Title {
			t.Errorf("group = kind %q title %q subject %q ips %v, want an auth_failure group per subnet", g.Kind, g.Title, g.Subject, g.IPs)
		}
		if _, duplicate := got[g.Title]; duplicate {
			t.Fatalf("duplicate group for subnet %q", g.Title)
		}
		got[g.Title] = g.Count
	}
	if !maps.Equal(got, map[string]int{"198.51.100.0/24": 1, "203.0.113.0/24": 2}) {
		t.Fatalf("groups by subnet = %v, want one group per subnet", got)
	}
}
