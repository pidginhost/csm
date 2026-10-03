package webui

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// The history row and the email groups show a spray's structured subnet the
// way they show a subnet in SourceIP.
func TestSprayCIDRHistoryAndGroups(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	structured := func(check, cidr string, at time.Time) alert.Finding {
		return alert.Finding{Check: check, Severity: alert.Critical, Message: check + " event", CIDRs: []string{cidr}, Timestamp: at}
	}
	rows := withAccountIP([]alert.Finding{structured("mail_subnet_spray", "203.0.113.0/24", now)})
	if len(rows) != 1 || rows[0].IP != "203.0.113.0/24" {
		t.Fatalf("history rows %+v, want the subnet as IP", rows)
	}
	groups := buildEmailGroups([]alert.Finding{
		structured("mail_subnet_spray", "203.0.113.0/24", now.Add(-3*time.Minute)),
		emailFinding("smtp_subnet_spray", alert.Critical, "", "", "203.0.113.0/24", now.Add(-2*time.Minute)),
		structured("smtp_subnet_spray", "198.51.100.0/24", now.Add(-time.Minute)),
	}, now.Add(-time.Hour), now, "")
	got := map[string]int{}
	for _, g := range groups {
		if g.Kind != "auth_failure" || g.Subject != "ip" || len(g.IPs) != 1 || g.IPs[0] != g.Title {
			t.Errorf("group kind %q title %q subject %q ips %v, want an auth_failure group per subnet", g.Kind, g.Title, g.Subject, g.IPs)
		}
		got[g.Title] = g.Count
	}
	if len(got) != 2 || got["203.0.113.0/24"] != 2 || got["198.51.100.0/24"] != 1 {
		t.Fatalf("groups by subnet %v, want structured and legacy sprays merged per subnet", got)
	}
}
