package webui

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A mail or SMTP password spray names a subnet, not an address. The history
// row and the email groups show that subnet today; moving it to a structured
// field must keep what an operator sees.
func TestSprayPinHistoryRowShowsTheSubnet(t *testing.T) {
	rows := withAccountIP([]alert.Finding{
		{Check: "mail_subnet_spray", Severity: alert.Critical, SourceIP: "203.0.113.0/24", Message: "Mail password spray from 203.0.113.0/24: 8 unique IPs in 10m0s"},
		{Check: "smtp_subnet_spray", Severity: alert.Critical, Message: "SMTP password spray from 198.51.100.0/24: 8 unique IPs in 10m0s"},
	})
	for i, want := range []string{"203.0.113.0/24", "198.51.100.0/24"} {
		if rows[i].IP != want || rows[i].Account != "" {
			t.Errorf("row %d: ip %q account %q, want %q and no account", i, rows[i].IP, rows[i].Account, want)
		}
	}
}

func TestSprayPinEmailGroupsKeyOnTheSubnet(t *testing.T) {
	now := time.Now()
	in := []alert.Finding{
		emailFinding("mail_subnet_spray", alert.Critical, "", "", "203.0.113.0/24", now.Add(-3*time.Minute)),
		emailFinding("smtp_subnet_spray", alert.Critical, "", "", "203.0.113.0/24", now.Add(-2*time.Minute)),
		emailFinding("mail_subnet_spray", alert.Critical, "", "", "198.51.100.0/24", now.Add(-time.Minute)),
	}
	groups := buildEmailGroups(in, now.Add(-time.Hour), now, "")
	got := map[string]string{}
	for _, g := range groups {
		if g.Kind != "auth_failure" || g.Subject != "ip" || len(g.IPs) != 1 || g.IPs[0] != g.Title {
			t.Errorf("group = kind %q title %q subject %q ips %v, want an auth_failure group per subnet", g.Kind, g.Title, g.Subject, g.IPs)
		}
		got[g.Title] = fmt.Sprint(g.Count)
	}
	if fmt.Sprint(got) != "map[198.51.100.0/24:1 203.0.113.0/24:2]" {
		t.Fatalf("groups by subnet = %v, want one group per subnet", got)
	}
}
