package checks

import (
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// The subnet block of a password spray follows the subnet in its message;
// SourceIP is never read, and the per-address path never acts on a spray.
func TestSprayPinSubnetBlockFollowsTheMessage(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.StatePath = t.TempDir()
	setAutoResponseLive(cfg)
	setAutoBlockNow(t, time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC))

	fake := &recordingIPBlocker{}
	prev := getIPBlocker()
	SetIPBlocker(fake)
	t.Cleanup(func() { SetIPBlocker(prev) })

	findings := []alert.Finding{
		{Check: "mail_subnet_spray", Severity: alert.Critical, SourceIP: "198.51.100.0/24", Message: "Mail password spray from 203.0.113.0/24: 8 unique IPs in 10m0s"},
		{Check: "smtp_subnet_spray", Severity: alert.Critical, SourceIP: "203.0.113.0/24", Message: "SMTP password spray from 192.0.2.0/24: 8 unique IPs in 10m0s"},
		{Check: "mail_subnet_spray", Severity: alert.Critical, SourceIP: "198.51.100.0/24", Message: "Mail password spray burst"},
		{Check: "smtp_subnet_spray", Severity: alert.Critical, SourceIP: "198.51.100.0/24", Message: "SMTP password spray burst"},
	}
	for _, f := range findings {
		if blockableFinding(f, true) || extractIPFromFinding(f) != "" {
			t.Errorf("%s reaches the per-address path", f.Check)
		}
	}
	AutoBlockIPs(cfg, findings)
	if !slices.Equal(fake.blockedSubnet, []string{"203.0.113.0/24", "192.0.2.0/24"}) || len(fake.blocked) != 0 {
		t.Fatalf("blocked subnets %v and addresses %v, want only both message subnets", fake.blockedSubnet, fake.blocked)
	}
}
