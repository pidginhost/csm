package checks

import (
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// The subnet block reads a spray's structured subnet first and the message
// only for findings without one, so the message can stop carrying it later.
func TestSpraySubnetBlockPrefersStructuredCIDR(t *testing.T) {
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

	AutoBlockIPs(cfg, []alert.Finding{
		{Check: "mail_subnet_spray", Severity: alert.Critical, CIDRs: []string{"203.0.113.0/24"}, Message: "Mail password spray burst"},
		{Check: "smtp_subnet_spray", Severity: alert.Critical, CIDRs: []string{"198.51.100.0/24"}, Message: "SMTP password spray from 192.0.2.0/24: 8 unique IPs in 10m0s"},
		{Check: "mail_subnet_spray", Severity: alert.Critical, Message: "Mail password spray from 192.0.2.0/24: 8 unique IPs in 10m0s"},
	})
	if !slices.Equal(fake.blockedSubnet, []string{"203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"}) || len(fake.blocked) != 0 {
		t.Fatalf("blocked subnets %v and addresses %v, want the structured subnets, then the message one", fake.blockedSubnet, fake.blocked)
	}
}
