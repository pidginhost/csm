package checks

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// dryRunSubnetConfig leaves auto_response.dry_run unset, which defaults to
// dry-run active.
func dryRunSubnetConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.BlockExpiry = "1h"
	return cfg
}

// subnetRecorder records subnet mutations and treats every IP as still
// blocked so seeded state survives the reconcile prune.
type subnetRecorder struct {
	blockedSubnets  []string
	unblockedSubnet []string
	subnets         []firewall.SubnetEntry
	validationErrs  map[string]error
	validated       []string
}

func (b *subnetRecorder) BlockIP(string, string, time.Duration) error { return nil }
func (b *subnetRecorder) UnblockIP(string) error                      { return nil }
func (b *subnetRecorder) IsBlocked(string) bool                       { return true }
func (b *subnetRecorder) BlockSubnet(cidr, _ string, _ time.Duration) error {
	b.blockedSubnets = append(b.blockedSubnets, cidr)
	return nil
}
func (b *subnetRecorder) IsSubnetBlocked(string) bool { return false }
func (b *subnetRecorder) BlockedSubnets() []firewall.SubnetEntry {
	return b.subnets
}
func (b *subnetRecorder) UnblockSubnet(cidr string) error {
	b.unblockedSubnet = append(b.unblockedSubnet, cidr)
	return nil
}
func (b *subnetRecorder) ValidateSubnetBlock(cidr string) error {
	b.validated = append(b.validated, cidr)
	return b.validationErrs[cidr]
}

func findDryRunSubnetNotice(actions []alert.Finding, cidr string) *alert.Finding {
	for i := range actions {
		if actions[i].Check == "auto_block" &&
			strings.Contains(actions[i].Message, "[dry-run]") &&
			strings.Contains(actions[i].Message, cidr) {
			return &actions[i]
		}
	}
	return nil
}

// Dry-run must make subnet decisions visible: the spray fast-path used to
// skip silently, so operators evaluating dry-run saw zero subnet activity.
func TestDryRunSubnetSprayEmitsNoticeWithoutBlocking(t *testing.T) {
	cfg := dryRunSubnetConfig(t)
	blocker := &subnetRecorder{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	findings := []alert.Finding{{
		Check:    "mail_subnet_spray",
		Severity: alert.Critical,
		Message:  "mail auth spray from 203.0.113.0/24",
	}}
	actions := AutoBlockIPs(cfg, findings)

	if len(blocker.blockedSubnets) != 0 {
		t.Fatalf("BlockSubnet called in dry-run: %v", blocker.blockedSubnets)
	}
	notice := findDryRunSubnetNotice(actions, "203.0.113.0/24")
	if notice == nil {
		t.Fatalf("actions = %+v, want a [dry-run] subnet notice", actions)
	}
	if notice.Severity != alert.Warning {
		t.Errorf("notice severity = %v, want Warning", notice.Severity)
	}
}

func TestDryRunASNCrawlEmitsNoticeWithoutBlocking(t *testing.T) {
	cfg := dryRunSubnetConfig(t)
	blocker := &subnetRecorder{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	findings := []alert.Finding{{
		Check:    "http_asn_crawl",
		Severity: alert.Critical,
		Message:  "distributed crawl saturating PHP pool",
		CIDRs:    []string{"198.51.100.0/24"},
	}}
	actions := AutoBlockIPs(cfg, findings)

	if len(blocker.blockedSubnets) != 0 {
		t.Fatalf("BlockSubnet called in dry-run: %v", blocker.blockedSubnets)
	}
	if findDryRunSubnetNotice(actions, "198.51.100.0/24") == nil {
		t.Fatalf("actions = %+v, want a [dry-run] asn-crawl notice", actions)
	}
	state := loadBlockState(cfg.StatePath)
	if state.BlocksThisHour != 0 {
		t.Errorf("BlocksThisHour = %d, want 0 (dry-run consumes no budget)", state.BlocksThisHour)
	}
}

func TestDryRunASNCrawlPreservesExhaustedBudget(t *testing.T) {
	cfg := dryRunSubnetConfig(t)
	cfg.AutoResponse.MaxBlocksPerHour = 2
	now := time.Date(2026, 8, 3, 18, 0, 0, 0, time.UTC)
	oldNow := autoBlockNow
	autoBlockNow = func() time.Time { return now }
	t.Cleanup(func() { autoBlockNow = oldNow })
	saveBlockState(cfg.StatePath, &blockState{
		BlocksThisHour: 2,
		HourKey:        now.Format("2006-01-02T15"),
	})

	blocker := &subnetRecorder{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	actions := AutoBlockIPs(cfg, []alert.Finding{{
		Check:    "http_asn_crawl",
		Severity: alert.Critical,
		Message:  "distributed crawl saturating PHP pool",
		CIDRs:    []string{"198.51.100.0/24", "203.0.113.0/24"},
	}})

	for _, cidr := range []string{"198.51.100.0/24", "203.0.113.0/24"} {
		if findDryRunSubnetNotice(actions, cidr) == nil {
			t.Errorf("actions = %+v, want dry-run notice for %s despite exhausted budget", actions, cidr)
		}
	}
	state := loadBlockState(cfg.StatePath)
	if state.BlocksThisHour != 2 {
		t.Errorf("BlocksThisHour = %d, want existing budget usage preserved", state.BlocksThisHour)
	}
}

func TestDryRunNetblockEscalationEmitsNoticeWithoutBlocking(t *testing.T) {
	cfg := dryRunSubnetConfig(t)
	cfg.AutoResponse.NetBlock = true
	saveBlockState(cfg.StatePath, &blockState{
		IPs: []blockedIP{
			{IP: "203.0.113.1", ExpiresAt: time.Now().Add(time.Hour)},
			{IP: "203.0.113.2", ExpiresAt: time.Now().Add(time.Hour)},
			{IP: "203.0.113.3", ExpiresAt: time.Now().Add(time.Hour)},
		},
	})

	blocker := &subnetRecorder{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	actions := AutoBlockIPs(cfg, nil)

	if len(blocker.blockedSubnets) != 0 {
		t.Fatalf("BlockSubnet called in dry-run: %v", blocker.blockedSubnets)
	}
	if findDryRunSubnetNotice(actions, "203.0.113.0/24") == nil {
		t.Fatalf("actions = %+v, want a [dry-run] netblock notice", actions)
	}
}

func TestDryRunSubnetNoticesHonorFirewallPreflight(t *testing.T) {
	errUnsafe := errors.New("contains protected address")
	tests := []struct {
		name     string
		cidr     string
		findings []alert.Finding
		seed     func(*config.Config)
	}{
		{
			name: "spray",
			cidr: "192.0.2.0/24",
			findings: []alert.Finding{{
				Check: "mail_subnet_spray", Message: "mail auth spray from 192.0.2.0/24",
			}},
		},
		{
			name: "asn-crawl",
			cidr: "198.51.100.0/24",
			findings: []alert.Finding{{
				Check: "http_asn_crawl", Severity: alert.Critical,
				Message: "distributed crawl", CIDRs: []string{"198.51.100.0/24"},
			}},
		},
		{
			name: "netblock",
			cidr: "203.0.113.0/24",
			seed: func(cfg *config.Config) {
				cfg.AutoResponse.NetBlock = true
				saveBlockState(cfg.StatePath, &blockState{IPs: []blockedIP{
					{IP: "203.0.113.1", ExpiresAt: time.Now().Add(time.Hour)},
					{IP: "203.0.113.2", ExpiresAt: time.Now().Add(time.Hour)},
					{IP: "203.0.113.3", ExpiresAt: time.Now().Add(time.Hour)},
				}})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := dryRunSubnetConfig(t)
			if tc.seed != nil {
				tc.seed(cfg)
			}
			blocker := &subnetRecorder{validationErrs: map[string]error{tc.cidr: errUnsafe}}
			oldBlocker := getIPBlocker()
			SetIPBlocker(blocker)
			t.Cleanup(func() { SetIPBlocker(oldBlocker) })

			actions := AutoBlockIPs(cfg, tc.findings)

			if findDryRunSubnetNotice(actions, tc.cidr) != nil {
				t.Fatalf("actions = %+v, must not claim safety-rejected subnet would be blocked", actions)
			}
			if len(blocker.validated) != 1 || blocker.validated[0] != tc.cidr {
				t.Fatalf("validated = %v, want [%s]", blocker.validated, tc.cidr)
			}
			if len(blocker.blockedSubnets) != 0 {
				t.Fatalf("BlockSubnet called in dry-run: %v", blocker.blockedSubnets)
			}
		})
	}
}

func TestDryRunSubnetSpraySkipsInfraIntersection(t *testing.T) {
	cfg := dryRunSubnetConfig(t)
	cfg.InfraIPs = []string{"203.0.113.200"}
	blocker := &subnetRecorder{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	actions := AutoBlockIPs(cfg, []alert.Finding{{
		Check: "mail_subnet_spray", Message: "mail auth spray from 203.0.113.0/24",
	}})

	if findDryRunSubnetNotice(actions, "203.0.113.0/24") != nil {
		t.Fatalf("actions = %+v, must not report a subnet containing infra IP", actions)
	}
	if len(blocker.validated) != 0 {
		t.Fatalf("firewall preflight ran after config guard: %v", blocker.validated)
	}
}

// Dry-run must be read-only: pruning exempt subnets mutates the kernel
// firewall and has to wait until live mode.
func TestDryRunDoesNotPruneExemptSubnets(t *testing.T) {
	cfg := dryRunSubnetConfig(t)
	cfg.Firewall = &firewall.FirewallConfig{
		Enabled:         true,
		DOSExemptRanges: []string{"203.0.113.0/24"},
	}
	blocker := &subnetRecorder{
		subnets: []firewall.SubnetEntry{{
			CIDR:   "203.0.113.0/24",
			Source: firewall.SourceAutoResponse,
		}},
	}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	AutoBlockIPs(cfg, nil)

	if len(blocker.unblockedSubnet) != 0 {
		t.Fatalf("UnblockSubnet called in dry-run: %v", blocker.unblockedSubnet)
	}
}

// Live mode still prunes: the dry-run gate must not disable the cleanup
// when real blocking is active.
func TestLiveModeStillPrunesExemptSubnets(t *testing.T) {
	cfg := dryRunSubnetConfig(t)
	setAutoResponseLive(cfg)
	cfg.Firewall = &firewall.FirewallConfig{
		Enabled:         true,
		DOSExemptRanges: []string{"203.0.113.0/24"},
	}
	blocker := &subnetRecorder{
		subnets: []firewall.SubnetEntry{{
			CIDR:   "203.0.113.0/24",
			Source: firewall.SourceAutoResponse,
		}},
	}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	AutoBlockIPs(cfg, nil)

	if len(blocker.unblockedSubnet) != 1 {
		t.Fatalf("UnblockSubnet calls = %v, want the exempt subnet pruned in live mode", blocker.unblockedSubnet)
	}
}
