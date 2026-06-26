//go:build linux

package daemon

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// spySubnetManager satisfies checks.IPBlocker and the unexported subnetManager
// interface so PruneExemptAutoSubnets can exercise the full prune loop.
type spySubnetManager struct {
	subnets         []firewall.SubnetEntry
	blockedSubnets  bool
	unblocked       []string
}

func (s *spySubnetManager) BlockIP(_ string, _ string, _ time.Duration) error { return nil }
func (s *spySubnetManager) UnblockIP(_ string) error                          { return nil }
func (s *spySubnetManager) IsBlocked(_ string) bool                           { return false }
func (s *spySubnetManager) BlockSubnet(_ string, _ string, _ time.Duration) error {
	return nil
}
func (s *spySubnetManager) IsSubnetBlocked(_ string) bool { return false }
func (s *spySubnetManager) BlockedSubnets() []firewall.SubnetEntry {
	s.blockedSubnets = true
	out := make([]firewall.SubnetEntry, len(s.subnets))
	copy(out, s.subnets)
	return out
}
func (s *spySubnetManager) UnblockSubnet(cidr string) error {
	s.unblocked = append(s.unblocked, cidr)
	return nil
}

// TestStartupPruneAfterFirewallWired verifies that checks.PruneExemptAutoSubnets
// enumerates the blocker's subnet list (calls BlockedSubnets) and removes only
// auto_response entries that intersect the DoS-exempt set. This mirrors the
// daemon startup call at checks.SetIPBlocker time.
func TestStartupPruneAfterFirewallWired(t *testing.T) {
	spy := &spySubnetManager{
		subnets: []firewall.SubnetEntry{
			// Should be pruned: auto_response + inside exempt range.
			{
				CIDR:      "192.0.2.0/24",
				Source:    firewall.SourceAutoResponse,
				Reason:    "http_asn_crawl",
				BlockedAt: time.Now(),
			},
			// Must NOT be pruned: web_ui source, leave untouched.
			{
				CIDR:      "192.0.2.0/24",
				Source:    firewall.SourceWebUI,
				Reason:    "manual block",
				BlockedAt: time.Now(),
			},
			// Must NOT be pruned: auto_response but outside exempt range.
			{
				CIDR:      "198.51.100.0/24",
				Source:    firewall.SourceAutoResponse,
				Reason:    "netblock",
				BlockedAt: time.Now(),
			},
		},
	}

	f := false
	cfg := &config.Config{}
	cfg.Firewall = &firewall.FirewallConfig{
		DOSExemptRanges:             []string{"192.0.2.0/24"},
		DOSExemptKnownMailProviders: &f,
	}

	pruned := checks.PruneExemptAutoSubnets(cfg, spy)

	if !spy.blockedSubnets {
		t.Error("PruneExemptAutoSubnets must call BlockedSubnets to enumerate current blocks")
	}
	if pruned != 1 {
		t.Errorf("want 1 pruned entry, got %d", pruned)
	}
	if len(spy.unblocked) != 1 {
		t.Errorf("want 1 UnblockSubnet call, got %d: %v", len(spy.unblocked), spy.unblocked)
	}
	if len(spy.unblocked) == 1 && spy.unblocked[0] != "192.0.2.0/24" {
		t.Errorf("wrong CIDR unblocked: want 192.0.2.0/24, got %s", spy.unblocked[0])
	}

	// Verify web_ui and non-exempt auto_response blocks were not touched.
	for _, cidr := range spy.unblocked {
		if cidr == "198.51.100.0/24" {
			t.Error("non-exempt subnet 198.51.100.0/24 must not be unblocked")
		}
	}

	// A plain IPBlocker (no BlockedSubnets) must return 0 gracefully.
	plain := &recordingBlocker{}
	if n := checks.PruneExemptAutoSubnets(cfg, plain); n != 0 {
		t.Errorf("plain IPBlocker: want 0, got %d", n)
	}
}

// recordingBlocker is a minimal IPBlocker for the daemon-package test.
type recordingBlocker struct{}

func (r *recordingBlocker) BlockIP(_ string, _ string, _ time.Duration) error { return nil }
func (r *recordingBlocker) UnblockIP(_ string) error                          { return nil }
func (r *recordingBlocker) IsBlocked(_ string) bool                           { return false }
func (r *recordingBlocker) BlockSubnet(_ string, _ string, _ time.Duration) error {
	return fmt.Errorf("not implemented")
}
func (r *recordingBlocker) IsSubnetBlocked(_ string) bool { return false }
