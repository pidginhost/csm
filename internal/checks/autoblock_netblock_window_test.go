package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// netblockBlocker keeps a live kernel view: blocks land in it, expiry is
// simulated by removing them, and operator blocks can be placed directly.
type netblockBlocker struct {
	live    map[string]struct{}
	allowed map[string]bool
	subnets []string
}

func newNetblockBlocker() *netblockBlocker {
	return &netblockBlocker{live: map[string]struct{}{}, allowed: map[string]bool{}}
}

func (b *netblockBlocker) BlockIP(ip, _ string, _ time.Duration) error {
	b.live[ip] = struct{}{}
	return nil
}
func (b *netblockBlocker) UnblockIP(ip string) error { delete(b.live, ip); return nil }
func (b *netblockBlocker) IsBlocked(ip string) bool {
	_, ok := b.live[ip]
	return ok
}
func (b *netblockBlocker) LiveBlockedSet() (firewall.LiveBlockedSnapshot, error) {
	v4 := make(map[string]struct{}, len(b.live))
	for ip := range b.live {
		v4[ip] = struct{}{}
	}
	return firewall.LiveBlockedSnapshot{V4: v4, V6: map[string]struct{}{}, HasV4: true, HasV6: true}, nil
}
func (b *netblockBlocker) BlockSubnet(cidr, _ string, _ time.Duration) error {
	b.subnets = append(b.subnets, cidr)
	return nil
}
func (b *netblockBlocker) IsSubnetBlocked(cidr string) bool {
	for _, s := range b.subnets {
		if s == cidr {
			return true
		}
	}
	return false
}
func (b *netblockBlocker) IsAllowed(ip string) bool { return b.allowed[ip] }

func netblockWindowConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := newAutoBlockTestConfig(t)
	cfg.AutoResponse.NetBlock = true
	cfg.AutoResponse.NetBlockThreshold = 3
	cfg.AutoResponse.NetBlockWindow = "168h"
	setAutoResponseLive(cfg)
	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() { SetChallengeIPList(oldChallengeList) })
	return cfg
}

func bruteForceFrom(ip string) []alert.Finding {
	return []alert.Finding{{Check: "wp_login_bruteforce", Message: "WordPress brute force from " + ip}}
}

// An attacker rotating through one /24 with a single address blocked at a
// time never had three blocks live at once, so the subnet escaped forever.
func TestAutoBlockIPs_NetBlockCountsRotationWithinWindow(t *testing.T) {
	cfg := netblockWindowConfig(t)
	blocker := newNetblockBlocker()
	swapBlocker(t, blocker)

	for _, ip := range []string{"198.51.100.10", "198.51.100.20", "198.51.100.30"} {
		AutoBlockIPs(cfg, bruteForceFrom(ip))
		delete(blocker.live, ip) // the 24h block lapses before the next address shows up
	}
	if len(blocker.subnets) != 1 || blocker.subnets[0] != "198.51.100.0/24" {
		t.Fatalf("subnets = %v, want the rotated /24 blocked", blocker.subnets)
	}
}

func TestAutoBlockIPs_NetBlockIgnoresBlocksOutsideWindow(t *testing.T) {
	cfg := netblockWindowConfig(t)
	now := time.Now()
	setAutoBlockNow(t, now)
	saveNetblockHistory(cfg.StatePath, &netblockHistory{IPs: map[string]time.Time{
		"198.51.100.10": now.Add(-8 * 24 * time.Hour),
		"198.51.100.20": now.Add(-8 * 24 * time.Hour),
	}})
	blocker := newNetblockBlocker()
	swapBlocker(t, blocker)

	AutoBlockIPs(cfg, bruteForceFrom("198.51.100.30"))
	if len(blocker.subnets) != 0 {
		t.Fatalf("subnets = %v, want none: earlier blocks are older than the window", blocker.subnets)
	}
}

// Operator and permanent blocks live only in the firewall, not in the
// auto-block tracker; they are the strongest evidence and must count.
func TestAutoBlockIPs_NetBlockCountsLiveOperatorBlocks(t *testing.T) {
	cfg := netblockWindowConfig(t)
	blocker := newNetblockBlocker()
	blocker.live["198.51.100.37"] = struct{}{}
	blocker.live["198.51.100.144"] = struct{}{}
	swapBlocker(t, blocker)

	AutoBlockIPs(cfg, bruteForceFrom("198.51.100.158"))
	if len(blocker.subnets) != 1 || blocker.subnets[0] != "198.51.100.0/24" {
		t.Fatalf("subnets = %v, want the /24 blocked", blocker.subnets)
	}
}

func TestAutoBlockIPs_NetBlockSkipsAllowedHistory(t *testing.T) {
	cfg := netblockWindowConfig(t)
	now := time.Now()
	setAutoBlockNow(t, now)
	saveNetblockHistory(cfg.StatePath, &netblockHistory{IPs: map[string]time.Time{
		"198.51.100.10": now.Add(-time.Hour),
		"198.51.100.20": now.Add(-time.Hour),
	}})
	blocker := newNetblockBlocker()
	blocker.allowed["198.51.100.20"] = true // whitelisted after its block
	swapBlocker(t, blocker)

	AutoBlockIPs(cfg, bruteForceFrom("198.51.100.30"))
	if len(blocker.subnets) != 0 {
		t.Fatalf("subnets = %v, want none: an allowed address is not evidence", blocker.subnets)
	}
}

func TestForgetNetblockHistoryDropsAddress(t *testing.T) {
	cfg := netblockWindowConfig(t)
	now := time.Now()
	setAutoBlockNow(t, now)
	saveNetblockHistory(cfg.StatePath, &netblockHistory{IPs: map[string]time.Time{
		"198.51.100.10": now.Add(-time.Hour),
		"198.51.100.20": now.Add(-time.Hour),
	}})
	ForgetNetblockHistory(cfg.StatePath, "198.51.100.20")
	blocker := newNetblockBlocker()
	swapBlocker(t, blocker)

	AutoBlockIPs(cfg, bruteForceFrom("198.51.100.30"))
	if len(blocker.subnets) != 0 {
		t.Fatalf("subnets = %v, want none after the operator cleared an address", blocker.subnets)
	}
}

// A subnet block expires like any other. The offenders that caused it must
// not re-block the subnet on every cycle for the rest of the window; a new
// subnet block needs a fresh set of offenders.
func TestAutoBlockIPs_NetBlockNeedsFreshOffendersAfterSubnetBlock(t *testing.T) {
	cfg := netblockWindowConfig(t)
	now := time.Now()
	setAutoBlockNow(t, now)
	saveNetblockHistory(cfg.StatePath, &netblockHistory{
		IPs: map[string]time.Time{
			"198.51.100.10": now.Add(-3 * time.Hour),
			"198.51.100.20": now.Add(-3 * time.Hour),
			"198.51.100.30": now.Add(-3 * time.Hour),
		},
		Subnets: map[string]time.Time{"198.51.100.0/24": now.Add(-2 * time.Hour)},
	})
	blocker := newNetblockBlocker() // the earlier subnet block has lapsed
	swapBlocker(t, blocker)

	AutoBlockIPs(cfg, nil)
	if len(blocker.subnets) != 0 {
		t.Fatalf("subnets = %v, want none: the offenders were already answered", blocker.subnets)
	}
	for _, ip := range []string{"198.51.100.40", "198.51.100.50", "198.51.100.60"} {
		AutoBlockIPs(cfg, bruteForceFrom(ip))
	}
	if len(blocker.subnets) != 1 {
		t.Fatalf("subnets = %v, want one new block from fresh offenders", blocker.subnets)
	}
}

func TestFlushAutoBlockStateClearsNetblockHistory(t *testing.T) {
	cfg := netblockWindowConfig(t)
	saveNetblockHistory(cfg.StatePath, &netblockHistory{IPs: map[string]time.Time{"198.51.100.10": time.Now()}})
	if _, err := FlushAutoBlockState(cfg.StatePath, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if h := loadNetblockHistory(cfg.StatePath); len(h.IPs) != 0 || len(h.Subnets) != 0 {
		t.Fatalf("history after flush = %+v, want empty", h)
	}
}

func TestAutoBlockIPs_ProgrammaticConfigUsesDefaultNetblockWindow(t *testing.T) {
	cfg := netblockWindowConfig(t)
	cfg.AutoResponse.NetBlockWindow = ""
	now := time.Now()
	setAutoBlockNow(t, now)
	saveNetblockHistory(cfg.StatePath, &netblockHistory{IPs: map[string]time.Time{
		"198.51.100.10": now.Add(-6 * 24 * time.Hour),
		"198.51.100.20": now.Add(-6 * 24 * time.Hour),
	}})
	blocker := newNetblockBlocker()
	swapBlocker(t, blocker)

	AutoBlockIPs(cfg, bruteForceFrom("198.51.100.30"))
	if len(blocker.subnets) != 1 {
		t.Fatalf("subnets = %v, want the default %s window to cover six days", blocker.subnets, config.DefaultNetBlockWindow)
	}
}

// Pruning runs hourly, so between prunes the counting step alone must keep
// blocks that ended before the window from counting.
func TestAutoBlockIPs_NetBlockWindowAppliesBetweenPrunes(t *testing.T) {
	cfg := netblockWindowConfig(t)
	now := time.Now()
	setAutoBlockNow(t, now)
	saveNetblockHistory(cfg.StatePath, &netblockHistory{
		IPs: map[string]time.Time{
			"198.51.100.10": now.Add(-8 * 24 * time.Hour),
			"198.51.100.20": now.Add(-8 * 24 * time.Hour),
		},
		PrunedAt: now.Add(-10 * time.Minute),
	})
	blocker := newNetblockBlocker()
	swapBlocker(t, blocker)

	AutoBlockIPs(cfg, bruteForceFrom("198.51.100.30"))
	if len(blocker.subnets) != 0 {
		t.Fatalf("subnets = %v, want none: earlier blocks ended before the window", blocker.subnets)
	}
}
