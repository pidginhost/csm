package checks

import (
	"fmt"
	"os"
	"path/filepath"
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
	mustSaveNetblockHistory(t, cfg.StatePath, &netblockHistory{IPs: map[string]time.Time{
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
	mustSaveNetblockHistory(t, cfg.StatePath, &netblockHistory{IPs: map[string]time.Time{
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
	mustSaveNetblockHistory(t, cfg.StatePath, &netblockHistory{IPs: map[string]time.Time{
		"198.51.100.10": now.Add(-time.Hour),
		"198.51.100.20": now.Add(-time.Hour),
	}})
	if err := ForgetNetblockHistory(cfg.StatePath, "198.51.100.20", nil); err != nil {
		t.Fatal(err)
	}
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
	mustSaveNetblockHistory(t, cfg.StatePath, &netblockHistory{
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
	mustSaveNetblockHistory(t, cfg.StatePath, &netblockHistory{IPs: map[string]time.Time{"198.51.100.10": time.Now()}})
	if _, err := FlushAutoBlockState(cfg.StatePath, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if h := mustLoadNetblockHistory(t, cfg.StatePath); len(h.IPs) != 0 || len(h.Subnets) != 0 {
		t.Fatalf("history after flush = %+v, want empty", h)
	}
}

func TestAutoBlockIPs_ProgrammaticConfigUsesDefaultNetblockWindow(t *testing.T) {
	cfg := netblockWindowConfig(t)
	cfg.AutoResponse.NetBlockWindow = ""
	now := time.Now()
	setAutoBlockNow(t, now)
	mustSaveNetblockHistory(t, cfg.StatePath, &netblockHistory{IPs: map[string]time.Time{
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
	mustSaveNetblockHistory(t, cfg.StatePath, &netblockHistory{
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

func TestNetblockOperatorReblockRefreshesHistory(t *testing.T) {
	cfg := netblockWindowConfig(t)
	now := time.Now()
	setAutoBlockNow(t, now)
	blocker := newNetblockBlocker()
	swapBlocker(t, blocker)
	ip := "198.51.100.10"
	for _, address := range []string{ip, "198.51.100.20", "198.51.100.30"} {
		blocker.live[address] = struct{}{}
	}
	AutoBlockIPs(cfg, nil)
	if len(blocker.subnets) != 1 {
		t.Fatalf("initial subnet blocks = %v", blocker.subnets)
	}
	blocker.subnets = nil
	delete(blocker.live, "198.51.100.20")
	delete(blocker.live, "198.51.100.30")
	delete(blocker.live, ip)
	AutoBlockIPs(cfg, nil)
	autoBlockNow = func() time.Time { return now.Add(time.Hour) }
	blocker.live[ip] = struct{}{}
	AutoBlockIPs(cfg, nil)
	delete(blocker.live, ip)
	AutoBlockIPs(cfg, nil)
	if got := mustLoadNetblockHistory(t, cfg.StatePath).IPs[ip]; !got.Equal(now.Add(time.Hour)) {
		t.Fatalf("repeat operator block time = %s, want %s", got, now.Add(time.Hour))
	}
	AutoBlockIPs(cfg, bruteForceFrom("198.51.100.40"))
	AutoBlockIPs(cfg, bruteForceFrom("198.51.100.50"))
	if len(blocker.subnets) != 1 {
		t.Fatalf("fresh operator block did not count after ending: %v", blocker.subnets)
	}

}

func TestNetblockAllowedHistoryStaysForgotten(t *testing.T) {
	cfg := netblockWindowConfig(t)
	blocker := newNetblockBlocker()
	swapBlocker(t, blocker)
	ip := "198.51.100.10"
	blocker.live[ip] = struct{}{}
	AutoBlockIPs(cfg, nil)
	delete(blocker.live, ip)
	blocker.allowed[ip] = true
	AutoBlockIPs(cfg, nil)
	delete(blocker.allowed, ip)
	AutoBlockIPs(cfg, bruteForceFrom("198.51.100.20"))
	AutoBlockIPs(cfg, bruteForceFrom("198.51.100.30"))
	if len(blocker.subnets) != 0 {
		t.Fatalf("forgotten address caused subnet block: %v", blocker.subnets)
	}
}

func TestFlushAutoBlockStateReportsNetblockHistoryFailure(t *testing.T) {
	cfg := netblockWindowConfig(t)
	if err := os.Mkdir(filepath.Join(cfg.StatePath, netblockHistoryFile), 0o700); err != nil {
		t.Fatal(err)
	}
	result, err := FlushAutoBlockState(cfg.StatePath, func() error { return nil })
	if !result.Flushed || err == nil {
		t.Fatalf("flush = %+v, %v; want partial failure", result, err)
	}
}

func TestNetblockHistoryRetentionAndIdleWrites(t *testing.T) {
	cfg := netblockWindowConfig(t)
	now := time.Now()
	setAutoBlockNow(t, now)
	blocker := newNetblockBlocker()
	swapBlocker(t, blocker)
	blocker.live["198.51.100.10"] = struct{}{}
	mustSaveNetblockHistory(t, cfg.StatePath, &netblockHistory{
		IPs:     map[string]time.Time{"198.51.100.10": now.Add(-8 * 24 * time.Hour), "203.0.113.10": now.Add(-8 * 24 * time.Hour)},
		Subnets: map[string]time.Time{"203.0.113.0/24": now.Add(-8 * 24 * time.Hour)},
	})
	AutoBlockIPs(cfg, nil)
	h := mustLoadNetblockHistory(t, cfg.StatePath)
	if len(h.IPs) != 1 || len(h.Subnets) != 0 {
		t.Fatalf("unbounded history: %+v", h)
	}
	path := filepath.Join(cfg.StatePath, netblockHistoryFile)
	// A past mtime detects atomic replacements without depending on clock resolution.
	stamp := now.Add(-time.Hour)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	autoBlockNow = func() time.Time { return now.Add(30 * time.Second) }
	AutoBlockIPs(cfg, nil)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(stamp) {
		t.Fatal("unchanged history was rewritten")
	}
}

func mustLoadNetblockHistory(t *testing.T, path string) *netblockHistory {
	t.Helper()
	h, err := loadNetblockHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestNetblockDoesNotReuseHistoryAfterMailSubnetBlock(t *testing.T) {
	cfg := netblockWindowConfig(t)
	now := time.Now()
	setAutoBlockNow(t, now)
	mustSaveNetblockHistory(t, cfg.StatePath, &netblockHistory{IPs: map[string]time.Time{
		"198.51.100.10": now.Add(-time.Hour),
		"198.51.100.20": now.Add(-time.Hour),
		"198.51.100.30": now.Add(-time.Hour),
	}})
	blocker := newNetblockBlocker()
	swapBlocker(t, blocker)
	AutoBlockIPs(cfg, []alert.Finding{{Check: "smtp_subnet_spray", Message: "SMTP spray from 198.51.100.0/24"}})
	if len(blocker.subnets) != 1 {
		t.Fatalf("mail subnet blocks = %v", blocker.subnets)
	}
	blocker.subnets = nil
	AutoBlockIPs(cfg, nil)
	if len(blocker.subnets) != 0 {
		t.Fatalf("answered offenders re-blocked subnet: %v", blocker.subnets)
	}
}

type incompleteNetblockSnapshot struct{ *netblockBlocker }

func (b *incompleteNetblockSnapshot) LiveBlockedSet() (firewall.LiveBlockedSnapshot, error) {
	return firewall.LiveBlockedSnapshot{HasV4: true}, nil
}

func TestNetblockKeepsPermanentHistoryWithoutFamilySnapshot(t *testing.T) {
	cfg := netblockWindowConfig(t)
	now := time.Now()
	setAutoBlockNow(t, now)
	ips := []string{"2001:db8::10", "2001:db8::20", "2001:db8::30"}
	history := &netblockHistory{IPs: make(map[string]time.Time)}
	blocker := &incompleteNetblockSnapshot{newNetblockBlocker()}
	for _, ip := range ips {
		history.IPs[ip] = now.Add(-8 * 24 * time.Hour)
		blocker.live[ip] = struct{}{}
	}
	mustSaveNetblockHistory(t, cfg.StatePath, history)
	swapBlocker(t, blocker)
	AutoBlockIPs(cfg, nil)
	if len(blocker.subnets) != 1 || blocker.subnets[0] != "2001:db8::/64" {
		t.Fatalf("subnets = %v, want cached permanent blocks to count", blocker.subnets)
	}
}

func TestNetblockPreservesUnreadableHistory(t *testing.T) {
	cfg := netblockWindowConfig(t)
	path := filepath.Join(cfg.StatePath, netblockHistoryFile)
	contents := []byte(`{"ips":`)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	blocker := newNetblockBlocker()
	for _, ip := range []string{"198.51.100.10", "198.51.100.20", "198.51.100.30"} {
		blocker.live[ip] = struct{}{}
	}
	swapBlocker(t, blocker)
	AutoBlockIPs(cfg, nil)
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(contents) {
		t.Fatalf("unreadable history overwritten: %s", got)
	}
	// Losing the history must not switch escalation off: addresses blocked
	// right now are still evidence.
	if len(blocker.subnets) != 1 || blocker.subnets[0] != "198.51.100.0/24" {
		t.Fatalf("subnet blocks = %v, want the /24 blocked from current evidence", blocker.subnets)
	}
}

func TestNetblockUnreadableHistoryCountsOnlyCurrentOffenders(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		t.Run(fmt.Sprintf("dry_run=%t", dryRun), func(t *testing.T) {
			cfg := netblockWindowConfig(t)
			cfg.AutoResponse.DryRun = &dryRun
			now := time.Now()
			setAutoBlockNow(t, now)
			path := filepath.Join(cfg.StatePath, netblockHistoryFile)
			// Decoding reaches the IP map before the invalid timestamp. None of
			// that partial history may become evidence for the fallback.
			contents := []byte(fmt.Sprintf(`{"ips":{"198.51.100.50":%q},"pruned_at":"invalid"}`, now.Format(time.RFC3339)))
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatal(err)
			}
			blocker := newNetblockBlocker()
			for _, ip := range []string{"198.51.100.10", "198.51.100.20", "198.51.100.30"} {
				blocker.live[ip] = struct{}{}
			}
			blocker.allowed["198.51.100.30"] = true
			swapBlocker(t, blocker)
			if err := writeBlockState(cfg.StatePath, &blockState{IPs: []blockedIP{
				{IP: "198.51.100.10", BlockedAt: now.Add(-8 * 24 * time.Hour)},
				{IP: "198.51.100.40", BlockedAt: now.Add(-time.Hour)},
			}}); err != nil {
				t.Fatal(err)
			}
			if actions := AutoBlockIPs(cfg, nil); len(actions) != 0 || len(blocker.subnets) != 0 {
				t.Fatalf("expired, allowed or partial-history IP counted: actions=%v subnets=%v", actions, blocker.subnets)
			}
			// Removing the allow entry leaves three live offenders, including
			// the tracked block older than the history window.
			delete(blocker.allowed, "198.51.100.30")
			actions := AutoBlockIPs(cfg, nil)
			wantMessage := "AUTO-NETBLOCK: 198.51.100.0/24 blocked (3 IPs from same subnet)"
			wantSeverity := alert.Critical
			if dryRun {
				wantMessage = "AUTO-NETBLOCK [dry-run]: 198.51.100.0/24 would be blocked (3 IPs from same subnet)"
				wantSeverity = alert.Warning
				if len(blocker.subnets) != 0 {
					t.Fatalf("dry-run applied subnet blocks: %v", blocker.subnets)
				}
			} else if len(blocker.subnets) != 1 || blocker.subnets[0] != "198.51.100.0/24" {
				t.Fatalf("subnet blocks = %v, want the current offenders' /24", blocker.subnets)
			}
			if len(actions) != 1 || actions[0].Message != wantMessage || actions[0].Severity != wantSeverity {
				t.Fatalf("actions = %+v, want %q at severity %v", actions, wantMessage, wantSeverity)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != string(contents) {
				t.Fatalf("unreadable history changed: %s (%v)", got, err)
			}
		})
	}
}

func mustSaveNetblockHistory(t *testing.T, path string, h *netblockHistory) {
	t.Helper()
	if err := saveNetblockHistory(path, h); err != nil {
		t.Fatal(err)
	}
}

func TestNetblockHistoryBoundedAtProductionRate(t *testing.T) {
	now := time.Now()
	cfg := netblockWindowConfig(t)
	h := &netblockHistory{IPs: map[string]time.Time{}, Subnets: map[string]time.Time{}}
	blocker := newNetblockBlocker()
	window := netblockWindow(cfg)
	for hour := 0; hour < 9*24; hour++ {
		current := make(map[string]bool)
		for n := 0; n < 2800; n++ {
			current[fmt.Sprintf("2001:db8:1::%x", n)] = true
		}
		// Two new blocks per minute, summarized as one hour of arrivals.
		for n := 0; n < 120; n++ {
			current[fmt.Sprintf("2001:db8:2::%x", hour*120+n)] = true
		}
		at := now.Add(time.Duration(hour) * time.Hour)
		recordNetblockHistory(h, nil, current, blocker, at, window)
		if recordNetblockHistory(h, nil, current, blocker, at.Add(30*time.Second), window) {
			t.Fatal("unchanged cycle would rewrite production history")
		}
	}
	want := 2800 + (int(window/time.Hour)+1)*120
	if len(h.IPs) != want || len(h.Active) != 2920 {
		t.Fatalf("history size = %d IPs, %d active; want %d, 2920", len(h.IPs), len(h.Active), want)
	}
}

func TestNetblockPermanentBlocksStillCountAfterSubnetExpiry(t *testing.T) {
	cfg := netblockWindowConfig(t)
	now := time.Now()
	setAutoBlockNow(t, now)
	blocker := newNetblockBlocker()
	swapBlocker(t, blocker)
	h := &netblockHistory{IPs: map[string]time.Time{}}
	for _, ip := range []string{"198.51.100.10", "198.51.100.20", "198.51.100.30"} {
		blocker.live[ip] = struct{}{}
		h.IPs[ip] = now.Add(-8 * 24 * time.Hour)
	}
	mustSaveNetblockHistory(t, cfg.StatePath, h)
	AutoBlockIPs(cfg, nil)
	if len(blocker.subnets) != 1 {
		t.Fatalf("old permanent blocks did not count: %v", blocker.subnets)
	}
	blocker.subnets = nil
	AutoBlockIPs(cfg, nil)
	if len(blocker.subnets) != 1 {
		t.Fatalf("live permanent blocks did not renew subnet: %v", blocker.subnets)
	}
}

func TestNetblockMailBlockAnswersNewlyObservedOperatorBlocks(t *testing.T) {
	cfg := netblockWindowConfig(t)
	blocker := newNetblockBlocker()
	swapBlocker(t, blocker)
	for _, ip := range []string{"198.51.100.10", "198.51.100.20", "198.51.100.30"} {
		blocker.live[ip] = struct{}{}
	}
	AutoBlockIPs(cfg, []alert.Finding{{Check: "mail_subnet_spray", Message: "Mail spray from 198.51.100.0/24"}})
	if len(blocker.subnets) != 1 {
		t.Fatalf("mail subnet blocks = %v", blocker.subnets)
	}
	blocker.subnets = nil
	clear(blocker.live)
	AutoBlockIPs(cfg, nil)
	if len(blocker.subnets) != 0 {
		t.Fatalf("same-cycle operator blocks counted as fresh: %v", blocker.subnets)
	}
}
