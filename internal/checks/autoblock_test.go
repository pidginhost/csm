package checks

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

func countRateLimitWarnings(actions []alert.Finding) int {
	n := 0
	for _, a := range actions {
		if strings.Contains(a.Message, "rate limit reached") {
			n++
		}
	}
	return n
}

func setAutoBlockNow(t *testing.T, now time.Time) {
	t.Helper()
	previous := autoBlockNow
	autoBlockNow = func() time.Time { return now }
	t.Cleanup(func() { autoBlockNow = previous })
}

func setAutoResponseLive(cfg *config.Config) {
	dryRun := false
	cfg.AutoResponse.DryRun = &dryRun
}

type recordingIPBlocker struct {
	blocked       []string
	calls         []blockCall
	blockedSubnet []string
	subnetCalls   []subnetCall
}

func (b *recordingIPBlocker) BlockSubnet(cidr, reason string, timeout time.Duration) error {
	b.blockedSubnet = append(b.blockedSubnet, cidr)
	b.subnetCalls = append(b.subnetCalls, subnetCall{cidr: cidr, reason: reason, timeout: timeout})
	return nil
}

func (b *recordingIPBlocker) IsSubnetBlocked(cidr string) bool {
	for _, blocked := range b.blockedSubnet {
		if blocked == cidr {
			return true
		}
	}
	return false
}

type blockCall struct {
	ip      string
	reason  string
	timeout time.Duration
}

type subnetCall struct {
	cidr    string
	reason  string
	timeout time.Duration
}

func (b *recordingIPBlocker) BlockIP(ip, reason string, timeout time.Duration) error {
	b.blocked = append(b.blocked, ip)
	b.calls = append(b.calls, blockCall{ip: ip, reason: reason, timeout: timeout})
	return nil
}

func (b *recordingIPBlocker) UnblockIP(ip string) error {
	return nil
}

func (b *recordingIPBlocker) IsBlocked(ip string) bool {
	return false
}

type swapOnLiveSubnetBlocker struct {
	*recordingIPBlocker
	replacement IPBlocker
}

func (b *swapOnLiveSubnetBlocker) IsBlockedLive(string) (bool, error) {
	SetIPBlocker(b.replacement)
	return true, nil
}

type staticChallengeIPList struct {
	ips map[string]bool
}

func (l *staticChallengeIPList) Add(ip, reason string, duration time.Duration) {
	l.ips[ip] = true
}

func (l *staticChallengeIPList) AddNonEscalating(ip, reason string, duration time.Duration) {
	l.ips[ip] = true
}

func (l *staticChallengeIPList) Remove(ip string) {
	delete(l.ips, ip)
}

func (l *staticChallengeIPList) Contains(ip string) bool {
	return l.ips[ip]
}

// TestAutoBlockIPs_ThreatEntryExpiresWithBlock is the structural regression
// test for the production permablock loop: the local threat DB record for a
// temporary auto-block must lapse with the firewall block instead of marking
// the IP permanently malicious (which re-flags it on every later access and
// re-blocks it forever).
func TestAutoBlockIPs_ThreatEntryExpiresWithBlock(t *testing.T) {
	withTestThreatStore(t)
	restore := SetGlobalThreatDBForTest(t.TempDir())
	t.Cleanup(restore)

	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.BlockExpiry = "1h"
	setAutoResponseLive(cfg)

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	before := time.Now()
	AutoBlockIPs(cfg, []alert.Finding{
		{
			Check:     "wp_login_bruteforce",
			Message:   "WordPress brute force from 192.0.2.55",
			Timestamp: time.Now(),
		},
	})

	if len(blocker.blocked) != 1 || blocker.blocked[0] != "192.0.2.55" {
		t.Fatalf("blocked IPs = %v, want [192.0.2.55]", blocker.blocked)
	}

	entry, found := store.Global().GetPermanentBlock("192.0.2.55")
	if !found {
		t.Fatal("threat DB entry missing after auto-block")
	}
	if entry.Source != store.ThreatSourceAutoBlock {
		t.Fatalf("Source = %q, want %q", entry.Source, store.ThreatSourceAutoBlock)
	}
	if entry.ExpiresAt.Before(before.Add(50*time.Minute)) || entry.ExpiresAt.After(before.Add(70*time.Minute)) {
		t.Fatalf("ExpiresAt = %v, want ~1h after %v (must match block expiry)", entry.ExpiresAt, before)
	}
	if entry.Expired(before) {
		t.Fatal("fresh temp entry reported expired")
	}
}

func TestAutoBlockIPs_SkipsChallengeListedIPs(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.Challenge.Enabled = true

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() {
		SetIPBlocker(oldBlocker)
	})

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(&staticChallengeIPList{
		ips: map[string]bool{
			"1.2.3.4": true,
		},
	})
	t.Cleanup(func() {
		SetChallengeIPList(oldChallengeList)
	})

	actions := AutoBlockIPs(cfg, []alert.Finding{
		{
			Check:     "wp_login_bruteforce",
			Message:   "WordPress brute force from 1.2.3.4",
			Timestamp: time.Now(),
		},
	})

	if len(actions) != 0 {
		t.Fatalf("AutoBlockIPs returned %d actions, want 0 for challenged IP", len(actions))
	}
	if len(blocker.blocked) != 0 {
		t.Fatalf("BlockIP called for challenged IPs: %v", blocker.blocked)
	}

	state := loadBlockState(cfg.StatePath)
	if len(state.IPs) != 0 {
		t.Fatalf("saved blocked IP state = %v, want none", state.IPs)
	}
	if len(state.Pending) != 0 {
		t.Fatalf("saved pending IP state = %v, want none", state.Pending)
	}
}

func TestAutoBlockIPs_HTTPScannerBlockActionBypassesChallengeList(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.HTTPScannerAction = "block"
	cfg.Challenge.Enabled = true

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() {
		SetIPBlocker(oldBlocker)
	})

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(&staticChallengeIPList{
		ips: map[string]bool{
			"192.0.2.201": true,
		},
	})
	t.Cleanup(func() {
		SetChallengeIPList(oldChallengeList)
	})

	actions := AutoBlockIPs(cfg, []alert.Finding{
		{
			Check:     "http_scanner_profile",
			SourceIP:  "192.0.2.201",
			Message:   "URL scanner profile from 192.0.2.201: 50 of 50 requests",
			Timestamp: time.Now(),
		},
	})

	if len(blocker.blocked) != 1 || blocker.blocked[0] != "192.0.2.201" {
		t.Fatalf("blocked=%v want [192.0.2.201]", blocker.blocked)
	}
	if len(actions) != 1 || !strings.Contains(actions[0].Message, "192.0.2.201") {
		t.Fatalf("actions = %+v, want auto-block for scanner block action", actions)
	}
}

func TestAutoBlockIPs_ChallengeDisabledBypassesChallengeList(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.Challenge.Enabled = false

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() {
		SetIPBlocker(oldBlocker)
	})

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(&staticChallengeIPList{
		ips: map[string]bool{
			"192.0.2.202": true,
		},
	})
	t.Cleanup(func() {
		SetChallengeIPList(oldChallengeList)
	})

	actions := AutoBlockIPs(cfg, []alert.Finding{
		{
			Check:     "wp_login_bruteforce",
			SourceIP:  "192.0.2.202",
			Message:   "WordPress brute force from 192.0.2.202",
			Timestamp: time.Now(),
		},
	})

	if len(blocker.blocked) != 1 || blocker.blocked[0] != "192.0.2.202" {
		t.Fatalf("blocked=%v want [192.0.2.202]", blocker.blocked)
	}
	if len(actions) != 1 || !strings.Contains(actions[0].Message, "192.0.2.202") {
		t.Fatalf("actions = %+v, want auto-block when challenge is disabled", actions)
	}
}

func TestAutoBlockIPs_QueuesIPsWhenRateLimited(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	now := time.Date(2026, 6, 2, 13, 15, 0, 0, time.UTC)
	setAutoBlockNow(t, now)
	saveBlockState(cfg.StatePath, &blockState{
		BlocksThisHour: config.DefaultMaxBlocksPerHour,
		HourKey:        now.Format("2006-01-02T15"),
	})

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() {
		SetIPBlocker(oldBlocker)
	})

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() {
		SetChallengeIPList(oldChallengeList)
	})

	actions := AutoBlockIPs(cfg, []alert.Finding{
		{
			Check:     "wp_login_bruteforce",
			Message:   "WordPress brute force from 5.6.7.8",
			Timestamp: time.Now(),
		},
	})

	if len(blocker.blocked) != 0 {
		t.Fatalf("BlockIP called despite rate limit: %v", blocker.blocked)
	}
	if len(actions) != 1 {
		t.Fatalf("AutoBlockIPs returned %d actions, want 1 rate-limit warning", len(actions))
	}
	if actions[0].Severity != alert.Warning {
		t.Fatalf("rate-limit action severity = %v, want %v", actions[0].Severity, alert.Warning)
	}
	if !strings.Contains(actions[0].Message, "queued for next cycle") {
		t.Fatalf("rate-limit action message = %q, want queued warning", actions[0].Message)
	}

	state := loadBlockState(cfg.StatePath)
	if len(state.IPs) != 0 {
		t.Fatalf("saved blocked IP state = %v, want none", state.IPs)
	}
	if len(state.Pending) != 1 {
		t.Fatalf("saved pending IP count = %d, want 1", len(state.Pending))
	}
	if state.Pending[0].IP != "5.6.7.8" {
		t.Fatalf("pending IP = %q, want %q", state.Pending[0].IP, "5.6.7.8")
	}
}

func TestAutoBlockIPs_SkipsAlreadyBlockedNetblock(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.NetBlock = true
	cfg.AutoResponse.NetBlockThreshold = 2
	setAutoResponseLive(cfg)

	blocker := &recordingIPBlocker{blockedSubnet: []string{"198.51.100.0/24"}}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() {
		SetIPBlocker(oldBlocker)
	})

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() {
		SetChallengeIPList(oldChallengeList)
	})

	actions := AutoBlockIPs(cfg, []alert.Finding{
		{Check: "wp_login_bruteforce", Message: "WordPress brute force from 198.51.100.10"},
		{Check: "wp_login_bruteforce", Message: "WordPress brute force from 198.51.100.20"},
	})

	for _, action := range actions {
		if strings.Contains(action.Message, "AUTO-NETBLOCK") {
			t.Fatalf("unexpected repeated netblock action: %q", action.Message)
		}
	}
	if len(blocker.blockedSubnet) != 1 {
		t.Fatalf("BlockSubnet call count changed blockedSubnet to %v", blocker.blockedSubnet)
	}
}

// TestAutoBlockIPs_NetBlockHandlesIPv6: when multiple IPv6 addresses
// from the same /64 are auto-blocked, the netblock-escalation path
// must trigger a CIDR block of that /64. Previously the prefix
// extractor only understood IPv4 and IPv6 attackers escaped the
// /24-equivalent escalation entirely.
func TestAutoBlockIPs_NetBlockHandlesIPv6(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.NetBlock = true
	cfg.AutoResponse.NetBlockThreshold = 2
	setAutoResponseLive(cfg)

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() {
		SetIPBlocker(oldBlocker)
	})

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() {
		SetChallengeIPList(oldChallengeList)
	})

	AutoBlockIPs(cfg, []alert.Finding{
		{Check: "wp_login_bruteforce", Message: "WP brute from 2001:db8:1::10"},
		{Check: "wp_login_bruteforce", Message: "WP brute from 2001:db8:1::20"},
	})

	if len(blocker.blockedSubnet) != 1 {
		t.Fatalf("blockedSubnet=%v, want one IPv6 /64 netblock", blocker.blockedSubnet)
	}
	if blocker.blockedSubnet[0] != "2001:db8:1::/64" {
		t.Fatalf("blockedSubnet[0]=%q, want 2001:db8:1::/64", blocker.blockedSubnet[0])
	}
}

func TestAutoBlockIPs_NetBlockUsesConfiguredExpiry(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.BlockExpiry = "2h"
	cfg.AutoResponse.NetBlock = true
	cfg.AutoResponse.NetBlockThreshold = 2
	setAutoResponseLive(cfg)

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() {
		SetIPBlocker(oldBlocker)
	})

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() {
		SetChallengeIPList(oldChallengeList)
	})

	AutoBlockIPs(cfg, []alert.Finding{
		{Check: "wp_login_bruteforce", Message: "WP brute from 198.51.100.10"},
		{Check: "wp_login_bruteforce", Message: "WP brute from 198.51.100.20"},
	})

	if len(blocker.subnetCalls) != 1 {
		t.Fatalf("BlockSubnet calls = %+v, want one netblock call", blocker.subnetCalls)
	}
	if blocker.subnetCalls[0].cidr != "198.51.100.0/24" {
		t.Fatalf("BlockSubnet CIDR = %q, want 198.51.100.0/24", blocker.subnetCalls[0].cidr)
	}
	if blocker.subnetCalls[0].timeout != 2*time.Hour {
		t.Fatalf("BlockSubnet timeout = %s, want 2h", blocker.subnetCalls[0].timeout)
	}
}

func TestAutoBlockIPs_NetBlockDryRunSkipsBlockSubnet(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.NetBlock = true
	cfg.AutoResponse.NetBlockThreshold = 2

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() {
		SetIPBlocker(oldBlocker)
	})

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() {
		SetChallengeIPList(oldChallengeList)
	})

	AutoBlockIPs(cfg, []alert.Finding{
		{Check: "wp_login_bruteforce", Message: "WP brute from 198.51.100.10"},
		{Check: "wp_login_bruteforce", Message: "WP brute from 198.51.100.20"},
	})

	if len(blocker.subnetCalls) != 0 {
		t.Fatalf("dry-run must not netblock subnets, got %+v", blocker.subnetCalls)
	}
}

func TestAutoBlockIPs_SubnetStatusUsesScanSnapshot(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	setAutoResponseLive(cfg)

	replacement := &recordingIPBlocker{blockedSubnet: []string{"203.0.113.0/24"}}
	blocker := &swapOnLiveSubnetBlocker{
		recordingIPBlocker: &recordingIPBlocker{},
		replacement:        replacement,
	}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() {
		SetIPBlocker(oldBlocker)
	})

	saveBlockState(cfg.StatePath, &blockState{
		IPs: []blockedIP{{
			IP:        "198.51.100.44",
			Reason:    "seed",
			BlockedAt: time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}},
	})

	AutoBlockIPs(cfg, []alert.Finding{{
		Check:   "smtp_subnet_spray",
		Message: "SMTP password spray from 203.0.113.0/24: 8 unique IPs in 10m0s",
	}})

	if len(blocker.blockedSubnet) != 1 || blocker.blockedSubnet[0] != "203.0.113.0/24" {
		t.Fatalf("BlockSubnet calls on scan snapshot = %v, want [203.0.113.0/24]", blocker.blockedSubnet)
	}
	if len(replacement.blockedSubnet) != 1 {
		t.Fatalf("replacement blocker should only hold its seeded subnet, got %v", replacement.blockedSubnet)
	}
}

func TestAutoBlockIPs_BlocksGenericModSecEscalation(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() {
		SetIPBlocker(oldBlocker)
	})

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() {
		SetChallengeIPList(oldChallengeList)
	})

	actions := AutoBlockIPs(cfg, []alert.Finding{{
		Check:   "modsec_block_escalation",
		Message: "ModSecurity escalation: 3+ denies from 203.0.113.200 within 10m0s",
	}})

	if len(blocker.blocked) != 1 || blocker.blocked[0] != "203.0.113.200" {
		t.Fatalf("blocked IPs = %v, want 203.0.113.200", blocker.blocked)
	}
	if len(actions) != 1 || !strings.Contains(actions[0].Message, "203.0.113.200") {
		t.Fatalf("actions = %+v, want one auto-block for ModSec escalation", actions)
	}
}

func TestAutoBlockIPs_DoesNotBlockModSecAdvisories(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() {
		SetIPBlocker(oldBlocker)
	})

	actions := AutoBlockIPs(cfg, []alert.Finding{
		{
			Check:    "modsec_low_confidence_burst",
			Message:  "ModSecurity low-confidence burst from 203.0.113.201",
			SourceIP: "203.0.113.201",
		},
		{
			Check:    "modsec_classifier_gap",
			Message:  "ModSecurity classifier gap from 203.0.113.202",
			SourceIP: "203.0.113.202",
		},
	})

	if len(blocker.blocked) != 0 {
		t.Fatalf("blocked IPs = %v, want none for ModSec advisory findings", blocker.blocked)
	}
	if len(actions) != 0 {
		t.Fatalf("actions = %+v, want none for ModSec advisory findings", actions)
	}
}

// WAF high-volume attacker findings are already-confirmed attack signals;
// they must reach the auto-block firewall path just like modsec escalation
// or brute-force findings, instead of staying advisory.
func TestAutoBlockIPs_BlocksWAFAttackBlocked(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() { SetChallengeIPList(oldChallengeList) })

	actions := AutoBlockIPs(cfg, []alert.Finding{{
		Check:    "waf_attack_blocked",
		SourceIP: "203.0.113.55",
		Message:  "WAF blocking high-volume attacker: 203.0.113.55 (42 blocked requests)",
	}})

	if len(blocker.blocked) != 1 || blocker.blocked[0] != "203.0.113.55" {
		t.Fatalf("blocked IPs = %v, want 203.0.113.55", blocker.blocked)
	}
	if len(actions) == 0 || !strings.Contains(actions[0].Message, "203.0.113.55") {
		t.Fatalf("actions = %+v, want auto-block for WAF attacker", actions)
	}
}

func TestAutoBlockIPs_BlocksWAFAttackBlockedWhenChallengeEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.Challenge.Enabled = true

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	challengeList := &staticChallengeIPList{ips: make(map[string]bool)}
	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(challengeList)
	t.Cleanup(func() { SetChallengeIPList(oldChallengeList) })

	findings := []alert.Finding{{
		Check:    "waf_attack_blocked",
		SourceIP: "203.0.113.55",
		Message:  "WAF blocking high-volume attacker: 203.0.113.55 (42 blocked requests)",
	}}

	if actions := ChallengeRouteIPs(cfg, findings); len(actions) != 0 {
		t.Fatalf("challenge actions = %+v, want none for WAF hard-block path", actions)
	}
	if challengeList.Contains("203.0.113.55") {
		t.Fatalf("WAF attacker was placed on challenge list, want direct auto-block")
	}

	actions := AutoBlockIPs(cfg, findings)

	if len(blocker.blocked) != 1 || blocker.blocked[0] != "203.0.113.55" {
		t.Fatalf("blocked IPs = %v, want 203.0.113.55", blocker.blocked)
	}
	if len(actions) == 0 || !strings.Contains(actions[0].Message, "203.0.113.55") {
		t.Fatalf("actions = %+v, want auto-block for WAF attacker", actions)
	}
}

func TestAutoBlockIPs_HardBlockCheckBypassesExistingChallengeList(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(&staticChallengeIPList{
		ips: map[string]bool{
			"203.0.113.55": true,
		},
	})
	t.Cleanup(func() { SetChallengeIPList(oldChallengeList) })

	actions := AutoBlockIPs(cfg, []alert.Finding{{
		Check:    "waf_attack_blocked",
		SourceIP: "203.0.113.55",
		Message:  "WAF blocking high-volume attacker: 203.0.113.55 (42 blocked requests)",
	}})

	if len(blocker.blocked) != 1 || blocker.blocked[0] != "203.0.113.55" {
		t.Fatalf("blocked IPs = %v, want 203.0.113.55", blocker.blocked)
	}
	if len(actions) != 1 || !strings.Contains(actions[0].Message, "203.0.113.55") {
		t.Fatalf("actions = %+v, want auto-block for hard-block check", actions)
	}
}

func TestAutoBlockIPs_DrainsPendingQueueAfterRateLimitWindow(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	now := time.Date(2026, 6, 2, 13, 15, 0, 0, time.UTC)
	setAutoBlockNow(t, now)
	saveBlockState(cfg.StatePath, &blockState{
		BlocksThisHour: config.DefaultMaxBlocksPerHour,
		HourKey:        now.Add(-2 * time.Hour).Format("2006-01-02T15"),
		Pending: []pendingIP{
			{IP: "9.8.7.6", Reason: "queued brute force"},
		},
	})

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() {
		SetIPBlocker(oldBlocker)
	})

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() {
		SetChallengeIPList(oldChallengeList)
	})

	actions := AutoBlockIPs(cfg, nil)

	if len(blocker.blocked) != 1 || blocker.blocked[0] != "9.8.7.6" {
		t.Fatalf("BlockIP calls = %v, want [9.8.7.6]", blocker.blocked)
	}
	if len(actions) != 1 {
		t.Fatalf("AutoBlockIPs returned %d actions, want 1 auto-block action", len(actions))
	}
	if actions[0].Severity != alert.Critical {
		t.Fatalf("pending drain action severity = %v, want %v", actions[0].Severity, alert.Critical)
	}
	if !strings.Contains(actions[0].Message, "9.8.7.6 blocked") {
		t.Fatalf("pending drain action message = %q, want blocked IP message", actions[0].Message)
	}

	state := loadBlockState(cfg.StatePath)
	if len(state.Pending) != 0 {
		t.Fatalf("saved pending IP state = %v, want none after drain", state.Pending)
	}
	if len(state.IPs) != 1 {
		t.Fatalf("saved blocked IP count = %d, want 1", len(state.IPs))
	}
	if state.IPs[0].IP != "9.8.7.6" {
		t.Fatalf("saved blocked IP = %q, want %q", state.IPs[0].IP, "9.8.7.6")
	}
}

func TestAutoBlockIPs_RateLimitWarningThrottledWithinHour(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	now := time.Date(2026, 6, 2, 13, 15, 0, 0, time.UTC)
	setAutoBlockNow(t, now)
	hour := now.Format("2006-01-02T15")
	saveBlockState(cfg.StatePath, &blockState{
		BlocksThisHour: config.DefaultMaxBlocksPerHour,
		HourKey:        hour,
	})

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() {
		SetIPBlocker(oldBlocker)
	})

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() {
		SetChallengeIPList(oldChallengeList)
	})

	first := AutoBlockIPs(cfg, []alert.Finding{
		{Check: "wp_login_bruteforce", Message: "WordPress brute force from 5.6.7.8", Timestamp: time.Now()},
	})
	if got := countRateLimitWarnings(first); got != 1 {
		t.Fatalf("first scan rate-limit warnings = %d, want 1", got)
	}

	second := AutoBlockIPs(cfg, []alert.Finding{
		{Check: "wp_login_bruteforce", Message: "WordPress brute force from 9.10.11.12", Timestamp: time.Now()},
	})
	if got := countRateLimitWarnings(second); got != 0 {
		t.Fatalf("second scan within same hour rate-limit warnings = %d, want 0 (throttled)", got)
	}

	state := loadBlockState(cfg.StatePath)
	if len(state.Pending) != 2 {
		t.Fatalf("pending after two rate-limited scans = %d, want 2", len(state.Pending))
	}
	if state.RateLimitWarnedHour != hour {
		t.Fatalf("RateLimitWarnedHour = %q, want %q", state.RateLimitWarnedHour, hour)
	}
}

func TestAutoBlockIPs_RateLimitWarningReemitsAfterHourRollover(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.MaxBlocksPerHour = 1

	now := time.Date(2026, 6, 2, 13, 15, 0, 0, time.UTC)
	setAutoBlockNow(t, now)
	prevHour := now.Add(-2 * time.Hour).Format("2006-01-02T15")
	saveBlockState(cfg.StatePath, &blockState{
		BlocksThisHour:      1,
		HourKey:             prevHour,
		RateLimitWarnedHour: prevHour,
	})

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() {
		SetIPBlocker(oldBlocker)
	})

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() {
		SetChallengeIPList(oldChallengeList)
	})

	// Two attackers in the new hour: the window reset lets the first block,
	// the second hits the cap of 1 and must re-emit the warning because the
	// last warning belongs to a prior hour.
	actions := AutoBlockIPs(cfg, []alert.Finding{
		{Check: "wp_login_bruteforce", Message: "WordPress brute force from 5.6.7.8", Timestamp: time.Now()},
		{Check: "xmlrpc_abuse", Message: "XML-RPC abuse from 9.10.11.12: 40 requests", Timestamp: time.Now()},
	})

	if got := countRateLimitWarnings(actions); got != 1 {
		t.Fatalf("rate-limit warnings after hour rollover = %d, want 1 (re-emitted)", got)
	}
	state := loadBlockState(cfg.StatePath)
	if state.RateLimitWarnedHour != now.Format("2006-01-02T15") {
		t.Fatalf("RateLimitWarnedHour = %q, want current hour", state.RateLimitWarnedHour)
	}

	again := AutoBlockIPs(cfg, []alert.Finding{
		{Check: "wp_login_bruteforce", Message: "WordPress brute force from 13.14.15.16", Timestamp: time.Now()},
	})
	if got := countRateLimitWarnings(again); got != 0 {
		t.Fatalf("second same-hour scan warnings = %d, want 0", got)
	}
}

func TestAutoBlockIPs_PendingQueueCappedUnderFlood(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	now := time.Date(2026, 6, 2, 13, 15, 0, 0, time.UTC)
	setAutoBlockNow(t, now)
	hour := now.Format("2006-01-02T15")
	overflow := maxPendingBlocks + 5
	pending := make([]pendingIP, 0, overflow)
	for i := 0; i < overflow; i++ {
		pending = append(pending, pendingIP{
			IP:     fmt.Sprintf("2001:db8::%x", i),
			Reason: "queued flood",
		})
	}
	saveBlockState(cfg.StatePath, &blockState{
		BlocksThisHour: config.DefaultMaxBlocksPerHour,
		HourKey:        hour,
		Pending:        pending,
	})

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() {
		SetIPBlocker(oldBlocker)
	})

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() {
		SetChallengeIPList(oldChallengeList)
	})

	actions := AutoBlockIPs(cfg, nil)

	state := loadBlockState(cfg.StatePath)
	if len(state.Pending) != maxPendingBlocks {
		t.Fatalf("pending queue length = %d, want capped at %d", len(state.Pending), maxPendingBlocks)
	}

	var warned string
	for _, a := range actions {
		if strings.Contains(a.Message, "rate limit reached") {
			warned = a.Message
		}
	}
	if warned == "" {
		t.Fatal("expected a rate-limit warning when the queue overflowed")
	}
	if !strings.Contains(warned, "dropped") {
		t.Fatalf("warning %q should report dropped IPs once the queue is capped", warned)
	}
	if !strings.Contains(warned, "5 dropped") {
		t.Fatalf("warning %q should report the exact dropped count", warned)
	}
}

func TestAutoBlock_SMTPBruteForceMessageFormatIsExtractable(t *testing.T) {
	msg := "SMTP brute force from 203.0.113.5: 5 failed auths in 10m0s"
	got := extractIPFromFinding(alert.Finding{Message: msg})
	if got != "203.0.113.5" {
		t.Errorf("extractIPFromFinding(%q) = %q, want 203.0.113.5", msg, got)
	}
}

func TestAutoBlock_LocalThreatScoreMessageFormatIsExtractable(t *testing.T) {
	msg := "High local threat score: 203.0.113.5 (score 75/100, 50 attacks)"
	got := extractIPFromFinding(alert.Finding{Check: "local_threat_score", Message: msg})
	if got != "203.0.113.5" {
		t.Errorf("extractIPFromFinding(%q) = %q, want 203.0.113.5", msg, got)
	}
}

func TestAutoBlock_ExtractIPFromFindingUsesStructuredSourceIP(t *testing.T) {
	f := alert.Finding{
		Message:  "SMTP brute force threshold reached",
		SourceIP: "203.0.113.5",
	}
	if got := extractIPFromFinding(f); got != "203.0.113.5" {
		t.Fatalf("extractIPFromFinding() = %q, want 203.0.113.5", got)
	}
}

func TestAutoBlock_ExtractIPFromFindingDoesNotFallBackFromUnsafeSourceIP(t *testing.T) {
	f := alert.Finding{
		Message:  "SMTP brute force from 203.0.113.5: 5 failed auths in 10m0s",
		SourceIP: "127.0.0.1",
	}
	if got := extractIPFromFinding(f); got != "" {
		t.Fatalf("extractIPFromFinding() = %q, want empty for unsafe structured source", got)
	}
}

func TestAutoBlock_SMTPBruteForceIsInAlwaysBlock(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.StatePath = t.TempDir()

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() {
		SetIPBlocker(oldBlocker)
	})

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() {
		SetChallengeIPList(oldChallengeList)
	})

	findings := []alert.Finding{{
		Check:   "smtp_bruteforce",
		Message: "SMTP brute force from 203.0.113.5: 5 failed auths in 10m0s",
	}}
	AutoBlockIPs(cfg, findings)

	if len(blocker.blocked) != 1 || blocker.blocked[0] != "203.0.113.5" {
		t.Errorf("expected BlockIP(203.0.113.5) to be called once; got %v", blocker.blocked)
	}
}

func TestAutoBlock_SMTPBruteForceUsesStructuredSourceIP(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.StatePath = t.TempDir()

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	findings := []alert.Finding{{
		Check:    "smtp_bruteforce",
		Message:  "SMTP brute force threshold reached",
		SourceIP: "203.0.113.5",
	}}
	AutoBlockIPs(cfg, findings)

	if len(blocker.blocked) != 1 || blocker.blocked[0] != "203.0.113.5" {
		t.Errorf("expected BlockIP(203.0.113.5) from SourceIP, got %v", blocker.blocked)
	}
}

func TestAutoBlock_FTPBruteforceIPv6UsesStructuredSourceIP(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.StatePath = t.TempDir()

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() { SetChallengeIPList(oldChallengeList) })

	// The human message is ambiguous for an IPv6 address ending in "::";
	// SourceIP must be the value that drives the autoblock path.
	findings := []alert.Finding{{
		Check:    "ftp_bruteforce",
		Message:  "FTP brute force from 2001:db8::: 15 failed attempts",
		SourceIP: "2001:db8::",
	}}
	AutoBlockIPs(cfg, findings)

	if len(blocker.blocked) != 1 || blocker.blocked[0] != "2001:db8::" {
		t.Errorf("expected BlockIP(2001:db8::) from SourceIP, got %v", blocker.blocked)
	}
}

func TestAutoBlockIPs_PromotesRepeatOffenderToPermanentBlock(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.BlockExpiry = "1h"
	cfg.AutoResponse.PermBlock = true
	cfg.AutoResponse.PermBlockCount = 2
	cfg.AutoResponse.PermBlockInterval = "24h"

	tracker := &permBlockTracker{
		IPs: map[string][]time.Time{
			"4.3.2.1": {time.Now().Add(-1 * time.Hour)},
		},
	}
	savePermBlockTracker(cfg.StatePath, tracker)

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() {
		SetIPBlocker(oldBlocker)
	})

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() {
		SetChallengeIPList(oldChallengeList)
	})

	actions := AutoBlockIPs(cfg, []alert.Finding{
		{
			Check:     "wp_login_bruteforce",
			Message:   "WordPress brute force from 4.3.2.1",
			Timestamp: time.Now(),
		},
	})

	if len(blocker.calls) != 2 {
		t.Fatalf("BlockIP call count = %d, want 2", len(blocker.calls))
	}
	if blocker.calls[0].ip != "4.3.2.1" || blocker.calls[0].timeout != time.Hour {
		t.Fatalf("temporary block call = %+v, want IP 4.3.2.1 with 1h timeout", blocker.calls[0])
	}
	if blocker.calls[1].ip != "4.3.2.1" || blocker.calls[1].timeout != 0 {
		t.Fatalf("permanent block call = %+v, want IP 4.3.2.1 with zero timeout", blocker.calls[1])
	}
	if !strings.Contains(blocker.calls[1].reason, "PERMBLOCK") {
		t.Fatalf("permanent block reason = %q, want PERMBLOCK marker", blocker.calls[1].reason)
	}

	if len(actions) != 2 {
		t.Fatalf("AutoBlockIPs returned %d actions, want 2", len(actions))
	}
	if !strings.Contains(actions[1].Message, "AUTO-PERMBLOCK") {
		t.Fatalf("permblock action message = %q, want AUTO-PERMBLOCK", actions[1].Message)
	}
}

// engineLikeBlocker reproduces the real firewall engine's BlockIPOutcome
// contract: a second block of an already-blocked IP within the same scan
// (skipExisting) returns BlockOutcomeNoop. PermBlock escalation runs in that
// same cycle, right after the temp block landed, so routing the promotion
// through the ordinary block path would no-op forever and the kernel timeout
// would expire the "permanent" block. The engine satisfies permanentPromoter
// so the escalation upgrades the existing element instead.
type engineLikeBlocker struct {
	liveBlocked map[string]bool
	tempCalls   []blockCall
	promotions  []blockCall
}

func (b *engineLikeBlocker) BlockIP(ip, reason string, timeout time.Duration) error {
	_, err := b.BlockIPOutcome(ip, reason, timeout)
	return err
}
func (b *engineLikeBlocker) UnblockIP(string) error   { return nil }
func (b *engineLikeBlocker) IsBlocked(ip string) bool { return b.liveBlocked[ip] }

func (b *engineLikeBlocker) BlockIPOutcome(ip, reason string, timeout time.Duration) (firewall.BlockOutcome, error) {
	if b.liveBlocked[ip] {
		return firewall.BlockOutcomeNoop, nil
	}
	b.liveBlocked[ip] = true
	b.tempCalls = append(b.tempCalls, blockCall{ip: ip, reason: reason, timeout: timeout})
	return firewall.BlockOutcomeLive, nil
}

func (b *engineLikeBlocker) PromoteToPermanentBlock(ip, reason string) error {
	b.promotions = append(b.promotions, blockCall{ip: ip, reason: reason, timeout: 0})
	return nil
}

func TestAutoBlockIPs_PromotesViaUpgradeWhenAlreadyBlockedThisCycle(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.BlockExpiry = "1h"
	cfg.AutoResponse.PermBlock = true
	cfg.AutoResponse.PermBlockCount = 2
	cfg.AutoResponse.PermBlockInterval = "24h"

	tracker := &permBlockTracker{
		IPs: map[string][]time.Time{
			"4.3.2.1": {time.Now().Add(-1 * time.Hour)},
		},
	}
	savePermBlockTracker(cfg.StatePath, tracker)

	blocker := &engineLikeBlocker{liveBlocked: map[string]bool{}}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() { SetChallengeIPList(oldChallengeList) })

	actions := AutoBlockIPs(cfg, []alert.Finding{
		{
			Check:     "wp_login_bruteforce",
			Message:   "WordPress brute force from 4.3.2.1",
			Timestamp: time.Now(),
		},
	})

	if len(blocker.tempCalls) != 1 {
		t.Fatalf("temp block count = %d, want 1", len(blocker.tempCalls))
	}
	if len(blocker.promotions) != 1 || blocker.promotions[0].ip != "4.3.2.1" {
		t.Fatalf("promotions = %+v, want one upgrade of 4.3.2.1", blocker.promotions)
	}
	if !strings.Contains(blocker.promotions[0].reason, "PERMBLOCK") {
		t.Fatalf("promotion reason = %q, want PERMBLOCK marker", blocker.promotions[0].reason)
	}
	var sawPerm bool
	for _, a := range actions {
		if strings.Contains(a.Message, "AUTO-PERMBLOCK") {
			sawPerm = true
		}
	}
	if !sawPerm {
		t.Fatalf("no AUTO-PERMBLOCK action emitted; actions=%+v", actions)
	}
}

func TestAutoBlock_ExtractCIDRFromFinding(t *testing.T) {
	cases := map[string]string{
		"SMTP password spray from 203.0.113.0/24: 8 unique IPs in 10m0s":  "203.0.113.0/24",
		"SMTP password spray from 198.51.100.0/24: 9 unique IPs in 10m0s": "198.51.100.0/24",
		"wp_login_bruteforce from 1.2.3.4: 10 attempts":                   "",
		"garbage": "",
	}
	for msg, want := range cases {
		got := extractCIDRFromFinding(alert.Finding{Message: msg})
		if got != want {
			t.Errorf("extractCIDRFromFinding(%q) = %q, want %q", msg, got, want)
		}
	}
}

func TestAutoBlock_SMTPSubnetSprayTriggersBlockSubnet(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.StatePath = t.TempDir()
	setAutoResponseLive(cfg)

	fake := &recordingIPBlocker{}
	prev := getIPBlocker()
	SetIPBlocker(fake)
	defer func() { SetIPBlocker(prev) }()

	findings := []alert.Finding{{
		Check:   "smtp_subnet_spray",
		Message: "SMTP password spray from 203.0.113.0/24: 8 unique IPs in 10m0s",
	}}
	AutoBlockIPs(cfg, findings)

	if len(fake.blockedSubnet) != 1 || fake.blockedSubnet[0] != "203.0.113.0/24" {
		t.Errorf("expected BlockSubnet(203.0.113.0/24), got %v", fake.blockedSubnet)
	}
	if len(fake.blocked) != 0 {
		t.Errorf("expected no BlockIP calls; got %v", fake.blocked)
	}
}

func TestAutoBlock_SubnetSprayDryRunSkipsBlockSubnet(t *testing.T) {
	cases := []string{"smtp_subnet_spray", "mail_subnet_spray"}
	for _, check := range cases {
		t.Run(check, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.AutoResponse.Enabled = true
			cfg.AutoResponse.BlockIPs = true
			cfg.StatePath = t.TempDir()

			blocker := &recordingIPBlocker{}
			oldBlocker := getIPBlocker()
			SetIPBlocker(blocker)
			t.Cleanup(func() { SetIPBlocker(oldBlocker) })

			AutoBlockIPs(cfg, []alert.Finding{{
				Check:   check,
				Message: "Mail password spray from 203.0.113.0/24: 8 unique IPs in 10m0s",
			}})

			if len(blocker.blockedSubnet) != 0 {
				t.Fatalf("dry-run must not block subnets, got %v", blocker.blockedSubnet)
			}
		})
	}
}

func TestAutoBlock_MailBruteForceTriggersBlockIP(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.StatePath = t.TempDir()

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	findings := []alert.Finding{{
		Check:   "mail_bruteforce",
		Message: "Mail auth brute force from 203.0.113.5: 5 failed auths in 10m0s",
	}}
	AutoBlockIPs(cfg, findings)

	if len(blocker.blocked) != 1 || blocker.blocked[0] != "203.0.113.5" {
		t.Errorf("expected BlockIP(203.0.113.5), got %v", blocker.blocked)
	}
}

func TestAutoBlock_MailAccountCompromisedTriggersBlockIP(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.StatePath = t.TempDir()

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	findings := []alert.Finding{{
		Check:   "mail_account_compromised",
		Message: "Mail account compromise: successful login for alice@example.com from 203.0.113.5 after recent auth failures",
	}}
	AutoBlockIPs(cfg, findings)

	if len(blocker.blocked) != 1 || blocker.blocked[0] != "203.0.113.5" {
		t.Errorf("expected BlockIP(203.0.113.5), got %v", blocker.blocked)
	}
}

func TestAutoBlock_MailSubnetSprayTriggersBlockSubnet(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.StatePath = t.TempDir()
	setAutoResponseLive(cfg)

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	findings := []alert.Finding{{
		Check:   "mail_subnet_spray",
		Message: "Mail password spray from 203.0.113.0/24: 8 unique IPs in 10m0s",
	}}
	AutoBlockIPs(cfg, findings)

	if len(blocker.blockedSubnet) != 1 || blocker.blockedSubnet[0] != "203.0.113.0/24" {
		t.Errorf("expected BlockSubnet(203.0.113.0/24), got %v", blocker.blockedSubnet)
	}
	if len(blocker.blocked) != 0 {
		t.Errorf("expected no BlockIP calls; got %v", blocker.blocked)
	}
}

func TestAutoBlock_AdminPanelBruteForceTriggersBlockIP(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.StatePath = t.TempDir()

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	findings := []alert.Finding{{
		Check:   "admin_panel_bruteforce",
		Message: "Admin panel brute force from 203.0.113.5: 10 POSTs in 5m0s (real-time)",
	}}
	AutoBlockIPs(cfg, findings)

	if len(blocker.blocked) != 1 || blocker.blocked[0] != "203.0.113.5" {
		t.Errorf("expected BlockIP(203.0.113.5), got %v", blocker.blocked)
	}
}

func TestAutoBlock_SMTPSubnetSprayBypassesPerIPRateLimit(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.StatePath = t.TempDir()
	setAutoResponseLive(cfg)

	fake := &recordingIPBlocker{}
	prev := getIPBlocker()
	SetIPBlocker(fake)
	defer func() { SetIPBlocker(prev) }()

	state := loadBlockState(cfg.StatePath)
	now := time.Date(2026, 6, 2, 13, 15, 0, 0, time.UTC)
	setAutoBlockNow(t, now)
	state.HourKey = now.Format("2006-01-02T15")
	state.BlocksThisHour = config.DefaultMaxBlocksPerHour
	saveBlockState(cfg.StatePath, state)

	findings := []alert.Finding{{
		Check:   "smtp_subnet_spray",
		Message: "SMTP password spray from 203.0.113.0/24: 8 unique IPs in 10m0s",
	}}
	AutoBlockIPs(cfg, findings)

	if len(fake.blockedSubnet) != 1 {
		t.Errorf("subnet spray must bypass per-IP rate limit; got %v", fake.blockedSubnet)
	}
}

func TestAutoBlock_EmailAuthFailureRealtimeDoesNotBlockSingleFailure(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.StatePath = t.TempDir()

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	findings := []alert.Finding{{
		Check:    "email_auth_failure_realtime",
		Message:  "Email authentication failure for alice@example.com from 203.0.113.7",
		SourceIP: "203.0.113.7",
		Mailbox:  "alice",
		Domain:   "example.com",
	}}
	actions := AutoBlockIPs(cfg, findings)

	if len(blocker.blocked) != 0 {
		t.Fatalf("email_auth_failure_realtime blocked IPs = %v, want none", blocker.blocked)
	}
	if len(actions) != 0 {
		t.Fatalf("email_auth_failure_realtime actions = %+v, want none", actions)
	}
}

func TestAutoBlock_MailBruteforceSuspectedDoesNotBlock(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.StatePath = t.TempDir()

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	findings := []alert.Finding{{
		Check:    "mail_bruteforce_suspected",
		Message:  "Suspected mail misconfiguration from 203.0.113.8: 5 failed auths in 10m0s from an established good source (not auto-blocked)",
		SourceIP: "203.0.113.8",
	}}
	actions := AutoBlockIPs(cfg, findings)

	if len(blocker.blocked) != 0 {
		t.Fatalf("mail_bruteforce_suspected blocked IPs = %v, want none", blocker.blocked)
	}
	if len(actions) != 0 {
		t.Fatalf("mail_bruteforce_suspected actions = %+v, want none", actions)
	}
}

func TestAutoBlock_AccountOnlyMailFindingsDoNotBlock(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.StatePath = t.TempDir()

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	findings := []alert.Finding{
		{
			Check:   "email_credential_leak",
			Message: "SMTP credentials leaked in email subject from bob@example.com",
			Mailbox: "bob",
			Domain:  "example.com",
		},
		{
			Check:   "email_spam_outbreak",
			Message: "Spam outbreak: example.com exceeded max defers/failures - outgoing mail auto-suspended",
			Domain:  "example.com",
		},
		{
			Check:    "email_rate_critical",
			Message:  "Email rate CRITICAL: alice@example.com sent 500 messages in 60 minutes (threshold: 500)",
			Mailbox:  "alice",
			Domain:   "example.com",
			TenantID: "alice@example.com",
		},
	}
	actions := AutoBlockIPs(cfg, findings)

	if len(blocker.blocked) != 0 {
		t.Fatalf("account-only mail findings blocked IPs = %v, want none", blocker.blocked)
	}
	if len(actions) != 0 {
		t.Fatalf("account-only mail findings actions = %+v, want none", actions)
	}
}

func TestAutoBlock_SuspiciousGeoDoesNotHardBlockLoginIP(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.StatePath = t.TempDir()

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	findings := []alert.Finding{{
		Check:    "email_suspicious_geo",
		Message:  "Suspicious email login for alice@example.com from Romania (203.0.113.77) - previously seen: US",
		SourceIP: "203.0.113.77",
		Mailbox:  "alice",
		Domain:   "example.com",
	}}
	actions := AutoBlockIPs(cfg, findings)

	if len(blocker.blocked) != 0 {
		t.Fatalf("email_suspicious_geo blocked IPs = %v, want none", blocker.blocked)
	}
	if len(actions) != 0 {
		t.Fatalf("email_suspicious_geo actions = %+v, want none", actions)
	}
}

// A single direct cPanel login from a non-infra IP is a Warning-level
// audit row, not brute evidence. Even with block_cpanel_logins=true the
// auto-blocker must not slam the firewall on one event; that turns a
// legitimate customer logging in from a new country into a 24h lockout.
// Thresholded checks (multi_ip_login, webmail/api bruteforce, etc.)
// stay blockable under block_cpanel_logins.
func TestAutoBlock_CpanelLoginRealtimeDoesNotBlockSingleLogin(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.BlockCpanelLogins = true
	cfg.StatePath = t.TempDir()

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	findings := []alert.Finding{
		{
			Check:    "cpanel_login_realtime",
			Message:  "cPanel direct login from non-infra IP: 203.0.113.7 (account: bob, method: direct form login)",
			SourceIP: "203.0.113.7",
			TenantID: "bob",
		},
		{
			Check:    "cpanel_login",
			Message:  "cPanel direct login from non-infra IP: 198.51.100.9 (account: alice)",
			SourceIP: "198.51.100.9",
			TenantID: "alice",
		},
	}
	actions := AutoBlockIPs(cfg, findings)

	if len(blocker.blocked) != 0 {
		t.Fatalf("single cpanel_login finding blocked IPs = %v, want none", blocker.blocked)
	}
	if len(actions) != 0 {
		t.Fatalf("single cpanel_login findings actions = %+v, want none", actions)
	}
}

func TestAutoBlock_FTPLoginAfterBruteforceDoesNotBlockDirectly(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.StatePath = t.TempDir()

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	findings := []alert.Finding{{
		Check:    "ftp_login_after_bruteforce",
		Severity: alert.Critical,
		Message:  "FTP login succeeded for account alice from brute-force source 203.0.113.7 after 10 failed attempts",
		SourceIP: "203.0.113.7",
	}}
	actions := AutoBlockIPs(cfg, findings)

	if len(blocker.blocked) != 0 {
		t.Fatalf("ftp_login_after_bruteforce blocked IPs = %v, want none", blocker.blocked)
	}
	if len(actions) != 0 {
		t.Fatalf("ftp_login_after_bruteforce actions = %+v, want none", actions)
	}
}

func TestAutoBlock_AccountSprayFindingsRemainVisibilityOnly(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.StatePath = t.TempDir()

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	findings := []alert.Finding{
		{
			Check:    "smtp_account_spray",
			Message:  "SMTP password spray targeting alice@example.com: 12 unique IPs in 10m0s",
			SourceIP: "203.0.113.91",
			Mailbox:  "alice@example.com",
			Domain:   "example.com",
		},
		{
			Check:    "mail_account_spray",
			Message:  "Mail password spray targeting bob@example.com: 12 unique IPs in 10m0s",
			SourceIP: "203.0.113.92",
			Mailbox:  "bob@example.com",
			Domain:   "example.com",
		},
	}
	actions := AutoBlockIPs(cfg, findings)

	if len(blocker.blocked) != 0 {
		t.Fatalf("account-spray findings blocked IPs = %v, want none", blocker.blocked)
	}
	if len(actions) != 0 {
		t.Fatalf("account-spray findings actions = %+v, want none", actions)
	}
}

func TestAutoBlock_CredentialSprayIncidentKindIsNotFindingCheck(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.StatePath = t.TempDir()

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	findings := []alert.Finding{{
		Check:    "credential_spray",
		Message:  "Credential spray super-incident: 203.0.113.50 hit 8 distinct mailboxes in 15m",
		SourceIP: "203.0.113.50",
	}}
	actions := AutoBlockIPs(cfg, findings)

	if len(blocker.blocked) != 0 {
		t.Fatalf("credential_spray finding blocked IPs = %v, want none", blocker.blocked)
	}
	if len(actions) != 0 {
		t.Fatalf("credential_spray finding actions = %+v, want none", actions)
	}
}

func TestAutoBlock_HTTPRequestFlood(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	rb := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(rb)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() { SetChallengeIPList(oldChallengeList) })

	f := []alert.Finding{{
		Check:    "http_request_flood",
		Severity: alert.High,
		SourceIP: "192.0.2.200",
		Message:  "HTTP request flood from 192.0.2.200: 250 requests",
	}}
	AutoBlockIPs(cfg, f)
	if len(rb.blocked) != 1 || rb.blocked[0] != "192.0.2.200" {
		t.Fatalf("blocked=%v want [192.0.2.200]", rb.blocked)
	}
}

func TestAutoBlock_HTTPScannerProfile(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	rb := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(rb)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() { SetChallengeIPList(oldChallengeList) })

	f := []alert.Finding{{
		Check:    "http_scanner_profile",
		Severity: alert.High,
		SourceIP: "192.0.2.201",
		Message:  "URL scanner profile from 192.0.2.201: 50 of 50 requests",
	}}
	AutoBlockIPs(cfg, f)
	if len(rb.blocked) != 1 || rb.blocked[0] != "192.0.2.201" {
		t.Fatalf("blocked=%v want [192.0.2.201]", rb.blocked)
	}
}

func TestAutoBlock_HTTPClaimedBotUnverified(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	rb := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(rb)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() { SetChallengeIPList(oldChallengeList) })

	f := []alert.Finding{{
		Check:    "http_claimed_bot_unverified",
		Severity: alert.High,
		SourceIP: "192.0.2.202",
		Message:  "Unverified claimed bot from 192.0.2.202: request flood",
	}}
	AutoBlockIPs(cfg, f)
	if len(rb.blocked) != 1 || rb.blocked[0] != "192.0.2.202" {
		t.Fatalf("blocked=%v want [192.0.2.202]", rb.blocked)
	}
}

func TestAutoBlock_HTTPUASpoof(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	rb := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(rb)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	oldChallengeList := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() { SetChallengeIPList(oldChallengeList) })

	f := []alert.Finding{{
		Check:    "http_ua_spoof",
		Severity: alert.Critical,
		SourceIP: "203.0.113.200",
		Message:  "UA spoof",
	}}
	AutoBlockIPs(cfg, f)
	if len(rb.blocked) != 1 || rb.blocked[0] != "203.0.113.200" {
		t.Fatalf("blocked=%v want [203.0.113.200]", rb.blocked)
	}
}

// asnCrawlCfg returns a cfg ready for http_asn_crawl subnet tempban tests:
// Enabled+BlockIPs true, DryRun=false, valid StatePath.
func asnCrawlCfg(t *testing.T) *config.Config {
	t.Helper()
	dryRun := false
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.DryRun = &dryRun
	cfg.AutoResponse.HTTPASNCrawlTempban = "24h"
	return cfg
}

func TestAutoBlockHTTPASNCrawlTempbansCIDRs(t *testing.T) {
	blocker := &recordingIPBlocker{}
	prev := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(prev) })

	cfg := asnCrawlCfg(t)
	f := alert.Finding{
		Check:    "http_asn_crawl",
		Severity: alert.Critical,
		Message:  "Distributed crawl from AS45102 (Alibaba) against radiusro",
		CIDRs:    []string{"203.0.113.0/24", "198.51.100.0/24"},
	}

	actions := AutoBlockIPs(cfg, []alert.Finding{f})

	if len(blocker.blockedSubnet) != 2 {
		t.Fatalf("expected 2 subnets blocked, got %v", blocker.blockedSubnet)
	}
	found203, found198 := false, false
	for _, s := range blocker.blockedSubnet {
		if s == "203.0.113.0/24" {
			found203 = true
		}
		if s == "198.51.100.0/24" {
			found198 = true
		}
	}
	if !found203 || !found198 {
		t.Fatalf("expected both CIDRs tempbanned, got %+v", blocker.blockedSubnet)
	}

	for _, sc := range blocker.subnetCalls {
		if sc.cidr == "203.0.113.0/24" && sc.timeout != 24*time.Hour {
			t.Fatalf("tempban duration for 203.0.113.0/24 = %v, want 24h", sc.timeout)
		}
	}

	var hasAutoBlockSubnet bool
	for _, a := range actions {
		if strings.Contains(a.Message, "AUTO-BLOCK-SUBNET") {
			hasAutoBlockSubnet = true
			break
		}
	}
	if !hasAutoBlockSubnet {
		t.Fatal("expected auto_block action findings with AUTO-BLOCK-SUBNET, got none")
	}
}

func TestAutoBlockHTTPASNCrawlGuards(t *testing.T) {
	// Sub-case 1: dry-run must not block.
	t.Run("dry-run", func(t *testing.T) {
		blocker := &recordingIPBlocker{}
		prev := getIPBlocker()
		SetIPBlocker(blocker)
		t.Cleanup(func() { SetIPBlocker(prev) })

		dryRun := true
		cfg := &config.Config{}
		cfg.StatePath = t.TempDir()
		cfg.AutoResponse.Enabled = true
		cfg.AutoResponse.BlockIPs = true
		cfg.AutoResponse.DryRun = &dryRun
		cfg.AutoResponse.HTTPASNCrawlTempban = "24h"

		f := alert.Finding{Check: "http_asn_crawl", Severity: alert.Critical, CIDRs: []string{"203.0.113.0/24"}}
		AutoBlockIPs(cfg, []alert.Finding{f})
		if len(blocker.blockedSubnet) != 0 {
			t.Fatalf("dry-run must not block subnets, got %v", blocker.blockedSubnet)
		}
	})

	// Sub-case 2: non-Critical must not block.
	t.Run("non-critical", func(t *testing.T) {
		blocker := &recordingIPBlocker{}
		prev := getIPBlocker()
		SetIPBlocker(blocker)
		t.Cleanup(func() { SetIPBlocker(prev) })

		cfg := asnCrawlCfg(t)
		f := alert.Finding{Check: "http_asn_crawl", Severity: alert.High, CIDRs: []string{"203.0.113.0/24"}}
		AutoBlockIPs(cfg, []alert.Finding{f})
		if len(blocker.blockedSubnet) != 0 {
			t.Fatalf("non-Critical must not block subnets, got %v", blocker.blockedSubnet)
		}
	})

	// Sub-case 3: CIDR containing an infra IP must be skipped.
	t.Run("infra-intersect", func(t *testing.T) {
		blocker := &recordingIPBlocker{}
		prev := getIPBlocker()
		SetIPBlocker(blocker)
		t.Cleanup(func() { SetIPBlocker(prev) })

		cfg := asnCrawlCfg(t)
		cfg.InfraIPs = []string{"203.0.113.7"}

		f := alert.Finding{Check: "http_asn_crawl", Severity: alert.Critical, CIDRs: []string{"203.0.113.0/24"}}
		AutoBlockIPs(cfg, []alert.Finding{f})
		if len(blocker.blockedSubnet) != 0 {
			t.Fatalf("CIDR intersecting an infra IP must be skipped, got %v", blocker.blockedSubnet)
		}
	})

	// Sub-case 4: CIDR intersecting an infra CIDR range must be skipped.
	t.Run("infra-cidr-intersect", func(t *testing.T) {
		blocker := &recordingIPBlocker{}
		prev := getIPBlocker()
		SetIPBlocker(blocker)
		t.Cleanup(func() { SetIPBlocker(prev) })

		cfg := asnCrawlCfg(t)
		cfg.InfraIPs = []string{" 203.0.113.0/25 "}

		f := alert.Finding{Check: "http_asn_crawl", Severity: alert.Critical, CIDRs: []string{"203.0.113.0/24"}}
		AutoBlockIPs(cfg, []alert.Finding{f})
		if len(blocker.blockedSubnet) != 0 {
			t.Fatalf("CIDR intersecting an infra range must be skipped, got %v", blocker.blockedSubnet)
		}
	})

	// Sub-case 5: loopback CIDRs must be skipped even outside 127.0.0.0/24.
	t.Run("loopback-cidr", func(t *testing.T) {
		blocker := &recordingIPBlocker{}
		prev := getIPBlocker()
		SetIPBlocker(blocker)
		t.Cleanup(func() { SetIPBlocker(prev) })

		cfg := asnCrawlCfg(t)

		f := alert.Finding{Check: "http_asn_crawl", Severity: alert.Critical, CIDRs: []string{"127.1.2.0/24"}}
		AutoBlockIPs(cfg, []alert.Finding{f})
		if len(blocker.blockedSubnet) != 0 {
			t.Fatalf("loopback CIDR must be skipped, got %v", blocker.blockedSubnet)
		}
	})
}

// cfgWithExempt returns a config with the given CIDR ranges as DoS-exempt
// operator ranges. Known mail-provider ranges are disabled so tests are
// deterministic regardless of the embedded snapshot.
func cfgWithExempt(t *testing.T, ranges ...string) *config.Config {
	t.Helper()
	f := false
	cfg := &config.Config{}
	cfg.Firewall = &firewall.FirewallConfig{
		DOSExemptRanges:             ranges,
		DOSExemptKnownMailProviders: &f,
	}
	return cfg
}

// preBlockedIPBlocker wraps recordingIPBlocker to report specific IPs as
// already blocked so the AutoBlockIPs reconciliation loop does not prune
// them from block state during the initial "engine expired" sweep.
type preBlockedIPBlocker struct {
	*recordingIPBlocker
	live map[string]bool
}

func (b *preBlockedIPBlocker) IsBlocked(ip string) bool { return b.live[ip] }

// TestNetblock_SkipsExemptSubnet verifies that IPs individually blocked from
// a DoS-exempt range never trigger a subnet block even when their count meets
// the netblock threshold.
func TestNetblock_SkipsExemptSubnet(t *testing.T) {
	// Case 1: 3 IPs in exempt 203.0.113.0/24 -- BlockSubnet must NOT be called.
	t.Run("exempt-suppresses-netblock", func(t *testing.T) {
		blocker := &recordingIPBlocker{}
		prev := getIPBlocker()
		SetIPBlocker(blocker)
		t.Cleanup(func() { SetIPBlocker(prev) })

		oldCL := GetChallengeIPList()
		SetChallengeIPList(nil)
		t.Cleanup(func() { SetChallengeIPList(oldCL) })

		f := false
		cfg := &config.Config{}
		cfg.StatePath = t.TempDir()
		cfg.AutoResponse.Enabled = true
		cfg.AutoResponse.BlockIPs = true
		cfg.AutoResponse.NetBlock = true
		cfg.AutoResponse.NetBlockThreshold = 3
		setAutoResponseLive(cfg)
		cfg.Firewall = &firewall.FirewallConfig{
			DOSExemptRanges:             []string{"203.0.113.0/24"},
			DOSExemptKnownMailProviders: &f,
		}

		findings := []alert.Finding{
			{Check: "wp_login_bruteforce", SourceIP: "203.0.113.1", Message: "brute from 203.0.113.1"},
			{Check: "wp_login_bruteforce", SourceIP: "203.0.113.2", Message: "brute from 203.0.113.2"},
			{Check: "wp_login_bruteforce", SourceIP: "203.0.113.3", Message: "brute from 203.0.113.3"},
		}
		AutoBlockIPs(cfg, findings)

		for _, sc := range blocker.subnetCalls {
			if sc.cidr == "203.0.113.0/24" {
				t.Fatalf("exempt subnet 203.0.113.0/24 must not be blocked; subnetCalls=%+v", blocker.subnetCalls)
			}
		}
	})

	// Case 2: same 3 IPs in non-exempt 203.0.113.0/24 -- BlockSubnet MUST be called.
	t.Run("non-exempt-triggers-netblock", func(t *testing.T) {
		blocker := &recordingIPBlocker{}
		prev := getIPBlocker()
		SetIPBlocker(blocker)
		t.Cleanup(func() { SetIPBlocker(prev) })

		oldCL := GetChallengeIPList()
		SetChallengeIPList(nil)
		t.Cleanup(func() { SetChallengeIPList(oldCL) })

		f := false
		cfg := &config.Config{}
		cfg.StatePath = t.TempDir()
		cfg.AutoResponse.Enabled = true
		cfg.AutoResponse.BlockIPs = true
		cfg.AutoResponse.NetBlock = true
		cfg.AutoResponse.NetBlockThreshold = 3
		setAutoResponseLive(cfg)
		cfg.Firewall = &firewall.FirewallConfig{
			DOSExemptRanges:             nil,
			DOSExemptKnownMailProviders: &f,
		}

		findings := []alert.Finding{
			{Check: "wp_login_bruteforce", SourceIP: "203.0.113.1", Message: "brute from 203.0.113.1"},
			{Check: "wp_login_bruteforce", SourceIP: "203.0.113.2", Message: "brute from 203.0.113.2"},
			{Check: "wp_login_bruteforce", SourceIP: "203.0.113.3", Message: "brute from 203.0.113.3"},
		}
		AutoBlockIPs(cfg, findings)

		var saw bool
		for _, sc := range blocker.subnetCalls {
			if sc.cidr == "203.0.113.0/24" {
				saw = true
			}
		}
		if !saw {
			t.Fatalf("non-exempt /24 must be blocked; subnetCalls=%+v", blocker.subnetCalls)
		}
	})
}

// TestNetblock_ExemptIPsNotCounted verifies that pre-blocked IPs inside
// an exempt range are excluded from the per-subnet threshold count, so they
// cannot push a subnet over the netblock threshold.
func TestNetblock_ExemptIPsNotCounted(t *testing.T) {
	blocker := &preBlockedIPBlocker{
		recordingIPBlocker: &recordingIPBlocker{},
		live: map[string]bool{
			"203.0.113.1": true,
			"203.0.113.2": true,
			"203.0.113.3": true,
		},
	}
	prev := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(prev) })

	oldCL := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() { SetChallengeIPList(oldCL) })

	f := false
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.NetBlock = true
	cfg.AutoResponse.NetBlockThreshold = 3
	setAutoResponseLive(cfg)
	cfg.Firewall = &firewall.FirewallConfig{
		DOSExemptRanges:             []string{"203.0.113.0/24"},
		DOSExemptKnownMailProviders: &f,
	}

	now := time.Now()
	saveBlockState(cfg.StatePath, &blockState{
		IPs: []blockedIP{
			{IP: "203.0.113.1", Reason: "test", BlockedAt: now, ExpiresAt: now.Add(time.Hour)},
			{IP: "203.0.113.2", Reason: "test", BlockedAt: now, ExpiresAt: now.Add(time.Hour)},
			{IP: "203.0.113.3", Reason: "test", BlockedAt: now, ExpiresAt: now.Add(time.Hour)},
		},
	})

	AutoBlockIPs(cfg, nil)

	if len(blocker.subnetCalls) != 0 {
		t.Fatalf("exempt IPs must not contribute to threshold count; subnetCalls=%+v", blocker.subnetCalls)
	}
}

// TestIPv6Netblock_SkipsExemptSubnet verifies that IPv6 addresses from an
// exempt /64 do not trigger a /64 subnet block.
func TestIPv6Netblock_SkipsExemptSubnet(t *testing.T) {
	blocker := &recordingIPBlocker{}
	prev := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(prev) })

	oldCL := GetChallengeIPList()
	SetChallengeIPList(nil)
	t.Cleanup(func() { SetChallengeIPList(oldCL) })

	f := false
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.NetBlock = true
	cfg.AutoResponse.NetBlockThreshold = 2
	setAutoResponseLive(cfg)
	cfg.Firewall = &firewall.FirewallConfig{
		DOSExemptRanges:             []string{"2001:db8:1::/64"},
		DOSExemptKnownMailProviders: &f,
	}

	findings := []alert.Finding{
		{Check: "wp_login_bruteforce", SourceIP: "2001:db8:1::10", Message: "brute from 2001:db8:1::10"},
		{Check: "wp_login_bruteforce", SourceIP: "2001:db8:1::20", Message: "brute from 2001:db8:1::20"},
	}
	AutoBlockIPs(cfg, findings)

	for _, sc := range blocker.subnetCalls {
		if sc.cidr == "2001:db8:1::/64" {
			t.Fatalf("exempt IPv6 /64 must not be blocked; subnetCalls=%+v", blocker.subnetCalls)
		}
	}
}

// TestSprayASNCrawl_SkipExemptSubnet verifies that the direct subnet paths
// (smtp_subnet_spray, mail_subnet_spray, http_asn_crawl) skip CIDRs that
// intersect a DoS-exempt range.
func TestSprayASNCrawl_SkipExemptSubnet(t *testing.T) {
	f := false

	newCfg := func(t *testing.T) *config.Config {
		t.Helper()
		cfg := &config.Config{}
		cfg.StatePath = t.TempDir()
		cfg.AutoResponse.Enabled = true
		cfg.AutoResponse.BlockIPs = true
		setAutoResponseLive(cfg)
		cfg.Firewall = &firewall.FirewallConfig{
			DOSExemptRanges:             []string{"203.0.113.0/24"},
			DOSExemptKnownMailProviders: &f,
		}
		return cfg
	}

	t.Run("smtp-spray", func(t *testing.T) {
		blocker := &recordingIPBlocker{}
		prev := getIPBlocker()
		SetIPBlocker(blocker)
		t.Cleanup(func() { SetIPBlocker(prev) })

		cfg := newCfg(t)
		AutoBlockIPs(cfg, []alert.Finding{{
			Check:   "smtp_subnet_spray",
			Message: "SMTP password spray from 203.0.113.0/24: 8 unique IPs in 10m0s",
		}})
		if len(blocker.subnetCalls) != 0 {
			t.Fatalf("smtp_subnet_spray: exempt CIDR must be skipped; subnetCalls=%+v", blocker.subnetCalls)
		}
	})

	t.Run("mail-spray", func(t *testing.T) {
		blocker := &recordingIPBlocker{}
		prev := getIPBlocker()
		SetIPBlocker(blocker)
		t.Cleanup(func() { SetIPBlocker(prev) })

		cfg := newCfg(t)
		AutoBlockIPs(cfg, []alert.Finding{{
			Check:   "mail_subnet_spray",
			Message: "Mail password spray from 203.0.113.0/24: 8 unique IPs in 10m0s",
		}})
		if len(blocker.subnetCalls) != 0 {
			t.Fatalf("mail_subnet_spray: exempt CIDR must be skipped; subnetCalls=%+v", blocker.subnetCalls)
		}
	})

	t.Run("asn-crawl", func(t *testing.T) {
		blocker := &recordingIPBlocker{}
		prev := getIPBlocker()
		SetIPBlocker(blocker)
		t.Cleanup(func() { SetIPBlocker(prev) })

		dryRun := false
		cfg := newCfg(t)
		cfg.AutoResponse.DryRun = &dryRun
		cfg.AutoResponse.HTTPASNCrawlTempban = "24h"
		AutoBlockIPs(cfg, []alert.Finding{{
			Check:    "http_asn_crawl",
			Severity: alert.Critical,
			Message:  "Distributed crawl",
			CIDRs:    []string{"203.0.113.0/24"},
		}})
		if len(blocker.subnetCalls) != 0 {
			t.Fatalf("http_asn_crawl: exempt CIDR must be skipped; subnetCalls=%+v", blocker.subnetCalls)
		}
	})
}

// TestExemptSubnetSkipDoesNotConsumeHourlyBudget verifies that skipping an
// exempt CIDR in the http_asn_crawl path does not consume a MaxBlocksPerHour
// slot, so a subsequent non-exempt subnet can still be blocked in the same cycle.
func TestExemptSubnetSkipDoesNotConsumeHourlyBudget(t *testing.T) {
	blocker := &recordingIPBlocker{}
	prev := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(prev) })

	f := false
	dryRun := false
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.DryRun = &dryRun
	cfg.AutoResponse.HTTPASNCrawlTempban = "24h"
	cfg.AutoResponse.MaxBlocksPerHour = 1
	cfg.Firewall = &firewall.FirewallConfig{
		DOSExemptRanges:             []string{"203.0.113.0/24"},
		DOSExemptKnownMailProviders: &f,
	}

	AutoBlockIPs(cfg, []alert.Finding{{
		Check:    "http_asn_crawl",
		Severity: alert.Critical,
		Message:  "Distributed crawl",
		CIDRs:    []string{"203.0.113.0/24", "198.51.100.0/24"},
	}})

	for _, sc := range blocker.subnetCalls {
		if sc.cidr == "203.0.113.0/24" {
			t.Fatalf("exempt CIDR must not be blocked; subnetCalls=%+v", blocker.subnetCalls)
		}
	}

	var saw198 bool
	for _, sc := range blocker.subnetCalls {
		if sc.cidr == "198.51.100.0/24" {
			saw198 = true
		}
	}
	if !saw198 {
		t.Fatalf("non-exempt CIDR must be blocked after exempt skip (budget must not be consumed); subnetCalls=%+v", blocker.subnetCalls)
	}

	state := loadBlockState(cfg.StatePath)
	if state.BlocksThisHour != 1 {
		t.Fatalf("BlocksThisHour = %d, want 1 (only non-exempt block counted)", state.BlocksThisHour)
	}
}

func TestCidrIntersectsDOSExempt(t *testing.T) {
	// Exact IPv4 overlap.
	cfg := cfgWithExempt(t, "203.0.113.0/24")
	if !cidrIntersectsDOSExempt(cfg, "203.0.113.0/24") {
		t.Fatal("exact overlap: expected true")
	}
	// Non-overlapping IPv4.
	if cidrIntersectsDOSExempt(cfg, "198.51.100.0/24") {
		t.Fatal("no overlap: expected false")
	}
	// Malformed CIDR must fail safe (return true).
	if !cidrIntersectsDOSExempt(cfg, "garbage") {
		t.Fatal("malformed must fail safe to true")
	}
	// Candidate is a supernet of the exempt range (two-way Contains: candidate
	// bigger than exempt -> ipnet.Contains(exempt.IP) arm).
	if !cidrIntersectsDOSExempt(cfg, "203.0.112.0/23") {
		t.Fatal("candidate supernet of exempt: expected true")
	}
	// Candidate is a host inside the exempt range (two-way Contains: exempt
	// bigger than candidate -> exempt.Contains(ipnet.IP) arm in isolation).
	if !cidrIntersectsDOSExempt(cfg, "203.0.113.5/32") {
		t.Fatal("host inside exempt /24 must intersect")
	}
	// IPv6 exempt range - exact overlap.
	cfgV6 := cfgWithExempt(t, "2001:db8::/64")
	if !cidrIntersectsDOSExempt(cfgV6, "2001:db8::/64") {
		t.Fatal("exact IPv6 /64 overlap: expected true")
	}
	// IPv6 non-overlapping range.
	if cidrIntersectsDOSExempt(cfgV6, "2001:db8:1::/64") {
		t.Fatal("non-overlapping IPv6 /64: expected false")
	}
}

// subnetManagerBlocker is a test double that satisfies both IPBlocker and the
// subnetManager interface expected by PruneExemptAutoSubnets.
type subnetManagerBlocker struct {
	subnets    []firewall.SubnetEntry
	unblocked  []string
	unblockErr error
	// callCount counts every UnblockSubnet invocation, success or error, so a
	// test can prove the prune loop continued past a failing entry.
	callCount int
}

func (b *subnetManagerBlocker) BlockIP(_ string, _ string, _ time.Duration) error { return nil }
func (b *subnetManagerBlocker) UnblockIP(_ string) error                          { return nil }
func (b *subnetManagerBlocker) IsBlocked(_ string) bool                           { return false }
func (b *subnetManagerBlocker) BlockSubnet(_ string, _ string, _ time.Duration) error {
	return nil
}
func (b *subnetManagerBlocker) IsSubnetBlocked(_ string) bool { return false }
func (b *subnetManagerBlocker) BlockedSubnets() []firewall.SubnetEntry {
	out := make([]firewall.SubnetEntry, len(b.subnets))
	copy(out, b.subnets)
	return out
}
func (b *subnetManagerBlocker) UnblockSubnet(cidr string) error {
	b.callCount++
	if b.unblockErr != nil {
		return b.unblockErr
	}
	b.unblocked = append(b.unblocked, cidr)
	return nil
}

// TestPruneExemptAutoSubnets verifies that PruneExemptAutoSubnets:
//   - calls UnblockSubnet only for auto_response entries whose CIDR intersects
//     the DoS-exempt set
//   - leaves every other provenance source untouched even when it intersects
//     the exempt range (web_ui, cli, challenge, whitelist, dyndns, system,
//     unknown, and an empty/zero source)
//   - leaves auto_response entries outside the exempt range untouched
//   - returns the correct pruned count
//   - returns 0 when the blocker does not implement subnetManager
func TestPruneExemptAutoSubnets(t *testing.T) {
	cfg := cfgWithExempt(t, "203.0.113.0/24")

	// Every non-auto_response provenance source, each intersecting the exempt
	// range, must survive. Sources are the real constants from
	// internal/firewall/provenance.go plus an explicit empty source.
	survivorSources := []string{
		firewall.SourceWebUI,
		firewall.SourceCLI,
		firewall.SourceChallenge,
		firewall.SourceWhitelist,
		firewall.SourceDynDNS,
		firewall.SourceSystem,
		firewall.SourceUnknown,
		"", // empty/zero source must also be left alone
	}

	subnets := []firewall.SubnetEntry{
		// Should be pruned: auto_response + intersects exempt range.
		{CIDR: "203.0.113.0/24", Source: firewall.SourceAutoResponse, Reason: "http_asn_crawl"},
		// Should be pruned: auto_response + subnet of exempt range.
		{CIDR: "203.0.113.128/25", Source: firewall.SourceAutoResponse, Reason: "netblock"},
		// Should NOT be pruned: auto_response but outside exempt range.
		{CIDR: "198.51.100.0/24", Source: firewall.SourceAutoResponse, Reason: "http_asn_crawl"},
	}
	// One intersecting entry per non-auto_response source. Distinct /28s inside
	// the exempt /24 so each is a separately addressable survivor.
	for i, src := range survivorSources {
		subnets = append(subnets, firewall.SubnetEntry{
			CIDR:   fmt.Sprintf("203.0.113.%d/28", i*16),
			Source: src,
			Reason: "operator",
		})
	}

	sm := &subnetManagerBlocker{subnets: subnets}

	pruned := PruneExemptAutoSubnets(cfg, sm)

	if pruned != 2 {
		t.Errorf("want 2 pruned, got %d", pruned)
	}
	if len(sm.unblocked) != 2 {
		t.Fatalf("want 2 UnblockSubnet calls, got %d: %v", len(sm.unblocked), sm.unblocked)
	}
	// Only the two intersecting auto_response CIDRs may be unblocked.
	wantUnblocked := map[string]bool{
		"203.0.113.0/24":   true,
		"203.0.113.128/25": true,
	}
	for _, cidr := range sm.unblocked {
		if !wantUnblocked[cidr] {
			t.Errorf("unexpected unblock of %s", cidr)
		}
	}
	// The non-exempt auto_response entry and every survivor source must NOT have
	// been unblocked.
	unblockedSet := make(map[string]bool, len(sm.unblocked))
	for _, cidr := range sm.unblocked {
		unblockedSet[cidr] = true
	}
	if unblockedSet["198.51.100.0/24"] {
		t.Errorf("non-exempt auto_response subnet 198.51.100.0/24 must not be unblocked")
	}
	for i := range survivorSources {
		cidr := fmt.Sprintf("203.0.113.%d/28", i*16)
		if unblockedSet[cidr] {
			t.Errorf("source %q survivor %s was unblocked but must be left alone",
				survivorSources[i], cidr)
		}
	}

	// Blocker that does not implement subnetManager must return 0.
	plain := &recordingIPBlocker{}
	if n := PruneExemptAutoSubnets(cfg, plain); n != 0 {
		t.Errorf("plain IPBlocker: want 0, got %d", n)
	}
}

// TestPruneExemptAutoSubnetsUnblockError verifies that an UnblockSubnet error
// is logged (we check stderr is not crashed) and the failing entry is not
// counted as pruned, but processing continues for subsequent entries.
func TestPruneExemptAutoSubnetsUnblockError(t *testing.T) {
	cfg := cfgWithExempt(t, "203.0.113.0/24")

	sm := &subnetManagerBlocker{
		subnets: []firewall.SubnetEntry{
			{CIDR: "203.0.113.0/28", Source: firewall.SourceAutoResponse, Reason: "x"},
			{CIDR: "203.0.113.16/28", Source: firewall.SourceAutoResponse, Reason: "x"},
		},
		unblockErr: fmt.Errorf("nftables: permission denied"),
	}

	pruned := PruneExemptAutoSubnets(cfg, sm)

	// Both entries matched but both failed to unblock → 0 pruned.
	if pruned != 0 {
		t.Errorf("want 0 pruned on unblock errors, got %d", pruned)
	}
	// The loop must have CONTINUED past the first failing entry and attempted
	// the second too: two UnblockSubnet calls, both errored.
	if sm.callCount != 2 {
		t.Errorf("want 2 UnblockSubnet attempts (loop continued past error), got %d", sm.callCount)
	}
	// No entry recorded as successfully unblocked.
	if len(sm.unblocked) != 0 {
		t.Errorf("unblockErr set but unblocked list non-empty: %v", sm.unblocked)
	}
}
