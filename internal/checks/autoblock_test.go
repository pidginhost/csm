package checks

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
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

func TestAutoBlockIPs_SubnetStatusUsesScanSnapshot(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

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
