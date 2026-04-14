package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

type recordingIPBlocker struct {
	blocked       []string
	calls         []blockCall
	blockedSubnet []string
}

func (b *recordingIPBlocker) BlockSubnet(cidr, reason string, timeout time.Duration) error {
	b.blockedSubnet = append(b.blockedSubnet, cidr)
	return nil
}

type blockCall struct {
	ip      string
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

type staticChallengeIPList struct {
	ips map[string]bool
}

func (l *staticChallengeIPList) Add(ip, reason string, duration time.Duration) {
	l.ips[ip] = true
}

func (l *staticChallengeIPList) Contains(ip string) bool {
	return l.ips[ip]
}

func TestAutoBlockIPs_SkipsChallengeListedIPs(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	blocker := &recordingIPBlocker{}
	oldBlocker := fwBlocker
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

func TestAutoBlockIPs_QueuesIPsWhenRateLimited(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	saveBlockState(cfg.StatePath, &blockState{
		BlocksThisHour: maxBlocksPerHour,
		HourKey:        time.Now().Format("2006-01-02T15"),
	})

	blocker := &recordingIPBlocker{}
	oldBlocker := fwBlocker
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

func TestAutoBlockIPs_DrainsPendingQueueAfterRateLimitWindow(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	saveBlockState(cfg.StatePath, &blockState{
		BlocksThisHour: maxBlocksPerHour,
		HourKey:        time.Now().Add(-2 * time.Hour).Format("2006-01-02T15"),
		Pending: []pendingIP{
			{IP: "9.8.7.6", Reason: "queued brute force"},
		},
	})

	blocker := &recordingIPBlocker{}
	oldBlocker := fwBlocker
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

func TestAutoBlock_SMTPBruteForceMessageFormatIsExtractable(t *testing.T) {
	msg := "SMTP brute force from 203.0.113.5: 5 failed auths in 10m0s"
	got := extractIPFromFinding(alert.Finding{Message: msg})
	if got != "203.0.113.5" {
		t.Errorf("extractIPFromFinding(%q) = %q, want 203.0.113.5", msg, got)
	}
}

func TestAutoBlock_SMTPBruteForceIsInAlwaysBlock(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.StatePath = t.TempDir()

	blocker := &recordingIPBlocker{}
	oldBlocker := fwBlocker
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
	oldBlocker := fwBlocker
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

func TestAutoBlock_ExtractCIDRFromFinding(t *testing.T) {
	cases := map[string]string{
		"SMTP password spray from 203.0.113.0/24: 8 unique IPs in 10m0s":  "203.0.113.0/24",
		"SMTP password spray from 198.51.100.0/24: 9 unique IPs in 10m0s": "198.51.100.0/24",
		"wp_login_bruteforce from 1.2.3.4: 10 attempts":                   "",
		"garbage":                                                          "",
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
	prev := fwBlocker
	fwBlocker = fake
	defer func() { fwBlocker = prev }()

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

func TestAutoBlock_SMTPSubnetSprayBypassesPerIPRateLimit(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.StatePath = t.TempDir()

	fake := &recordingIPBlocker{}
	prev := fwBlocker
	fwBlocker = fake
	defer func() { fwBlocker = prev }()

	state := loadBlockState(cfg.StatePath)
	state.HourKey = time.Now().Format("2006-01-02T15")
	state.BlocksThisHour = maxBlocksPerHour
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
