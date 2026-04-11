package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

type recordingIPBlocker struct {
	blocked []string
}

func (b *recordingIPBlocker) BlockIP(ip, reason string, timeout time.Duration) error {
	b.blocked = append(b.blocked, ip)
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
