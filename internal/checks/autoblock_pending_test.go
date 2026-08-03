package checks

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

type failingIPBlocker struct{}

func (b *failingIPBlocker) BlockIP(string, string, time.Duration) error {
	return errors.New("netlink receive: no buffer space available")
}
func (b *failingIPBlocker) UnblockIP(string) error { return nil }
func (b *failingIPBlocker) IsBlocked(string) bool  { return false }

func pendingTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.BlockExpiry = "1h"
	setAutoResponseLive(cfg)
	return cfg
}

// A firewall-down cycle must not discard the queued backlog: the queue is
// the only memory of rate-limited attackers whose findings may never recur.
func TestAutoBlockPendingRequeuedWhenEngineUnavailable(t *testing.T) {
	cfg := pendingTestConfig(t)
	saveBlockState(cfg.StatePath, &blockState{
		Pending: []pendingIP{{IP: "203.0.113.10", Reason: "queued"}},
	})

	oldBlocker := getIPBlocker()
	SetIPBlocker(nil)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	AutoBlockIPs(cfg, nil)

	state := loadBlockState(cfg.StatePath)
	if len(state.Pending) != 1 || state.Pending[0].IP != "203.0.113.10" {
		t.Fatalf("pending = %+v, want the queued IP requeued while engine is down", state.Pending)
	}
	if state.Pending[0].QueuedAt.IsZero() {
		t.Error("requeued entry must carry QueuedAt so it can age out")
	}
}

// Entries older than the max pending age are dropped: blocking hours later
// on stale evidence is worse than not blocking.
func TestAutoBlockPendingStaleEntriesDropped(t *testing.T) {
	cfg := pendingTestConfig(t)
	saveBlockState(cfg.StatePath, &blockState{
		Pending: []pendingIP{
			{IP: "203.0.113.11", Reason: "stale", QueuedAt: time.Now().Add(-3 * time.Hour)},
			{IP: "203.0.113.12", Reason: "fresh", QueuedAt: time.Now().Add(-time.Minute)},
		},
	})

	oldBlocker := getIPBlocker()
	SetIPBlocker(nil)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	AutoBlockIPs(cfg, nil)

	state := loadBlockState(cfg.StatePath)
	if len(state.Pending) != 1 || state.Pending[0].IP != "203.0.113.12" {
		t.Fatalf("pending = %+v, want only the fresh entry", state.Pending)
	}
}

// A rate-limited IP keeps its original QueuedAt across cycles so its age
// accumulates instead of resetting on every requeue.
func TestAutoBlockRateLimitQueuePreservesQueuedAt(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.MaxBlocksPerHour = 1

	queuedAt := time.Now().Add(-30 * time.Minute).Truncate(time.Second)
	saveBlockState(cfg.StatePath, &blockState{
		BlocksThisHour: 1,
		HourKey:        autoBlockNow().Format("2006-01-02T15"),
		Pending:        []pendingIP{{IP: "203.0.113.13", Reason: "queued", QueuedAt: queuedAt}},
	})

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	AutoBlockIPs(cfg, nil)

	if len(blocker.blocked) != 0 {
		t.Fatalf("blocked = %v, want none while rate-limited", blocker.blocked)
	}
	state := loadBlockState(cfg.StatePath)
	if len(state.Pending) != 1 || state.Pending[0].IP != "203.0.113.13" {
		t.Fatalf("pending = %+v, want the rate-limited IP requeued", state.Pending)
	}
	if !state.Pending[0].QueuedAt.Equal(queuedAt) {
		t.Errorf("QueuedAt = %v, want original %v preserved", state.Pending[0].QueuedAt, queuedAt)
	}
}

// Fresh rate-limited findings get a QueuedAt stamp when first queued.
func TestAutoBlockRateLimitQueueStampsNewEntries(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.MaxBlocksPerHour = 1
	saveBlockState(cfg.StatePath, &blockState{
		BlocksThisHour: 1,
		HourKey:        autoBlockNow().Format("2006-01-02T15"),
	})

	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	findings := []alert.Finding{{
		Check:    "wp_login_bruteforce",
		Severity: alert.Critical,
		Message:  "brute force from 203.0.113.14",
		SourceIP: "203.0.113.14",
	}}
	AutoBlockIPs(cfg, findings)

	state := loadBlockState(cfg.StatePath)
	if len(state.Pending) != 1 || state.Pending[0].IP != "203.0.113.14" {
		t.Fatalf("pending = %+v, want the rate-limited finding queued", state.Pending)
	}
	if state.Pending[0].QueuedAt.IsZero() {
		t.Error("new pending entry must be stamped with QueuedAt")
	}
}

// Block errors other than ErrIPProtected requeue the IP: a transient
// netlink failure must not permanently drop a confirmed attacker.
func TestAutoBlockErrorRequeuesPendingIP(t *testing.T) {
	cfg := pendingTestConfig(t)
	saveBlockState(cfg.StatePath, &blockState{
		Pending: []pendingIP{{IP: "203.0.113.15", Reason: "queued"}},
	})

	blocker := &failingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	AutoBlockIPs(cfg, nil)

	state := loadBlockState(cfg.StatePath)
	if len(state.Pending) != 1 || state.Pending[0].IP != "203.0.113.15" {
		t.Fatalf("pending = %+v, want the IP requeued after a block error", state.Pending)
	}
}
