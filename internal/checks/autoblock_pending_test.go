package checks

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
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

	before := blockOutcomeMetricValue(t, "error", BlockSourceScan)
	AutoBlockIPs(cfg, nil)

	state := loadBlockState(cfg.StatePath)
	if len(state.Pending) != 1 || state.Pending[0].IP != "203.0.113.10" {
		t.Fatalf("pending = %+v, want the queued IP requeued while engine is down", state.Pending)
	}
	if state.Pending[0].QueuedAt.IsZero() {
		t.Error("requeued entry must carry QueuedAt so it can age out")
	}
	if got := blockOutcomeMetricValue(t, "error", BlockSourceScan); got != before+1 {
		t.Fatalf("error/scan = %v, want %v", got, before+1)
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

// A queue overflow is an operator-visible loss even when the hourly rate
// limit did not cause it. Engine-down retries can fill the same bounded queue.
func TestAutoBlockPendingOverflowWarnsWhenEngineUnavailable(t *testing.T) {
	cfg := pendingTestConfig(t)
	now := time.Date(2026, 8, 3, 12, 30, 0, 0, time.UTC)
	setAutoBlockNow(t, now)
	pending := make([]pendingIP, 0, maxPendingBlocks+1)
	for i := 0; i <= maxPendingBlocks; i++ {
		pending = append(pending, pendingIP{
			IP:       fmt.Sprintf("2001:db8::%x", i),
			Reason:   "queued",
			QueuedAt: now,
		})
	}
	saveBlockState(cfg.StatePath, &blockState{
		Pending:             pending,
		RateLimitWarnedHour: now.Format("2006-01-02T15"),
	})

	oldBlocker := getIPBlocker()
	SetIPBlocker(nil)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	var actions []alert.Finding
	stderr := captureStderr(t, func() { actions = AutoBlockIPs(cfg, nil) })

	state := loadBlockState(cfg.StatePath)
	if len(state.Pending) != maxPendingBlocks {
		t.Fatalf("pending queue length = %d, want %d", len(state.Pending), maxPendingBlocks)
	}
	if len(actions) != 1 {
		t.Fatalf("actions = %+v, want one queue-overflow warning", actions)
	}
	if !strings.Contains(actions[0].Message, "pending queue full") ||
		!strings.Contains(actions[0].Message, "1 dropped") {
		t.Fatalf("overflow warning = %q, want queue-full message and exact drop count", actions[0].Message)
	}
	if got := strings.Count(stderr, "firewall engine not available"); got != 1 {
		t.Fatalf("engine-unavailable summaries = %d, want 1", got)
	}
	if !strings.Contains(stderr, fmt.Sprintf("requeued %d IPs", maxPendingBlocks)) {
		t.Fatalf("engine-unavailable summary did not report retry count: %q", stderr)
	}
	if state.PendingDropWarnedHour != now.Format("2006-01-02T15") {
		t.Fatalf("PendingDropWarnedHour = %q, want current hour", state.PendingDropWarnedHour)
	}

	var again []alert.Finding
	captureStderr(t, func() {
		again = AutoBlockIPs(cfg, []alert.Finding{{
			Check:    "wp_login_bruteforce",
			SourceIP: "2001:db8:1::1",
			Message:  "new candidate",
		}})
	})
	if len(again) != 0 {
		t.Fatalf("second same-hour overflow actions = %+v, want warning throttled", again)
	}
}

// A failed block whose retry cannot fit in the queue must be reported as
// dropped. Claiming it was requeued contradicts the durable state on disk.
func TestAutoBlockPendingErrorOverflowDoesNotClaimDroppedRetry(t *testing.T) {
	cfg := pendingTestConfig(t)
	now := time.Date(2026, 8, 3, 12, 30, 0, 0, time.UTC)
	setAutoBlockNow(t, now)
	pending := make([]pendingIP, 0, maxPendingBlocks+1)
	for i := 0; i <= maxPendingBlocks; i++ {
		pending = append(pending, pendingIP{
			IP:       fmt.Sprintf("2001:db8::%x", i),
			Reason:   "queued",
			QueuedAt: now,
		})
	}
	saveBlockState(cfg.StatePath, &blockState{Pending: pending})

	oldBlocker := getIPBlocker()
	SetIPBlocker(&failingIPBlocker{})
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	stderr := captureStderr(t, func() { AutoBlockIPs(cfg, nil) })

	if got := strings.Count(stderr, "(requeued)"); got != maxPendingBlocks {
		t.Fatalf("requeued error logs = %d, want %d successful retries", got, maxPendingBlocks)
	}
	if got := strings.Count(stderr, "retry dropped"); got != 1 {
		t.Fatalf("dropped retry logs = %d, want 1", got)
	}
}

// Malformed persisted entries can never succeed. Drop them at the state-file
// boundary instead of retrying the same invalid value until the age cap.
func TestAutoBlockPendingMalformedIPDroppedWithoutRetry(t *testing.T) {
	cfg := pendingTestConfig(t)
	saveBlockState(cfg.StatePath, &blockState{
		Pending: []pendingIP{{IP: "not-an-ip", Reason: "legacy", QueuedAt: time.Now()}},
	})

	oldBlocker := getIPBlocker()
	SetIPBlocker(nil)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	AutoBlockIPs(cfg, nil)

	if state := loadBlockState(cfg.StatePath); len(state.Pending) != 0 {
		t.Fatalf("pending = %+v, want malformed entry dropped", state.Pending)
	}
}

// Old blocked_ips.json files have no queued_at key. They must still load,
// survive one retry, and receive their first timestamp when requeued.
func TestAutoBlockPendingLegacyJSONStampsQueuedAtOnRetry(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.MaxBlocksPerHour = 1
	now := time.Date(2026, 8, 3, 12, 30, 0, 0, time.UTC)
	setAutoBlockNow(t, now)
	legacy := fmt.Sprintf(
		`{"ips":[],"pending":[{"ip":"203.0.113.16","reason":"legacy"}],"blocks_this_hour":1,"hour_key":%q}`,
		now.Format("2006-01-02T15"),
	)
	if err := osFS.WriteFile(filepath.Join(cfg.StatePath, blockStateFile), []byte(legacy), 0o600); err != nil {
		t.Fatalf("write legacy block state: %v", err)
	}

	oldBlocker := getIPBlocker()
	SetIPBlocker(&recordingIPBlocker{})
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	AutoBlockIPs(cfg, nil)

	state := loadBlockState(cfg.StatePath)
	if len(state.Pending) != 1 || state.Pending[0].IP != "203.0.113.16" {
		t.Fatalf("pending = %+v, want legacy entry requeued", state.Pending)
	}
	if !state.Pending[0].QueuedAt.Equal(now) {
		t.Fatalf("QueuedAt = %v, want first retry time %v", state.Pending[0].QueuedAt, now)
	}
}

// A recurring finding can refresh why an IP should be blocked, but it must
// not refresh when the original evidence entered the retry queue.
func TestAutoBlockPendingReasonRefreshPreservesQueuedAt(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.MaxBlocksPerHour = 1
	now := time.Date(2026, 8, 3, 12, 30, 0, 0, time.UTC)
	setAutoBlockNow(t, now)
	queuedAt := now.Add(-30 * time.Minute)
	saveBlockState(cfg.StatePath, &blockState{
		BlocksThisHour: 1,
		HourKey:        now.Format("2006-01-02T15"),
		Pending: []pendingIP{{
			IP:       "203.0.113.17",
			Reason:   "old reason",
			QueuedAt: queuedAt,
		}},
	})

	oldBlocker := getIPBlocker()
	SetIPBlocker(&recordingIPBlocker{})
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	AutoBlockIPs(cfg, []alert.Finding{{
		Check:    "wp_login_bruteforce",
		SourceIP: "203.0.113.17",
		Message:  "refreshed reason",
	}})

	state := loadBlockState(cfg.StatePath)
	if len(state.Pending) != 1 {
		t.Fatalf("pending = %+v, want one refreshed entry", state.Pending)
	}
	if state.Pending[0].Reason != "refreshed reason" {
		t.Errorf("Reason = %q, want refreshed reason", state.Pending[0].Reason)
	}
	if !state.Pending[0].QueuedAt.Equal(queuedAt) {
		t.Errorf("QueuedAt = %v, want original %v", state.Pending[0].QueuedAt, queuedAt)
	}
}
