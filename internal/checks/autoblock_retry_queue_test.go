package checks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/queuehealth"
)

type retryQueueBlocker struct {
	block    func(string) error
	contains func(string) bool
}

func (b retryQueueBlocker) BlockIP(ip, _ string, _ time.Duration) error { return b.block(ip) }
func (retryQueueBlocker) UnblockIP(string) error                        { return nil }
func (b retryQueueBlocker) IsBlocked(ip string) bool {
	if b.contains != nil {
		return b.contains(ip)
	}
	return false
}

func retryQueueRows(t *testing.T, now time.Time) (queuehealth.Status, queuehealth.Status) {
	t.Helper()
	rows := AutoBlockQueueStatuses(now)
	pending, ok := rows["pending"]
	if !ok {
		t.Fatal("durable pending queue missing")
	}
	candidates, ok := rows["candidates"]
	if !ok {
		t.Fatal("accepted candidate queue missing")
	}
	return pending, candidates
}

func retryFinding(ip string) alert.Finding {
	return alert.Finding{Check: "wp_login_bruteforce", SourceIP: ip, Message: "retry queue regression", Severity: alert.Critical}
}

func TestAutoBlockRetryStartupObservationIsReadOnly(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { t.Error("read-only observation called firewall"); return nil })
	now := time.Now().Truncate(time.Second)
	seed := &blockState{Pending: []pendingIP{
		{IP: "192.0.2.70", Reason: "existing", QueuedAt: now.Add(-30 * time.Minute)},
		{IP: "192.0.2.71", Reason: "legacy"},
	}}
	if err := writeBlockState(cfg.StatePath, seed); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.StatePath, blockStateFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = InitAutoBlockQueueHealth(cfg.StatePath); err != nil {
		t.Fatal(err)
	}
	pending, candidates := retryQueueRows(t, now)
	if pending.Depth != 2 || pending.InFlight != 0 || pending.DepthUnavailable || pending.Capacity != maxPendingBlocks || pending.Status != "ok" || pending.LagSeconds != 1800 {
		t.Fatalf("restored queue not measured: %+v", pending)
	}
	if !candidates.CapacityUnavailable || candidates.Depth != 0 || candidates.InFlight != 0 {
		t.Fatalf("invented candidate work: %+v", candidates)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatalf("startup rewrote retry state: %v", err)
	}
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	pending, _ = retryQueueRows(t, now.Add(time.Minute))
	if pending.Depth != 2 || pending.LagSeconds != 1860 {
		t.Fatalf("health consulted filesystem instead of observed work: %+v", pending)
	}
}

// Real membership callbacks inspect health at each admission boundary. In
// particular, a fresh candidate must be visible before the next lookup blocks.
func TestAutoBlockRetryLoadedAndAcceptedWorkStayVisible(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { return nil })
	now := time.Now().Truncate(time.Second)
	if err := writeBlockState(cfg.StatePath, &blockState{
		IPs:     []blockedIP{{IP: "192.0.2.72"}},
		Pending: []pendingIP{{IP: "192.0.2.73", Reason: "pending", QueuedAt: now.Add(-time.Minute)}},
	}); err != nil {
		t.Fatal(err)
	}
	reconciled, firstFresh, secondFresh, calls := false, false, false, 0
	SetIPBlocker(retryQueueBlocker{
		contains: func(ip string) bool {
			pending, candidates := retryQueueRows(t, time.Now())
			switch ip {
			case "192.0.2.72":
				reconciled = true
				if pending.Depth != 1 || pending.InFlight != 0 || candidates.Depth != 0 {
					t.Errorf("loaded work hidden before reconciliation: pending=%+v candidates=%+v", pending, candidates)
				}
			case "192.0.2.74":
				if calls == 0 {
					firstFresh = true
					if pending.InFlight != 1 || candidates.Depth != 1 {
						t.Errorf("drain transfer lost owner: pending=%+v candidates=%+v", pending, candidates)
					}
				}
			case "192.0.2.75":
				if calls == 0 {
					secondFresh = true
					if pending.InFlight != 1 || candidates.Depth != 2 {
						t.Errorf("fresh map admission was delayed: pending=%+v candidates=%+v", pending, candidates)
					}
				}
			}
			return false
		},
		block: func(string) error {
			pending, candidates := retryQueueRows(t, time.Now())
			if candidates.InFlight != 1 || candidates.Depth != 3-calls-1 || pending.InFlight != 1 {
				t.Errorf("attempt ownership changed: calls=%d pending=%+v candidates=%+v", calls, pending, candidates)
			}
			calls++
			return nil
		},
	})
	findings := AutoBlockIPs(cfg, []alert.Finding{retryFinding("192.0.2.74"), retryFinding("192.0.2.75")})
	if !reconciled || !firstFresh || !secondFresh || calls != 3 || len(findings) != 3 {
		t.Fatalf("missing real path: reconcile=%v first=%v second=%v calls=%d findings=%d", reconciled, firstFresh, secondFresh, calls, len(findings))
	}
	pending, candidates := retryQueueRows(t, time.Now())
	if pending.Depth != 0 || pending.InFlight != 0 || pending.DroppedTotal != 0 || candidates.Depth != 0 || candidates.InFlight != 0 || candidates.DroppedTotal != 0 {
		t.Fatalf("completed owners leaked: pending=%+v candidates=%+v", pending, candidates)
	}
	state, err := readBlockState(cfg.StatePath)
	if err != nil || len(state.IPs) != 3 || len(state.Pending) != 0 || state.BlocksThisHour != 3 {
		t.Fatalf("block policy changed: state=%+v err=%v", state, err)
	}
}

func TestAutoBlockRetryQuotaAgeAndExpiry(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { t.Error("quota exhausted but block attempted"); return nil })
	cfg.AutoResponse.MaxBlocksPerHour = 1
	now := time.Date(2026, 9, 10, 12, 30, 0, 0, time.UTC)
	setAutoBlockNow(t, now)
	queued := now.Add(-30 * time.Minute)
	if err := writeBlockState(cfg.StatePath, &blockState{HourKey: now.Format("2006-01-02T15"), BlocksThisHour: 1, Pending: []pendingIP{{IP: "192.0.2.76", Reason: "old", QueuedAt: queued}}}); err != nil {
		t.Fatal(err)
	}
	finding := retryFinding("192.0.2.76")
	finding.Message = "refreshed reason"
	AutoBlockIPs(cfg, []alert.Finding{finding})
	pending, candidates := retryQueueRows(t, now.Add(time.Minute))
	if pending.Depth != 1 || pending.InFlight != 0 || pending.Status != "ok" || pending.LagSeconds != 1860 || pending.DroppedTotal != 0 || candidates.Depth != 0 || candidates.InFlight != 0 {
		t.Fatalf("normal quota wait degraded or age reset: pending=%+v candidates=%+v", pending, candidates)
	}
	state, err := readBlockState(cfg.StatePath)
	if err != nil || len(state.Pending) != 1 || !state.Pending[0].QueuedAt.Equal(queued) || state.Pending[0].Reason != finding.Message {
		t.Fatalf("retry evidence changed: state=%+v err=%v", state, err)
	}
	pending, _ = retryQueueRows(t, queued.Add(maxPendingAge))
	if pending.Status != "ok" {
		t.Fatalf("inclusive expiry invented: %+v", pending)
	}
	pending, _ = retryQueueRows(t, queued.Add(maxPendingAge+time.Second))
	if pending.Status != "degraded" || pending.Reason != "backlog_lag" {
		t.Fatalf("stale retry missing: %+v", pending)
	}
	autoBlockNow = func() time.Time { return queued.Add(maxPendingAge + time.Second) }
	AutoBlockIPs(cfg, nil)
	pending, candidates = retryQueueRows(t, time.Now())
	if pending.Depth != 0 || pending.DroppedTotal != 1 || candidates.DroppedTotal != 0 {
		t.Fatalf("confirmed expiry loss incorrect: pending=%+v candidates=%+v", pending, candidates)
	}
	AutoBlockIPs(cfg, nil)
	pending, _ = retryQueueRows(t, time.Now())
	if pending.DroppedTotal != 1 {
		t.Fatalf("expiry double counted: %+v", pending)
	}
}

func TestAutoBlockRetryFailureSurvivesUntilRecovery(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { return errors.New("synthetic firewall failure") })
	for attempt := range 3 {
		AutoBlockIPs(cfg, []alert.Finding{retryFinding("192.0.2.77")})
		pending, candidates := retryQueueRows(t, time.Now())
		if pending.Depth != 1 || pending.InFlight != 0 || pending.Status != "degraded" || pending.Reason != "retry_failed" || pending.DroppedTotal != 0 || candidates.DroppedTotal != 0 {
			t.Fatalf("attempt %d retained retry counted lost: pending=%+v candidates=%+v", attempt, pending, candidates)
		}
	}
	SetIPBlocker(retryQueueBlocker{block: func(string) error { return nil }})
	actions := AutoBlockIPs(cfg, nil)
	pending, candidates := retryQueueRows(t, time.Now())
	if len(actions) != 1 || pending.Status != "ok" || pending.Depth != 0 || pending.InFlight != 0 || pending.DroppedTotal != 0 || candidates.DroppedTotal != 0 {
		t.Fatalf("successful retry did not recover: actions=%d pending=%+v candidates=%+v", len(actions), pending, candidates)
	}
}

func TestAutoBlockRetryOverflowCountsConfirmedLoss(t *testing.T) {
	for _, restored := range []bool{false, true} {
		t.Run(fmt.Sprintf("restored=%v", restored), func(t *testing.T) {
			cfg := autoBlockQueueFixture(t, func() error { return nil })
			SetIPBlocker(nil)
			now := time.Now().Truncate(time.Second)
			state := &blockState{}
			findings := make([]alert.Finding, 0, maxPendingBlocks+1)
			for i := 0; i <= maxPendingBlocks; i++ {
				ip := fmt.Sprintf("2001:db8::%x", i)
				if restored {
					state.Pending = append(state.Pending, pendingIP{IP: ip, Reason: "restored", QueuedAt: now})
				} else {
					findings = append(findings, retryFinding(ip))
				}
			}
			if err := writeBlockState(cfg.StatePath, state); err != nil {
				t.Fatal(err)
			}
			captureStderr(t, func() { AutoBlockIPs(cfg, findings) })
			pending, candidates := retryQueueRows(t, time.Now())
			pendingLoss, candidateLoss := uint64(0), uint64(1)
			if restored {
				pendingLoss, candidateLoss = 1, 0
			}
			if pending.Depth != maxPendingBlocks || pending.InFlight != 0 || pending.DroppedTotal != pendingLoss || candidates.DroppedTotal != candidateLoss || candidates.Depth != 0 || candidates.InFlight != 0 {
				t.Fatalf("overflow accounting wrong: pending=%+v candidates=%+v", pending, candidates)
			}
			state, err := readBlockState(cfg.StatePath)
			if err != nil || len(state.Pending) != maxPendingBlocks {
				t.Fatalf("persisted retry bound changed: state count=%d err=%v", len(state.Pending), err)
			}
		})
	}
}

func failRetryWrite(t *testing.T, statePath string) func() {
	t.Helper()
	path := filepath.Join(statePath, blockStateFile+".tmp")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "held"), []byte("synthetic write-failure fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Rename(path, path+".saved"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAutoBlockRetryFailedWriteKeepsOldAndLosesFresh(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { return nil })
	SetIPBlocker(nil)
	now := time.Now().Truncate(time.Second)
	if err := writeBlockState(cfg.StatePath, &blockState{Pending: []pendingIP{{IP: "192.0.2.78", Reason: "stale", QueuedAt: now.Add(-3 * time.Hour)}}}); err != nil {
		t.Fatal(err)
	}
	restoreWrite := failRetryWrite(t, cfg.StatePath)
	captureStderr(t, func() { AutoBlockIPs(cfg, []alert.Finding{retryFinding("192.0.2.79")}) })
	pending, candidates := retryQueueRows(t, time.Now())
	if pending.Depth != 1 || pending.DepthUnavailable || pending.DroppedTotal != 0 || pending.Reason != "state_io" || candidates.DroppedTotal != 1 {
		t.Fatalf("readable rollback miscounted: pending=%+v candidates=%+v", pending, candidates)
	}
	captureStderr(t, func() { AutoBlockIPs(cfg, nil) })
	pending, candidates = retryQueueRows(t, time.Now())
	if pending.Depth != 1 || pending.DroppedTotal != 0 || candidates.DroppedTotal != 1 {
		t.Fatalf("failed deletion counted twice: pending=%+v candidates=%+v", pending, candidates)
	}
	restoreWrite()
	captureStderr(t, func() { AutoBlockIPs(cfg, nil) })
	pending, candidates = retryQueueRows(t, time.Now())
	if pending.Depth != 0 || pending.InFlight != 0 || pending.DroppedTotal != 1 || candidates.DroppedTotal != 1 || pending.Reason == "state_io" {
		t.Fatalf("confirmed deletion not settled: pending=%+v candidates=%+v", pending, candidates)
	}
}

func TestAutoBlockRetryAcknowledgedBlockCannotBecomeLoss(t *testing.T) {
	calls := 0
	cfg := autoBlockQueueFixture(t, func() error { calls++; return nil })
	now := time.Now().Truncate(time.Second)
	setAutoBlockNow(t, now)
	queued := now.Add(-time.Minute)
	if err := writeBlockState(cfg.StatePath, &blockState{Pending: []pendingIP{{IP: "192.0.2.80", Reason: "retry", QueuedAt: queued}}}); err != nil {
		t.Fatal(err)
	}
	restoreWrite := failRetryWrite(t, cfg.StatePath)
	captureStderr(t, func() { AutoBlockIPs(cfg, nil) })
	pending, candidates := retryQueueRows(t, time.Now())
	if calls != 1 || pending.Depth != 1 || pending.DroppedTotal != 0 || candidates.DroppedTotal != 0 {
		t.Fatalf("completed attempt not retained through failed deletion: calls=%d pending=%+v candidates=%+v", calls, pending, candidates)
	}
	restoreWrite()
	autoBlockNow = func() time.Time { return queued.Add(maxPendingAge + time.Second) }
	AutoBlockIPs(cfg, nil)
	pending, candidates = retryQueueRows(t, time.Now())
	if calls != 1 || pending.Depth != 0 || pending.DroppedTotal != 0 || candidates.DroppedTotal != 0 {
		t.Fatalf("prior successful block became expiry loss: calls=%d pending=%+v candidates=%+v", calls, pending, candidates)
	}
}

func TestAutoBlockRetryLegacyStampUsesActualQueueTime(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { return nil })
	cfg.AutoResponse.MaxBlocksPerHour = 1
	now := time.Date(2026, 9, 10, 12, 30, 0, 0, time.UTC)
	setAutoBlockNow(t, now)
	if err := writeBlockState(cfg.StatePath, &blockState{HourKey: now.Format("2006-01-02T15"), BlocksThisHour: 1, Pending: []pendingIP{{IP: "192.0.2.81", Reason: "legacy"}}}); err != nil {
		t.Fatal(err)
	}
	AutoBlockIPs(cfg, nil)
	pending, _ := retryQueueRows(t, now.Add(10*time.Second))
	if pending.Depth != 1 || pending.LagSeconds != 10 {
		t.Fatalf("legacy record did not adopt actual first queue timestamp: %+v", pending)
	}
	state, err := readBlockState(cfg.StatePath)
	if err != nil || len(state.Pending) != 1 || !state.Pending[0].QueuedAt.Equal(now) {
		t.Fatalf("legacy wire timestamp changed: state=%+v err=%v", state, err)
	}
}

func TestAutoBlockRetryPostRenameErrorUsesActualRecords(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { return nil })
	SetIPBlocker(nil)
	now := time.Now().Truncate(time.Second)
	if err := writeBlockState(cfg.StatePath, &blockState{Pending: []pendingIP{{IP: "192.0.2.82", Reason: "stale", QueuedAt: now.Add(-3 * time.Hour)}}}); err != nil {
		t.Fatal(err)
	}
	previous := persistAutoBlockState
	defer func() { persistAutoBlockState = previous }()
	persistAutoBlockState = func(path string, state *blockState) error {
		if err := writeBlockState(path, state); err != nil {
			return err
		}
		return errors.New("synthetic directory-sync failure after real rename")
	}
	captureStderr(t, func() { AutoBlockIPs(cfg, []alert.Finding{retryFinding("192.0.2.83")}) })
	pending, candidates := retryQueueRows(t, time.Now())
	if pending.Depth != 1 || pending.DepthUnavailable || pending.DroppedLowerBound || pending.DroppedTotal != 1 || pending.Reason != "state_io" || candidates.DroppedTotal != 0 {
		t.Fatalf("post-rename error assumed rollback: pending=%+v candidates=%+v", pending, candidates)
	}
	state, err := readBlockState(cfg.StatePath)
	if err != nil || len(state.Pending) != 1 || state.Pending[0].IP != "192.0.2.83" {
		t.Fatalf("post-rename fixture failed: state=%+v err=%v", state, err)
	}
}

type retryQueueReadFailure struct {
	OS
	path  string
	calls int
	fail  bool
}

func (f *retryQueueReadFailure) ReadFile(path string) ([]byte, error) {
	if path == f.path {
		f.calls++
		if f.fail && f.calls > 1 {
			return nil, os.ErrPermission
		}
	}
	return f.OS.ReadFile(path)
}

func TestAutoBlockRetryUnknownWriteNeverInventsLoss(t *testing.T) {
	calls := 0
	cfg := autoBlockQueueFixture(t, func() error { calls++; return nil })
	now := time.Now().Truncate(time.Second)
	setAutoBlockNow(t, now)
	queued := now.Add(-time.Minute)
	if err := writeBlockState(cfg.StatePath, &blockState{Pending: []pendingIP{{IP: "192.0.2.84", Reason: "known retry", QueuedAt: queued}}}); err != nil {
		t.Fatal(err)
	}
	restoreWrite := failRetryWrite(t, cfg.StatePath)
	previousOS := osFS
	fixture := &retryQueueReadFailure{OS: realOS{}, path: filepath.Join(cfg.StatePath, blockStateFile), fail: true}
	osFS = fixture
	defer func() { osFS = previousOS }()
	captureStderr(t, func() { AutoBlockIPs(cfg, nil) })
	pending, candidates := retryQueueRows(t, time.Now())
	if calls != 1 || !pending.DepthUnavailable || !pending.DroppedLowerBound || pending.DroppedTotal != 0 || pending.Reason != "state_io" || candidates.DroppedTotal != 0 {
		t.Fatalf("unreadable outcome claimed exact state: calls=%d pending=%+v candidates=%+v", calls, pending, candidates)
	}
	fixture.fail = false
	restoreWrite()
	autoBlockNow = func() time.Time { return queued.Add(maxPendingAge + time.Second) }
	AutoBlockIPs(cfg, nil)
	pending, candidates = retryQueueRows(t, time.Now())
	if calls != 1 || pending.DepthUnavailable || pending.Depth != 0 || pending.DroppedTotal != 0 || !pending.DroppedLowerBound || candidates.DroppedTotal != 0 {
		t.Fatalf("unknown prior success became false expiry loss: pending=%+v candidates=%+v", pending, candidates)
	}
	// Later fresh work has an exact outcome even though earlier losses remain
	// a lower bound. A readable failed write must still count its known loss.
	SetIPBlocker(nil)
	_ = failRetryWrite(t, cfg.StatePath)
	captureStderr(t, func() { AutoBlockIPs(cfg, []alert.Finding{retryFinding("192.0.2.85")}) })
	pending, candidates = retryQueueRows(t, time.Now())
	if pending.DepthUnavailable || pending.Depth != 0 || pending.DroppedTotal != 0 || candidates.DroppedTotal != 1 {
		t.Fatalf("uncertainty hid later proved fresh loss: pending=%+v candidates=%+v", pending, candidates)
	}
}

func TestAutoBlockRetryDuplicateRecordsCoalesceWithoutLoss(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { return nil })
	cfg.AutoResponse.MaxBlocksPerHour = 1
	now := time.Now().Truncate(time.Second)
	state := &blockState{HourKey: autoBlockNow().Format("2006-01-02T15"), BlocksThisHour: 1, Pending: []pendingIP{
		{IP: "192.0.2.86", Reason: "first", QueuedAt: now.Add(-time.Minute)},
		{IP: "192.0.2.86", Reason: "last", QueuedAt: now.Add(-30 * time.Second)},
	}}
	if err := writeBlockState(cfg.StatePath, state); err != nil {
		t.Fatal(err)
	}
	AutoBlockIPs(cfg, nil)
	pending, candidates := retryQueueRows(t, time.Now())
	if pending.Depth != 1 || pending.DroppedTotal != 0 || candidates.DroppedTotal != 0 {
		t.Fatalf("existing coalescence treated as loss: pending=%+v candidates=%+v", pending, candidates)
	}
	state, err := readBlockState(cfg.StatePath)
	if err != nil || len(state.Pending) != 1 || state.Pending[0].Reason != "last" || !state.Pending[0].QueuedAt.Equal(now.Add(-30*time.Second)) {
		t.Fatalf("duplicate policy changed: state=%+v err=%v", state, err)
	}
	autoBlockQueues.mu.Lock()
	defer autoBlockQueues.mu.Unlock()
	if len(autoBlockQueues.retries.records) != 1 || len(autoBlockQueues.retries.disk) != 1 || len(autoBlockQueues.retries.candidates) != 0 {
		t.Errorf("settled queue retained retired owners")
	}
	if autoBlockQueues.retries.disk[0].queueCandidate != nil {
		t.Errorf("durable snapshot retained completed candidate and duplicate history")
	}
}

type retryOutcomeBlocker struct {
	retryQueueBlocker
	outcome firewall.BlockOutcome
	err     error
}

func (b retryOutcomeBlocker) BlockIPOutcome(string, string, time.Duration) (firewall.BlockOutcome, error) {
	return b.outcome, b.err
}

func TestAutoBlockRetryExpectedOutcomesAreNotLosses(t *testing.T) {
	for _, outcome := range []firewall.BlockOutcome{firewall.BlockOutcomeDryRun, firewall.BlockOutcomeAllowed, firewall.BlockOutcomeAllowlisted, firewall.BlockOutcomeNoop} {
		t.Run(string(outcome), func(t *testing.T) {
			cfg := autoBlockQueueFixture(t, func() error { return nil })
			if err := writeBlockState(cfg.StatePath, &blockState{Pending: []pendingIP{{IP: "192.0.2.92", Reason: "retry", QueuedAt: time.Now()}}}); err != nil {
				t.Fatal(err)
			}
			SetIPBlocker(retryOutcomeBlocker{outcome: outcome})
			AutoBlockIPs(cfg, []alert.Finding{retryFinding("192.0.2.93")})
			pending, candidates := retryQueueRows(t, time.Now())
			if pending.Depth != 0 || pending.InFlight != 0 || pending.DroppedTotal != 0 || candidates.Depth != 0 || candidates.InFlight != 0 || candidates.DroppedTotal != 0 {
				t.Fatalf("expected outcome counted lost: pending=%+v candidates=%+v", pending, candidates)
			}
		})
	}
	t.Run("protected", func(t *testing.T) {
		cfg := autoBlockQueueFixture(t, func() error { return firewall.ErrIPProtected })
		if err := writeBlockState(cfg.StatePath, &blockState{Pending: []pendingIP{{IP: "192.0.2.94", Reason: "retry", QueuedAt: time.Now()}}}); err != nil {
			t.Fatal(err)
		}
		AutoBlockIPs(cfg, []alert.Finding{retryFinding("192.0.2.95")})
		pending, candidates := retryQueueRows(t, time.Now())
		if pending.Depth != 0 || pending.DroppedTotal != 0 || candidates.DroppedTotal != 0 || pending.Status != "ok" {
			t.Fatalf("protected refusal counted lost: pending=%+v candidates=%+v", pending, candidates)
		}
	})
}

func TestAutoBlockRetryConfirmedDropsDegradeAndRecover(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { t.Error("invalid retry reached firewall"); return nil })
	if err := writeBlockState(cfg.StatePath, &blockState{Pending: []pendingIP{{IP: "invalid-one"}, {IP: "invalid-two"}, {IP: "invalid-three"}}}); err != nil {
		t.Fatal(err)
	}
	captureStderr(t, func() { AutoBlockIPs(cfg, nil) })
	pending, candidates := retryQueueRows(t, time.Now())
	if pending.Depth != 0 || pending.DroppedTotal != 3 || pending.RecentDrops != 3 || pending.Status != "degraded" || pending.Reason != "dropped_work" || candidates.DroppedTotal != 0 {
		t.Fatalf("confirmed loss threshold missing: pending=%+v candidates=%+v", pending, candidates)
	}
	pending, _ = retryQueueRows(t, time.Now().Add(2*time.Minute))
	if pending.Status != "ok" || pending.DroppedTotal != 3 || pending.RecentDrops != 0 {
		t.Fatalf("loss recovery erased evidence: %+v", pending)
	}
}

func TestAutoBlockRetryUnreadableStateReportsUnknownDepth(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { return nil })
	path := filepath.Join(cfg.StatePath, blockStateFile)
	if err := os.WriteFile(path, []byte("{invalid state"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := InitAutoBlockQueueHealth(cfg.StatePath); err == nil {
		t.Fatal("corrupt state was accepted")
	}
	pending, _ := retryQueueRows(t, time.Now())
	if !pending.DepthUnavailable || pending.Status != "degraded" || pending.Reason != "state_io" || !pending.DroppedLowerBound {
		t.Fatalf("corrupt state presented as empty: %+v", pending)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "{invalid state" {
		t.Fatalf("failed read rewrote state: %v", err)
	}
	if err := writeBlockState(cfg.StatePath, &blockState{Pending: []pendingIP{{IP: "192.0.2.96", Reason: "restored", QueuedAt: time.Now()}}}); err != nil {
		t.Fatal(err)
	}
	if err := InitAutoBlockQueueHealth(cfg.StatePath); err != nil {
		t.Fatal(err)
	}
	pending, _ = retryQueueRows(t, time.Now())
	if pending.DepthUnavailable || pending.Depth != 1 || pending.Status != "ok" || pending.DroppedTotal != 0 || !pending.DroppedLowerBound {
		t.Fatalf("read recovery concealed work or uncertainty: %+v", pending)
	}
}

func TestAutoBlockRetryLongBatchKeepsOperationProgress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		cfg := autoBlockQueueFixture(t, func() error { calls++; time.Sleep(30 * time.Second); return nil })
		seed := &blockState{}
		for i := 0; i < 5; i++ {
			seed.Pending = append(seed.Pending, pendingIP{IP: fmt.Sprintf("192.0.2.%d", 100+i), Reason: "queued", QueuedAt: time.Now().Add(-time.Minute)})
		}
		if err := writeBlockState(cfg.StatePath, seed); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { defer close(done); AutoBlockIPs(cfg, nil) }()
		defer func() { <-done }()
		time.Sleep(65 * time.Second)
		pending, candidates := retryQueueRows(t, time.Now())
		if pending.InFlight != 5 || pending.ProcessingSeconds != 5 || pending.Status != "ok" || candidates.Depth != 2 || candidates.InFlight != 1 || candidates.ProcessingSeconds != 5 || candidates.Status != "ok" {
			t.Fatalf("advancing retry batch falsely degraded: pending=%+v candidates=%+v", pending, candidates)
		}
		<-done
		pending, candidates = retryQueueRows(t, time.Now())
		if calls != 5 || pending.Depth != 0 || pending.InFlight != 0 || pending.DroppedTotal != 0 || candidates.DroppedTotal != 0 {
			t.Fatalf("batch did not drain: calls=%d pending=%+v candidates=%+v", calls, pending, candidates)
		}
	})
}
