package checks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

func flushAutoBlockStateForTest(t *testing.T, statePath string) error {
	t.Helper()
	result, err := FlushAutoBlockState(statePath, func() error { return nil })
	if err == nil && !result.Flushed {
		t.Fatal("successful callback was not reported as flushed")
	}
	return err
}

func writeFirewallFlushState(t *testing.T, statePath string, ips ...string) {
	t.Helper()
	dir := filepath.Join(statePath, "firewall")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	entries := make([]string, 0, len(ips))
	for _, ip := range ips {
		entries = append(entries, `{"ip":"`+ip+`"}`)
	}
	data := `{"blocked":[` + strings.Join(entries, ",") + `]}`
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// An operator flush must clear the auto-block bookkeeping too: leftover
// ThreatDB temp rows re-flag every flushed IP through ip_reputation on the
// next scan and re-block it, silently undoing the flush.
func TestFlushAutoBlockStateClearsTrackerAndThreatRows(t *testing.T) {
	withTestThreatStore(t)
	restore := SetGlobalThreatDBForTest(t.TempDir())
	t.Cleanup(restore)

	statePath := t.TempDir()
	writeFirewallFlushState(t, statePath, "203.0.113.20", "203.0.113.23")
	saveBlockState(statePath, &blockState{
		IPs: []blockedIP{
			{IP: "203.0.113.20", Reason: "r", ExpiresAt: time.Now().Add(time.Hour)},
			{IP: "203.0.113.21", Reason: "r", ExpiresAt: time.Now().Add(time.Hour)},
		},
		Pending: []pendingIP{{IP: "203.0.113.22", Reason: "queued", QueuedAt: time.Now()}},
	})
	tdb := GetThreatDB()
	tdb.AddTemporary("203.0.113.20", "r", time.Hour)
	tdb.AddTemporary("203.0.113.23", "engine-only", time.Hour)

	// 203.0.113.23 is in the engine's pre-flush list but not the local
	// tracker; 203.0.113.21 only in the tracker. Both must be cleaned.
	result, err := FlushAutoBlockState(statePath, func() error { return nil })
	if err != nil {
		t.Fatalf("FlushAutoBlockState: %v", err)
	}
	if !result.Flushed || result.SnapshotErr != nil || result.BlockedCount != 2 {
		t.Fatalf("flush result = %+v, want two snapshotted blocks and success", result)
	}

	state := loadBlockState(statePath)
	if len(state.IPs) != 0 {
		t.Errorf("tracker IPs = %+v, want cleared", state.IPs)
	}
	if len(state.Pending) != 1 || state.Pending[0].IP != "203.0.113.22" {
		t.Errorf("pending = %+v, want preserved (queued IPs are not blocks)", state.Pending)
	}
	if _, found := tdb.Lookup("203.0.113.20"); found {
		t.Error("threat row for flushed IP survived; flush would self-revert")
	}
	if _, found := tdb.Lookup("203.0.113.23"); found {
		t.Error("threat row for engine-only flushed IP survived")
	}
	for _, ip := range []string{"203.0.113.20", "203.0.113.23"} {
		if _, found := store.Global().GetPermanentBlock(ip); found {
			t.Errorf("auto-block store row for %s survived", ip)
		}
	}
}

func TestFlushAutoBlockStatePreservesOperatorEvidence(t *testing.T) {
	withTestThreatStore(t)
	restore := SetGlobalThreatDBForTest(t.TempDir())
	t.Cleanup(restore)

	const ip = "203.0.113.24"
	tdb := GetThreatDB()
	tdb.AddTemporary(ip, "automatic", time.Hour)
	tdb.AddPermanent(ip, "operator block")

	statePath := t.TempDir()
	writeFirewallFlushState(t, statePath, ip)
	if err := flushAutoBlockStateForTest(t, statePath); err != nil {
		t.Fatalf("FlushAutoBlockState: %v", err)
	}

	if reason, found := tdb.Lookup(ip); !found || reason != "operator block" {
		t.Fatalf("operator threat evidence = (%q, %v), want preserved", reason, found)
	}
	entry, found := store.Global().GetPermanentBlock(ip)
	if !found || entry.Source != store.ThreatSourceOperator {
		t.Fatalf("operator store row not intact: found=%v entry=%+v", found, entry)
	}
}

func TestFlushAutoBlockStateReportsCorruptTrackerWithoutOverwritingIt(t *testing.T) {
	withTestThreatStore(t)
	restore := SetGlobalThreatDBForTest(t.TempDir())
	t.Cleanup(restore)

	statePath := t.TempDir()
	writeFirewallFlushState(t, statePath, "203.0.113.25")
	trackerPath := filepath.Join(statePath, blockStateFile)
	const corrupt = "{not valid json"
	if err := os.WriteFile(trackerPath, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}

	const ip = "203.0.113.25"
	GetThreatDB().AddTemporary(ip, "engine-only", time.Hour)
	result, err := FlushAutoBlockState(statePath, func() error { return nil })
	if !result.Flushed {
		t.Fatal("firewall callback succeeded but flush was not reported")
	}
	if err == nil || !strings.Contains(err.Error(), "reading auto-block state") {
		t.Fatalf("FlushAutoBlockState error = %v, want corrupt tracker error", err)
	}

	data, readErr := os.ReadFile(trackerPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != corrupt {
		t.Fatalf("corrupt tracker overwritten with %q", data)
	}
	if _, found := GetThreatDB().Lookup(ip); found {
		t.Fatal("engine snapshot threat row survived tracker read failure")
	}
}

func TestFlushAutoBlockStateReportsStoreFailure(t *testing.T) {
	previousStore := store.Global()
	storePath := t.TempDir()
	sdb, err := store.Open(storePath)
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(sdb)
	var reopened *store.DB
	t.Cleanup(func() {
		store.SetGlobal(previousStore)
		if reopened != nil {
			_ = reopened.Close()
		}
	})

	const ip = "203.0.113.27"
	if addErr := sdb.AddTempBlock(ip, "automatic", time.Now().Add(time.Hour)); addErr != nil {
		t.Fatal(addErr)
	}
	if closeErr := sdb.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	statePath := t.TempDir()
	writeFirewallFlushState(t, statePath, ip)
	result, err := FlushAutoBlockState(statePath, func() error { return nil })
	if !result.Flushed {
		t.Fatal("firewall callback succeeded but flush was not reported")
	}
	if err == nil || !strings.Contains(err.Error(), "removing auto-block store row") {
		t.Fatalf("FlushAutoBlockState error = %v, want store failure", err)
	}
	state := loadBlockState(statePath)
	if len(state.CleanupPending) != 1 || state.CleanupPending[0] != ip {
		t.Fatalf("cleanup pending = %v, want %s retained for retry", state.CleanupPending, ip)
	}

	// The real engine has already persisted an empty firewall state. A retry
	// therefore has to recover the IP from CleanupPending, not the engine.
	writeFirewallFlushState(t, statePath)
	reopened, err = store.Open(storePath)
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(reopened)
	if err := flushAutoBlockStateForTest(t, statePath); err != nil {
		t.Fatalf("retrying FlushAutoBlockState: %v", err)
	}
	if _, found := reopened.GetPermanentBlock(ip); found {
		t.Fatal("retried cleanup left the stale auto-block store row")
	}
	if pending := loadBlockState(statePath).CleanupPending; len(pending) != 0 {
		t.Fatalf("cleanup pending after retry = %v, want cleared", pending)
	}
}

func TestFlushAutoBlockStateDoesNotCleanUpAfterFirewallFailure(t *testing.T) {
	statePath := t.TempDir()
	const ip = "203.0.113.28"
	saveBlockState(statePath, &blockState{
		IPs: []blockedIP{{IP: ip, Reason: "old", ExpiresAt: time.Now().Add(time.Hour)}},
	})

	result, err := FlushAutoBlockState(statePath, func() error {
		return errors.New("nft unavailable")
	})
	if err == nil || !strings.Contains(err.Error(), "nft unavailable") {
		t.Fatalf("FlushAutoBlockState error = %v, want firewall error", err)
	}
	if result.Flushed {
		t.Fatal("failed firewall callback reported as flushed")
	}
	if got := loadBlockState(statePath).IPs; len(got) != 1 || got[0].IP != ip {
		t.Fatalf("tracker changed after firewall failure: %+v", got)
	}
}

type flushSignalBlocker struct {
	blocked chan struct{}
}

func (b *flushSignalBlocker) BlockIP(string, string, time.Duration) error {
	select {
	case b.blocked <- struct{}{}:
	default:
	}
	return nil
}

func (*flushSignalBlocker) UnblockIP(string) error { return nil }
func (*flushSignalBlocker) IsBlocked(string) bool  { return false }

// Cleanup must finish deleting old threat evidence before another scan can
// re-block the same IP. Otherwise the cleanup can delete the fresh row written
// by that scan, leaving the new live block without matching evidence.
func TestFlushAutoBlockStateSerializesConcurrentReblock(t *testing.T) {
	previousStore := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(previousStore) })
	restore := SetGlobalThreatDBForTest(t.TempDir())
	t.Cleanup(restore)

	cfg := pendingTestConfig(t)
	const ip = "203.0.113.26"
	saveBlockState(cfg.StatePath, &blockState{
		IPs: []blockedIP{{IP: ip, Reason: "old", ExpiresAt: time.Now().Add(time.Hour)}},
	})
	tdb := GetThreatDB()
	tdb.AddTemporary(ip, "old", time.Hour)

	blocker := &flushSignalBlocker{blocked: make(chan struct{}, 1)}
	swapBlocker(t, blocker)

	flushStarted := make(chan struct{})
	allowFlush := make(chan struct{})
	flushDone := make(chan error, 1)
	go func() {
		_, err := FlushAutoBlockState(cfg.StatePath, func() error {
			close(flushStarted)
			<-allowFlush
			return nil
		})
		flushDone <- err
	}()
	<-flushStarted
	if blockStateMu.TryLock() {
		blockStateMu.Unlock()
		t.Fatal("flush released the auto-block state lock before cleanup")
	}

	autoStarted := make(chan struct{})
	autoDone := make(chan struct{})
	go func() {
		close(autoStarted)
		AutoBlockIPs(cfg, []alert.Finding{{
			Severity: alert.Critical,
			Check:    "wp_login_bruteforce",
			Message:  "WordPress brute force from " + ip,
		}})
		close(autoDone)
	}()
	<-autoStarted
	select {
	case <-blocker.blocked:
		t.Fatal("concurrent auto-block started before flush cleanup completed")
	default:
	}

	close(allowFlush)
	if err := <-flushDone; err != nil {
		t.Fatalf("FlushAutoBlockState: %v", err)
	}
	select {
	case <-autoDone:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent auto-block did not resume after flush")
	}

	if _, found := tdb.Lookup(ip); !found {
		t.Fatal("fresh threat evidence was removed by the completed flush")
	}
	if len(loadBlockState(cfg.StatePath).IPs) != 1 {
		t.Fatal("fresh live block is missing from the tracker")
	}
}
