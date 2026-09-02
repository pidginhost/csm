package rollback

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/integrity"
	"github.com/pidginhost/csm/internal/store"
)

func newTestManager(t *testing.T) (*Manager, *store.DB, string, *atomic.Int32) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "csm.yaml")
	if err := os.WriteFile(cfgPath, []byte("hostname: original\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var restartCount atomic.Int32
	restart := func(_ context.Context) error {
		restartCount.Add(1)
		return nil
	}
	m := NewManager(db, cfgPath, restart, time.Now)
	t.Cleanup(func() {
		_ = m.Confirm()
		_ = db.Close()
	})
	return m, db, cfgPath, &restartCount
}

func TestApplyPersistsAndStatusReports(t *testing.T) {
	m, db, _, _ := newTestManager(t)

	prev := []byte("hostname: prev\n")
	next := []byte("hostname: next\n")
	st, err := m.Apply(prev, next, 5*time.Minute, "tok-test")
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !st.Pending {
		t.Fatal("status should be pending after Apply")
	}
	if st.AppliedBy != "tok-test" {
		t.Errorf("AppliedBy = %q, want %q", st.AppliedBy, "tok-test")
	}
	if st.SecondsRemaining < 200 || st.SecondsRemaining > 320 {
		t.Errorf("SecondsRemaining = %d, want around 300", st.SecondsRemaining)
	}

	rec, ok := db.GetFirewallRollback()
	if !ok {
		t.Fatal("expected record persisted")
	}
	if !bytes.Equal(rec.PrevYAML, prev) {
		t.Errorf("PrevYAML drift: got %q want %q", rec.PrevYAML, prev)
	}
}

func TestApplyRefusesWhenAlreadyPending(t *testing.T) {
	m, _, _, _ := newTestManager(t)
	if _, err := m.Apply([]byte("a"), []byte("b"), time.Minute, "first"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply([]byte("c"), []byte("d"), time.Minute, "second"); err == nil {
		t.Error("second Apply should fail while first is pending")
	}
}

func TestApplyClampsTimeoutOutOfRange(t *testing.T) {
	m, _, _, _ := newTestManager(t)
	st, err := m.Apply([]byte("p"), []byte("n"), 10*time.Second, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if st.SecondsRemaining < int64(MinTimeout.Seconds())-5 {
		t.Errorf("expected clamp to MinTimeout, got %d seconds", st.SecondsRemaining)
	}
	_ = m.Confirm()

	st, err = m.Apply([]byte("p"), []byte("n"), 24*time.Hour, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if st.SecondsRemaining > int64(MaxTimeout.Seconds())+5 {
		t.Errorf("expected clamp to MaxTimeout, got %d seconds", st.SecondsRemaining)
	}
}

func TestConfirmDropsPending(t *testing.T) {
	m, db, _, restartCount := newTestManager(t)
	if _, err := m.Apply([]byte("p"), []byte("n"), time.Minute, "tok"); err != nil {
		t.Fatal(err)
	}
	if err := m.Confirm(); err != nil {
		t.Fatal(err)
	}
	if _, ok := db.GetFirewallRollback(); ok {
		t.Error("Confirm should clear bbolt record")
	}
	if restartCount.Load() != 0 {
		t.Errorf("Confirm must not restart, got %d", restartCount.Load())
	}
	// Idempotent.
	if err := m.Confirm(); err != nil {
		t.Errorf("Confirm on empty should be no-op, got %v", err)
	}
}

func TestRevertRestoresPreviousAndRestarts(t *testing.T) {
	m, db, cfgPath, restartCount := newTestManager(t)
	prev := []byte("hostname: prev\n")
	next := []byte("hostname: next\n")
	if _, err := m.Apply(prev, next, time.Minute, "tok"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, next, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := m.Revert(context.Background()); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, prev) {
		t.Errorf("config not restored: got %q want %q", got, prev)
	}
	if _, ok := db.GetFirewallRollback(); ok {
		t.Error("Revert should clear bbolt record")
	}
	if restartCount.Load() != 1 {
		t.Errorf("Revert should trigger restart once, got %d", restartCount.Load())
	}
}

// The pending record must be gone BEFORE the restart fires: systemctl
// restart kills this very process, so anything sequenced after it never
// runs. A record that survives a successful restart makes the next boot
// revert and restart again, forever.
func TestRevertClearsRecordBeforeRestart(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "csm.yaml")
	if werr := os.WriteFile(cfgPath, []byte("hostname: next\n"), 0o600); werr != nil {
		t.Fatal(werr)
	}

	var recordPresentAtRestart atomic.Bool
	var restartCount atomic.Int32
	var m *Manager
	restart := func(_ context.Context) error {
		restartCount.Add(1)
		_, ok := db.GetFirewallRollback()
		recordPresentAtRestart.Store(ok)
		return nil
	}
	m = NewManager(db, cfgPath, restart, time.Now)
	t.Cleanup(func() {
		_ = m.Confirm()
		_ = db.Close()
	})

	if _, aerr := m.Apply([]byte("hostname: prev\n"), []byte("hostname: next\n"), time.Minute, "tok"); aerr != nil {
		t.Fatal(aerr)
	}
	if rerr := m.Revert(context.Background()); rerr != nil {
		t.Fatalf("Revert: %v", rerr)
	}
	if recordPresentAtRestart.Load() {
		t.Error("rollback record still present when restart fired; a killed process never clears it and the next boot loops")
	}
	if got := restartCount.Load(); got != 1 {
		t.Errorf("restart called %d times, want 1", got)
	}
}

func TestRevertNoPendingErrors(t *testing.T) {
	m, _, _, _ := newTestManager(t)
	if err := m.Revert(context.Background()); err == nil {
		t.Error("Revert with no pending should error")
	}
}

func TestRecoverOnStartupExpiredReverts(t *testing.T) {
	m, db, cfgPath, restartCount := newTestManager(t)

	// Inject an already-expired rollback (simulates daemon down past
	// the deadline during the apply window).
	past := time.Now().Add(-1 * time.Minute).UTC()
	prev := []byte("hostname: prev\n")
	if err := db.SaveFirewallRollback(store.FirewallRollback{
		PrevYAML:  prev,
		AppliedAt: past.Add(-5 * time.Minute),
		ExpiresAt: past,
		AppliedBy: "tok",
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("hostname: next\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	reverted, err := m.RecoverOnStartup(context.Background())
	if err != nil {
		t.Fatalf("RecoverOnStartup: %v", err)
	}
	if !reverted {
		t.Error("expired rollback should produce reverted=true")
	}
	got, _ := os.ReadFile(cfgPath)
	if !bytes.Equal(got, prev) {
		t.Errorf("config not restored on startup: got %q want %q", got, prev)
	}
	if restartCount.Load() != 1 {
		t.Errorf("recovery revert should restart once, got %d", restartCount.Load())
	}
}

// Recovery drops the manager lock while it waits for the process-wide config
// writer lock. An operator may confirm the old rollback and start a new one in
// that interval; recovery must re-check the replacement deadline instead of
// immediately restoring its snapshot.
func TestRecoverOnStartupDoesNotRevertReplacementRollback(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfgPath := filepath.Join(dir, "csm.yaml")
	if err := os.WriteFile(cfgPath, []byte("hostname: current\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	observedExpired := make(chan struct{})
	var nowCalls atomic.Int32
	m := NewManager(db, cfgPath, nil, func() time.Time {
		if nowCalls.Add(1) == 1 {
			close(observedExpired)
		}
		return now
	})
	t.Cleanup(func() { _ = m.Confirm() })
	if err := db.SaveFirewallRollback(store.FirewallRollback{
		PrevYAML:  []byte("hostname: expired\n"),
		ExpiresAt: now.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	configMu := integrity.ConfigWriteMutex()
	configMu.Lock()
	done := make(chan struct {
		reverted bool
		err      error
	}, 1)
	go func() {
		reverted, recoverErr := m.RecoverOnStartup(context.Background())
		done <- struct {
			reverted bool
			err      error
		}{reverted, recoverErr}
	}()

	<-observedExpired
	deadline := time.Now().Add(5 * time.Second)
	for {
		if m.mu.TryLock() {
			m.mu.Unlock()
			break
		}
		if time.Now().After(deadline) {
			configMu.Unlock()
			t.Fatal("recovery did not release the manager lock before waiting for the config lock")
		}
		time.Sleep(time.Millisecond)
	}
	if err := m.AbortApplyIfCurrent(m.Status()); err != nil {
		configMu.Unlock()
		t.Fatal(err)
	}
	if _, err := m.Apply([]byte("hostname: replacement\n"), []byte("hostname: current\n"), time.Minute, "replacement"); err != nil {
		configMu.Unlock()
		t.Fatal(err)
	}
	configMu.Unlock()

	var result struct {
		reverted bool
		err      error
	}
	select {
	case result = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("recovery did not finish after the config writer lock was released")
	}
	if result.err != nil || result.reverted {
		t.Fatalf("recovery of replacement rollback = (%v, %v), want no revert", result.reverted, result.err)
	}
	if got, err := os.ReadFile(cfgPath); err != nil || string(got) != "hostname: current\n" {
		t.Fatalf("replacement rollback was applied early: data=%q err=%v", got, err)
	}
	if status := m.Status(); !status.Pending || !status.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("replacement rollback status = %+v, want pending future deadline", status)
	}
}

func TestStaleTimerDoesNotRevertFutureRollback(t *testing.T) {
	m, _, cfgPath, restartCount := newTestManager(t)
	if _, err := m.Apply([]byte("hostname: replacement\n"), []byte("hostname: current\n"), time.Minute, "replacement"); err != nil {
		t.Fatal(err)
	}
	if err := m.timerExpired(context.Background()); err != nil {
		t.Fatal(err)
	}
	if status := m.Status(); !status.Pending {
		t.Fatal("a stale timer cleared the future rollback")
	}
	if got, err := os.ReadFile(cfgPath); err != nil || string(got) != "hostname: original\n" {
		t.Fatalf("a stale timer restored the future rollback early: data=%q err=%v", got, err)
	}
	if got := restartCount.Load(); got != 0 {
		t.Fatalf("a stale timer restarted the daemon %d time(s)", got)
	}
}

func TestBlockedRevertDoesNotApplyReplacementRollback(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfgPath := filepath.Join(dir, "csm.yaml")
	if err := os.WriteFile(cfgPath, []byte("hostname: current\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	if err := db.SaveFirewallRollback(store.FirewallRollback{
		PrevYAML:  []byte("hostname: old\n"),
		AppliedAt: now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Minute),
		AppliedBy: "old",
	}); err != nil {
		t.Fatal(err)
	}
	observed := make(chan struct{})
	var observedOnce sync.Once
	m := NewManager(db, cfgPath, nil, func() time.Time {
		observedOnce.Do(func() { close(observed) })
		return now
	})
	t.Cleanup(func() { _ = m.Confirm() })

	configMu := integrity.ConfigWriteMutex()
	configMu.Lock()
	done := make(chan error, 1)
	go func() { done <- m.Revert(context.Background()) }()
	select {
	case <-observed:
	case <-time.After(5 * time.Second):
		configMu.Unlock()
		t.Fatal("revert did not capture the pending rollback before waiting for the config lock")
	}
	if err := m.AbortApplyIfCurrent(m.Status()); err != nil {
		configMu.Unlock()
		t.Fatal(err)
	}
	if _, err := m.Apply([]byte("hostname: replacement\n"), []byte("hostname: current\n"), time.Minute, "replacement"); err != nil {
		configMu.Unlock()
		t.Fatal(err)
	}
	configMu.Unlock()

	if err := <-done; err == nil || !strings.Contains(err.Error(), "changed before revert") {
		t.Fatalf("blocked stale revert error = %v, want replacement rejection", err)
	}
	if got, err := os.ReadFile(cfgPath); err != nil || string(got) != "hostname: current\n" {
		t.Fatalf("stale revert overwrote current config: data=%q err=%v", got, err)
	}
	if status := m.Status(); !status.Pending || status.AppliedBy != "replacement" {
		t.Fatalf("replacement rollback was cleared: %+v", status)
	}
}

func TestStaleConfirmDoesNotClearReplacementRollback(t *testing.T) {
	m, _, _, _ := newTestManager(t)
	if _, err := m.Apply([]byte("hostname: old\n"), []byte("hostname: current\n"), time.Minute, "old"); err != nil {
		t.Fatal(err)
	}
	stale := m.Status()
	if err := m.ConfirmIfCurrent(stale); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply([]byte("hostname: replacement\n"), []byte("hostname: current\n"), time.Minute, "replacement"); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfirmIfCurrent(stale); err == nil || !strings.Contains(err.Error(), "changed before confirm") {
		t.Fatalf("stale confirm error = %v, want replacement rejection", err)
	}
	if status := m.Status(); !status.Pending || status.AppliedBy != "replacement" {
		t.Fatalf("stale confirm cleared replacement rollback: %+v", status)
	}
}

func TestConfirmSharesConfigWriterLock(t *testing.T) {
	m, _, _, _ := newTestManager(t)
	if _, err := m.Apply([]byte("hostname: old\n"), []byte("hostname: current\n"), time.Minute, "old"); err != nil {
		t.Fatal(err)
	}

	configMu := integrity.ConfigWriteMutex()
	configMu.Lock()
	done := make(chan error, 1)
	go func() { done <- m.Confirm() }()
	select {
	case err := <-done:
		configMu.Unlock()
		t.Fatalf("confirm bypassed the shared config writer lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	configMu.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("confirm did not proceed after the config writer lock was released")
	}
}

func TestRecoverOnStartupWithinWindowRearms(t *testing.T) {
	m, db, _, _ := newTestManager(t)

	now := time.Now().UTC()
	if err := db.SaveFirewallRollback(store.FirewallRollback{
		PrevYAML:  []byte("hostname: prev\n"),
		AppliedAt: now,
		ExpiresAt: now.Add(10 * time.Minute),
		AppliedBy: "tok",
	}); err != nil {
		t.Fatal(err)
	}

	reverted, err := m.RecoverOnStartup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if reverted {
		t.Error("future-deadline rollback should not auto-revert on startup")
	}
	st := m.Status()
	if !st.Pending {
		t.Error("status should still report pending after rearm")
	}
	if st.SecondsRemaining < 500 || st.SecondsRemaining > 700 {
		t.Errorf("SecondsRemaining = %d, want around 600", st.SecondsRemaining)
	}
}

func TestRevertRestartFailureSurfaces(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "csm.yaml")
	if werr := os.WriteFile(cfgPath, []byte("x"), 0o600); werr != nil {
		t.Fatal(werr)
	}

	failingRestart := func(_ context.Context) error { return errors.New("systemctl unavailable") }
	m := NewManager(db, cfgPath, failingRestart, time.Now)
	t.Cleanup(func() {
		_ = m.Confirm()
		_ = db.Close()
	})

	prev := []byte("hostname: prev\n")
	if _, aerr := m.Apply(prev, []byte("hostname: next\n"), time.Minute, "tok"); aerr != nil {
		t.Fatal(aerr)
	}
	if rerr := m.Revert(context.Background()); rerr == nil {
		t.Error("Revert should bubble up restart failure")
	}
	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, prev) {
		t.Errorf("config not restored before restart failure: got %q want %q", got, prev)
	}
	// The record is cleared even on restart failure: the snapshot is on
	// disk, so any later daemon start converges on it. Keeping the record
	// re-ran the identical revert+restart on every boot.
	if _, ok := db.GetFirewallRollback(); ok {
		t.Error("rollback record should be cleared once the config is restored")
	}
}

func TestRevertClearFailureDoesNotRestart(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	prev := []byte("hostname: prev\n")
	rb := store.FirewallRollback{
		PrevYAML:  prev,
		AppliedAt: time.Now().Add(-2 * time.Minute).UTC(),
		ExpiresAt: time.Now().Add(-time.Minute).UTC(),
		AppliedBy: "tok",
	}
	if serr := db.SaveFirewallRollback(rb); serr != nil {
		t.Fatal(serr)
	}
	if cerr := db.Close(); cerr != nil {
		t.Fatal(cerr)
	}

	cfgPath := filepath.Join(dir, "csm.yaml")
	if werr := os.WriteFile(cfgPath, []byte("hostname: next\n"), 0o600); werr != nil {
		t.Fatal(werr)
	}
	var restartCount atomic.Int32
	m := NewManager(db, cfgPath, func(_ context.Context) error {
		restartCount.Add(1)
		return nil
	}, time.Now)

	m.mu.Lock()
	err = m.applyRevertLocked(context.Background(), rb)
	m.mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "clear rollback before restart") {
		t.Fatalf("applyRevertLocked error = %v, want clear failure", err)
	}
	if got := restartCount.Load(); got != 0 {
		t.Errorf("restart called %d times after clear failure, want 0", got)
	}
	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, prev) {
		t.Errorf("config not restored before clear failure: got %q want %q", got, prev)
	}

	reopened, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if _, ok := reopened.GetFirewallRollback(); !ok {
		t.Error("rollback record should remain pending when clear fails")
	}
}

func TestRecoverOnStartupConvergesAfterCrashBeforeClear(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	prev := []byte("hostname: prev\n")
	cfgPath := filepath.Join(dir, "csm.yaml")
	if werr := os.WriteFile(cfgPath, prev, 0o600); werr != nil {
		t.Fatal(werr)
	}
	past := time.Now().Add(-time.Minute).UTC()
	if serr := db.SaveFirewallRollback(store.FirewallRollback{
		PrevYAML:  prev,
		AppliedAt: past.Add(-5 * time.Minute),
		ExpiresAt: past,
		AppliedBy: "tok",
	}); serr != nil {
		t.Fatal(serr)
	}

	var restartCount atomic.Int32
	restart := func(_ context.Context) error {
		restartCount.Add(1)
		if _, ok := db.GetFirewallRollback(); ok {
			t.Error("rollback record present when restart fired")
		}
		return nil
	}
	firstStart := NewManager(db, cfgPath, restart, time.Now)
	reverted, err := firstStart.RecoverOnStartup(context.Background())
	if err != nil {
		t.Fatalf("first RecoverOnStartup: %v", err)
	}
	if !reverted {
		t.Error("expired record should re-run the interrupted revert")
	}

	secondStart := NewManager(db, cfgPath, restart, time.Now)
	reverted, err = secondStart.RecoverOnStartup(context.Background())
	if err != nil {
		t.Fatalf("second RecoverOnStartup: %v", err)
	}
	if reverted {
		t.Error("cleared record should not revert on the next startup")
	}
	if got := restartCount.Load(); got != 1 {
		t.Errorf("restart called %d times, want 1", got)
	}
}

func TestRecoverOnStartupExpiredRevertFailureDoesNotClaimReverted(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "csm.yaml")
	if werr := os.WriteFile(cfgPath, []byte("hostname: next\n"), 0o600); werr != nil {
		t.Fatal(werr)
	}
	m := NewManager(db, cfgPath, func(_ context.Context) error {
		return errors.New("systemctl unavailable")
	}, time.Now)
	t.Cleanup(func() {
		_ = m.Confirm()
		_ = db.Close()
	})

	past := time.Now().Add(-1 * time.Minute).UTC()
	if serr := db.SaveFirewallRollback(store.FirewallRollback{
		PrevYAML:  []byte("hostname: prev\n"),
		AppliedAt: past.Add(-5 * time.Minute),
		ExpiresAt: past,
		AppliedBy: "tok",
	}); serr != nil {
		t.Fatal(serr)
	}

	reverted, err := m.RecoverOnStartup(context.Background())
	if err == nil {
		t.Fatal("RecoverOnStartup should surface restart failure")
	}
	if reverted {
		t.Error("failed recovery must not report reverted=true")
	}
	// Cleared despite the failed restart: the restored config is on disk
	// and this daemon start (or the next) loads it; a retained record
	// would revert+restart on every boot forever.
	if _, ok := db.GetFirewallRollback(); ok {
		t.Error("rollback record should be cleared once the config is restored")
	}
}
