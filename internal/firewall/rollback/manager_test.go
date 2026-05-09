package rollback

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

func newTestManager(t *testing.T) (*Manager, *store.DB, string, *atomic.Int32) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

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
	t.Cleanup(func() { _ = db.Close() })

	cfgPath := filepath.Join(dir, "csm.yaml")
	if werr := os.WriteFile(cfgPath, []byte("x"), 0o600); werr != nil {
		t.Fatal(werr)
	}

	failingRestart := func(_ context.Context) error { return errors.New("systemctl unavailable") }
	m := NewManager(db, cfgPath, failingRestart, time.Now)

	if _, aerr := m.Apply([]byte("prev"), []byte("next"), time.Minute, "tok"); aerr != nil {
		t.Fatal(aerr)
	}
	if rerr := m.Revert(context.Background()); rerr == nil {
		t.Error("Revert should bubble up restart failure")
	}
	// Even with failed restart the snapshot is dropped because the
	// disk file is already restored; otherwise startup would loop.
	if _, ok := db.GetFirewallRollback(); ok {
		t.Error("rollback record should be cleared even when restart fails")
	}
}
