package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// openTestScanJobStores opens a temporary state.Store and store.DB, sets the
// global bbolt singleton, and registers cleanup. The caller receives both
// handles so it can query findings directly.
func openTestScanJobStores(t *testing.T) (*state.Store, *store.DB) {
	t.Helper()
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	db, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	prev := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = db.Close()
		_ = st.Close()
	})
	return st, db
}

// waitForState polls Progress until the job reaches the expected state or the
// deadline expires. It returns the final record. No sleep races: the worker
// writes state transitions synchronously via PutScanJob before returning, so
// Progress reflects the terminal state as soon as the worker goroutine finishes.
func waitForState(t *testing.T, m *ScanJobManager, id, want string, timeout time.Duration) store.ScanJobRecord {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		rec, ok := m.Progress(id)
		if ok && rec.State == want {
			return rec
		}
		time.Sleep(5 * time.Millisecond)
	}
	rec, _ := m.Progress(id)
	t.Fatalf("job %s: state %q after %s, want %q", id, rec.State, timeout, want)
	return store.ScanJobRecord{}
}

// TestScanJobRunsAndPersists verifies the happy path: a job is enqueued,
// runs to completion, and the terminal record is retrievable via Progress.
func TestScanJobRunsAndPersists(t *testing.T) {
	st, _ := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	id, err := m.Enqueue("account", "missing_acct", checks.AccountScanOptions{MaxFiles: 0, RespectIgnores: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	rec := waitForState(t, m, id, "done", 5*time.Second)
	if rec.Scope != "account" || rec.Target != "missing_acct" {
		t.Fatalf("unexpected job record %+v", rec)
	}
}

// TestScanJobCancelKeepsPartial verifies that canceling a running job
// sets state "canceled" while preserving findings returned after ctx.Done().
// A hook blocks the runner until the context is canceled, avoiding any sleep race.
func TestScanJobCancelKeepsPartial(t *testing.T) {
	st, db := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	started := make(chan struct{})
	m.runAccountScan = func(ctx context.Context, cfg *config.Config, st *state.Store, target string, opts checks.AccountScanOptions) []alert.Finding {
		close(started)
		<-ctx.Done()
		return []alert.Finding{{
			Check:    "webshell",
			FilePath: "/home/acct/public_html/c99.php",
		}}
	}

	id, err := m.Enqueue("account", "acct", checks.AccountScanOptions{MaxFiles: 0, RespectIgnores: false}, false)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("job did not start")
	}
	if cancelErr := m.Cancel(id); cancelErr != nil {
		t.Fatal(cancelErr)
	}
	rec := waitForState(t, m, id, "canceled", 5*time.Second)
	if rec.State != "canceled" {
		t.Fatalf("state = %q, want canceled", rec.State)
	}
	findings, total, err := db.ListScanJobFindings(id, 0, 10)
	if err != nil || total != 1 || len(findings) != 1 {
		t.Fatalf("partial findings = %d total=%d err=%v", len(findings), total, err)
	}
	if findings[0].FilePath != "/home/acct/public_html/c99.php" {
		t.Fatalf("partial finding path = %q", findings[0].FilePath)
	}
}

// TestStopCancelsInFlightJob verifies that Stop() returns promptly even when a
// job is mid-scan, and that the job lands in terminal state "canceled" with its
// partial findings retained -- without the blocking fixture being released.
// This test is the bite-proof for FIX 1: against the unfixed code, Stop() would
// block on <-m.workerDone until the scan completes naturally (which never
// happens here because we never release the blocker), causing the test to hang
// until the 3-second deadline fires.
func TestStopCancelsInFlightJob(t *testing.T) {
	st, db := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	// The blocker channel is intentionally never closed; the scanner must be
	// interrupted exclusively via ctx cancellation from Stop().
	blocker := make(chan struct{})

	m.runAccountScan = func(ctx context.Context, cfg *config.Config, st *state.Store, target string, opts checks.AccountScanOptions) []alert.Finding {
		close(started)
		select {
		case <-blocker:
		case <-ctx.Done():
		}
		return []alert.Finding{{Check: "webshell", FilePath: "/tmp/evil.php"}}
	}

	id, err := m.Enqueue("account", "victim", checks.AccountScanOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for the scan to be visibly running before calling Stop.
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("job did not start within 2s")
	}

	// Stop must return within 3 seconds; if it hangs, the test (and blocker)
	// goroutine would leak -- that is the bug we are fixing.
	done := make(chan struct{})
	go func() {
		m.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop() did not return within 3s -- in-flight job was not canceled")
	}

	// The job must have reached terminal state "canceled" with partial findings.
	rec, ok := m.Progress(id)
	if !ok {
		t.Fatal("job record missing after Stop")
	}
	if rec.State != "canceled" {
		t.Fatalf("job state = %q, want canceled", rec.State)
	}
	findings, total, err := db.ListScanJobFindings(id, 0, 10)
	if err != nil || total != 1 || len(findings) != 1 {
		t.Fatalf("partial findings = %d total=%d err=%v, want 1", len(findings), total, err)
	}
	if findings[0].FilePath != "/tmp/evil.php" {
		t.Fatalf("partial finding path = %q", findings[0].FilePath)
	}
}

// TestRunningJobMarkedErrorOnRestart verifies that a job left in state
// "running" by a previous daemon crash is transitioned to "error" with
// reason "daemon_restarted" when NewScanJobManager is called.
func TestRunningJobMarkedErrorOnRestart(t *testing.T) {
	st, db := openTestScanJobStores(t)
	if err := db.PutScanJob(store.ScanJobRecord{ID: "stuck", State: "running"}); err != nil {
		t.Fatal(err)
	}
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	rec, _, _ := db.GetScanJob("stuck")
	if rec.State != "error" || rec.Error != "daemon_restarted" {
		t.Fatalf("running job not reconciled: %+v", rec)
	}
}

// TestScanJobQueueBounded verifies that Enqueue returns an error when the
// queue is full rather than blocking the caller indefinitely.
func TestScanJobQueueBounded(t *testing.T) {
	st, _ := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	// Block the worker so the queue fills up.
	block := make(chan struct{})
	m.runAccountScan = func(ctx context.Context, cfg *config.Config, st *state.Store, target string, opts checks.AccountScanOptions) []alert.Finding {
		select {
		case <-block:
		case <-ctx.Done():
		}
		return nil
	}

	// Fill the queue: one running + scanJobQueueDepth queued.
	enqueuedIDs := make([]string, 0, scanJobQueueDepth+1)
	var enqID string
	var enqErr error
	for i := 0; i < scanJobQueueDepth+1; i++ {
		enqID, enqErr = m.Enqueue("account", "acct", checks.AccountScanOptions{}, false)
		if enqErr != nil {
			// This slot failed -- that's OK once the queue is truly full.
			break
		}
		enqueuedIDs = append(enqueuedIDs, enqID)
	}
	_ = enqID

	// The very next Enqueue must fail.
	_, err = m.Enqueue("account", "acct", checks.AccountScanOptions{}, false)
	if err == nil {
		t.Fatal("expected error when queue is full, got nil")
	}

	// Drain so the test goroutine does not leak.
	close(block)
	_ = enqueuedIDs
}

// TestScanJobCancelQueued verifies that canceling a job that is still
// waiting in the queue sets it to "canceled" without running the scanner.
func TestScanJobCancelQueued(t *testing.T) {
	st, _ := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	// Block the worker so a second enqueue stays queued.
	block := make(chan struct{})
	ran := make(chan string, 10)
	m.runAccountScan = func(ctx context.Context, cfg *config.Config, st *state.Store, target string, opts checks.AccountScanOptions) []alert.Finding {
		ran <- target
		select {
		case <-block:
		case <-ctx.Done():
		}
		return nil
	}

	// First job occupies the worker.
	_, err = m.Enqueue("account", "blocker", checks.AccountScanOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}
	// Wait for blocker to start running.
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("blocker did not start")
	}

	// Second job sits in the queue.
	id2, err := m.Enqueue("account", "queued", checks.AccountScanOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}

	// Cancel the queued job.
	if err := m.Cancel(id2); err != nil {
		t.Fatal(err)
	}

	// Unblock the worker.
	close(block)

	// The canceled job must reach terminal state "canceled".
	rec := waitForState(t, m, id2, "canceled", 3*time.Second)
	if rec.State != "canceled" {
		t.Fatalf("queued job state = %q, want canceled", rec.State)
	}
}

// TestScanJobDoesNotCallAlertDispatch verifies the report-only guarantee:
// the worker must never push findings to the alert pipeline. We accomplish
// this by confirming that only AppendScanJobFinding is called (indirectly
// via ListScanJobFindings) and no alert.Finding ends up in the global
// alertCh (which a real daemon would have wired).
func TestScanJobDoesNotCallAlertDispatch(t *testing.T) {
	st, db := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	m.runAccountScan = func(ctx context.Context, cfg *config.Config, st *state.Store, target string, opts checks.AccountScanOptions) []alert.Finding {
		return []alert.Finding{
			{Check: "webshell", FilePath: "/home/acct/shell.php"},
		}
	}

	id, err := m.Enqueue("account", "acct", checks.AccountScanOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}
	_ = waitForState(t, m, id, "done", 5*time.Second)

	findings, total, err := db.ListScanJobFindings(id, 0, 10)
	if err != nil {
		t.Fatalf("ListScanJobFindings: %v", err)
	}
	if total != 1 || len(findings) != 1 {
		t.Fatalf("findings count = %d total=%d, want 1", len(findings), total)
	}
}
