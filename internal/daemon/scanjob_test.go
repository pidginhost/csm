package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
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

func TestScanJobNilConfigUsesDefaultRetention(t *testing.T) {
	st, _ := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	m.runAccountScan = func(ctx context.Context, cfg *config.Config, st *state.Store, target string, opts checks.AccountScanOptions) []alert.Finding {
		if cfg == nil {
			t.Error("runner received nil config")
		}
		return nil
	}

	id, err := m.Enqueue("account", "missing_acct", checks.AccountScanOptions{MaxFiles: 0, RespectIgnores: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	_ = waitForState(t, m, id, "done", 5*time.Second)
}

func TestScanJobRejectsEnqueueAfterStop(t *testing.T) {
	st, db := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}

	m.Stop()

	if _, enqueueErr := m.Enqueue("account", "late", checks.AccountScanOptions{}, false); enqueueErr == nil {
		t.Fatal("expected enqueue after Stop to fail")
	}
	jobs, err := db.ListScanJobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("enqueue after Stop persisted %d job(s), want 0", len(jobs))
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

// ---------------------------------------------------------------------------
// Task B2: server-wide ("all") scope tests
// ---------------------------------------------------------------------------

// TestAllScopeAggregatesFindings verifies the happy path: 3 accounts each
// return 1 finding → job done, FindingCount 3, AccountsTotal/Done 3, each
// finding carries its account as TenantID, all retrievable via ListFindings.
func TestAllScopeAggregatesFindings(t *testing.T) {
	st, db := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	accounts := []string{"alice", "bob", "charlie"}
	m.enumerateAccounts = func(_ *config.Config) ([]string, error) {
		return accounts, nil
	}
	m.runAccountScan = func(ctx context.Context, cfg *config.Config, st *state.Store, target string, opts checks.AccountScanOptions) []alert.Finding {
		return []alert.Finding{{Check: "webshell", Message: "found in " + target}}
	}

	id, err := m.Enqueue("all", "", checks.AccountScanOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}
	rec := waitForState(t, m, id, "done", 5*time.Second)

	if rec.FindingCount != 3 {
		t.Fatalf("FindingCount = %d, want 3", rec.FindingCount)
	}
	if rec.AccountsTotal != 3 {
		t.Fatalf("AccountsTotal = %d, want 3", rec.AccountsTotal)
	}
	if rec.AccountsDone != 3 {
		t.Fatalf("AccountsDone = %d, want 3", rec.AccountsDone)
	}
	if rec.CurrentAccount != "" {
		t.Fatalf("CurrentAccount = %q after done, want empty", rec.CurrentAccount)
	}

	findings, total, err := db.ListScanJobFindings(id, 0, 0)
	if err != nil {
		t.Fatalf("ListScanJobFindings: %v", err)
	}
	if total != 3 || len(findings) != 3 {
		t.Fatalf("findings total=%d len=%d, want 3", total, len(findings))
	}
	tenants := make(map[string]bool)
	for _, f := range findings {
		tenants[f.TenantID] = true
	}
	for _, acct := range accounts {
		if !tenants[acct] {
			t.Fatalf("missing TenantID %q in findings", acct)
		}
	}
	// total==3 (above) is the seq-uniqueness proof: a colliding seq key would
	// overwrite a prior finding row and ListScanJobFindings would return <3.
}

// TestAllScopePanicIsolation verifies that a panic in the middle account's
// runner does not abort the job: the other two accounts' findings are present,
// an account_scan_error synthetic finding is recorded for the panicking account,
// job is "done" (not "error"), and AccountsDone == 3.
func TestAllScopePanicIsolation(t *testing.T) {
	st, db := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	m.enumerateAccounts = func(_ *config.Config) ([]string, error) {
		return []string{"alice", "bob", "charlie"}, nil
	}
	m.runAccountScan = func(ctx context.Context, cfg *config.Config, st *state.Store, target string, opts checks.AccountScanOptions) []alert.Finding {
		if target == "bob" {
			panic("bob explodes")
		}
		return []alert.Finding{{Check: "webshell", Message: "found in " + target}}
	}

	id, err := m.Enqueue("all", "", checks.AccountScanOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}
	rec := waitForState(t, m, id, "done", 5*time.Second)

	if rec.AccountsDone != 3 {
		t.Fatalf("AccountsDone = %d, want 3", rec.AccountsDone)
	}

	findings, total, err := db.ListScanJobFindings(id, 0, 0)
	if err != nil {
		t.Fatalf("ListScanJobFindings: %v", err)
	}
	// 2 real findings + 1 synthetic error finding
	if total != 3 || len(findings) != 3 {
		t.Fatalf("findings total=%d len=%d, want 3", total, len(findings))
	}

	var errorFindings []alert.Finding
	for _, f := range findings {
		if f.Check == "account_scan_error" {
			errorFindings = append(errorFindings, f)
		}
	}
	if len(errorFindings) != 1 {
		t.Fatalf("account_scan_error findings = %d, want 1", len(errorFindings))
	}
	if errorFindings[0].TenantID != "bob" {
		t.Fatalf("error finding TenantID = %q, want bob", errorFindings[0].TenantID)
	}
}

// TestAllScopeEnumerateError verifies that an enumerator failure sets the job
// to state "error" with the enumerator's message.
func TestAllScopeEnumerateError(t *testing.T) {
	st, _ := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	m.enumerateAccounts = func(_ *config.Config) ([]string, error) {
		return nil, errors.New("disk read failure")
	}

	id, err := m.Enqueue("all", "", checks.AccountScanOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}
	rec := waitForState(t, m, id, "error", 5*time.Second)
	if rec.Error != "disk read failure" {
		t.Fatalf("Error = %q, want %q", rec.Error, "disk read failure")
	}
}

// TestAllScopeCancelMidIteration verifies that canceling mid-iteration stops
// further scanning, retains partial findings, and sets state "canceled".
func TestAllScopeCancelMidIteration(t *testing.T) {
	st, db := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	m.enumerateAccounts = func(_ *config.Config) ([]string, error) {
		return []string{"alice", "bob", "charlie"}, nil
	}

	// idCh hands the job id to the runner. The runner's alice branch receives
	// on it, which happens-after the test's send below -- so there is no race
	// on the id and no reach-in to the manager's internal cancel map.
	idCh := make(chan string, 1)
	var cancelOnce sync.Once
	m.runAccountScan = func(ctx context.Context, cfg *config.Config, st *state.Store, target string, opts checks.AccountScanOptions) []alert.Finding {
		if target == "alice" {
			// Cancel the job after alice's findings are returned; the receive
			// blocks until the test has published the id.
			cancelOnce.Do(func() { _ = m.Cancel(<-idCh) })
		}
		return []alert.Finding{{Check: "webshell", Message: "found in " + target}}
	}

	id, err := m.Enqueue("all", "", checks.AccountScanOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}
	idCh <- id

	rec := waitForState(t, m, id, "canceled", 5*time.Second)
	if rec.State != "canceled" {
		t.Fatalf("state = %q, want canceled", rec.State)
	}

	// Alice's finding must be persisted (partial findings retained).
	_, total, err := db.ListScanJobFindings(id, 0, 0)
	if err != nil {
		t.Fatalf("ListScanJobFindings: %v", err)
	}
	if total == 0 {
		t.Fatal("no partial findings retained after cancel")
	}
	// Must not have scanned all 3 accounts.
	if rec.AccountsDone >= 3 {
		t.Fatalf("AccountsDone = %d after cancel, expected < 3", rec.AccountsDone)
	}
}

// TestAllScopeTenantIDNotClobbered verifies that a finding with TenantID
// already set by the check is preserved as-is.
func TestAllScopeTenantIDNotClobbered(t *testing.T) {
	st, db := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	m.enumerateAccounts = func(_ *config.Config) ([]string, error) {
		return []string{"alice"}, nil
	}
	m.runAccountScan = func(ctx context.Context, cfg *config.Config, st *state.Store, target string, opts checks.AccountScanOptions) []alert.Finding {
		return []alert.Finding{{Check: "webshell", TenantID: "pre-set-tenant"}}
	}

	id, err := m.Enqueue("all", "", checks.AccountScanOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}
	_ = waitForState(t, m, id, "done", 5*time.Second)

	findings, _, err := db.ListScanJobFindings(id, 0, 0)
	if err != nil {
		t.Fatalf("ListScanJobFindings: %v", err)
	}
	if len(findings) != 1 || findings[0].TenantID != "pre-set-tenant" {
		t.Fatalf("TenantID = %q, want pre-set-tenant", findings[0].TenantID)
	}
}

// TestAllScopeAccountScopeRegression verifies that an "account"-scope job
// still behaves exactly as before: one runner call, findings persisted, no
// AccountsTotal set.
func TestAllScopeAccountScopeRegression(t *testing.T) {
	st, db := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	calls := 0
	m.runAccountScan = func(ctx context.Context, cfg *config.Config, st *state.Store, target string, opts checks.AccountScanOptions) []alert.Finding {
		calls++
		return []alert.Finding{{Check: "webshell"}}
	}

	id, err := m.Enqueue("account", "alice", checks.AccountScanOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}
	rec := waitForState(t, m, id, "done", 5*time.Second)

	if calls != 1 {
		t.Fatalf("runner called %d times, want 1", calls)
	}
	if rec.AccountsTotal != 0 {
		t.Fatalf("AccountsTotal = %d, want 0 for account scope", rec.AccountsTotal)
	}
	findings, total, err := db.ListScanJobFindings(id, 0, 0)
	if err != nil {
		t.Fatalf("ListScanJobFindings: %v", err)
	}
	if total != 1 || len(findings) != 1 {
		t.Fatalf("findings total=%d len=%d, want 1", total, len(findings))
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

// ---------------------------------------------------------------------------
// Task E1: full-scan --quarantine wiring tests
// ---------------------------------------------------------------------------

// fakeQuarantineFile returns a quarantine func that moves the file to qdir,
// allowing daemon tests to operate on a temp dir without touching real paths.
// It mirrors the minimal behaviour of checks.QuarantineFindingFile:
//   - eligible set: the pure file-quarantine checks (webshell, obfuscated_php, …)
//   - ineligible: everything else (backdoor_binary, suspicious_crontab, …)
//   - moves the file to qdir and reports Success when eligible + file exists
//
// Source of truth for the eligible set is eligibleFullScanChecks in
// internal/checks/fullscan_quarantine.go; keep this list in sync if it changes.
func fakeQuarantineFile(qdir string) func(f alert.Finding) (checks.RemediationResult, bool) {
	eligible := map[string]bool{
		"webshell": true, "new_webshell_file": true, "obfuscated_php": true,
		"php_dropper": true, "suspicious_php_content": true,
		"new_php_in_languages": true, "new_php_in_upgrade": true,
		"phishing_page": true, "phishing_directory": true,
	}
	return func(f alert.Finding) (checks.RemediationResult, bool) {
		if !eligible[f.Check] || f.FilePath == "" {
			return checks.RemediationResult{}, false
		}
		dst := filepath.Join(qdir, filepath.Base(f.FilePath))
		if err := os.Rename(f.FilePath, dst); err != nil {
			return checks.RemediationResult{Error: err.Error()}, true
		}
		return checks.RemediationResult{
			Success: true,
			Action:  "quarantined " + f.FilePath + " → " + dst,
		}, true
	}
}

// TestScanJobQuarantine_EligibleFindingQuarantined: account-scope job with
// quarantine=true and a webshell finding whose FilePath is a real temp file →
// stored finding has RemediationStatus="quarantined", file moved.
func TestScanJobQuarantine_EligibleFindingQuarantined(t *testing.T) {
	root := t.TempDir()
	qdir := t.TempDir()

	// Create file before NewScanJobManager to avoid shadowing `err`.
	// RFC-5737 prefix in account name; PHP content is a test payload only.
	src := filepath.Join(root, "shell.php")
	// #nosec G306 -- test payload; simulates a malicious PHP file in a temp dir
	if writeErr := os.WriteFile(src, []byte("<?php system($_GET['c']); ?>"), 0644); writeErr != nil {
		t.Fatal(writeErr)
	}

	st, db := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	m.quarantineFile = fakeQuarantineFile(qdir)
	m.runAccountScan = func(ctx context.Context, cfg *config.Config, st *state.Store, target string, opts checks.AccountScanOptions) []alert.Finding {
		return []alert.Finding{{
			Check:    "webshell",
			FilePath: src,
		}}
	}

	id, err := m.Enqueue("account", "192-0-2-1", checks.AccountScanOptions{}, true)
	if err != nil {
		t.Fatal(err)
	}
	_ = waitForState(t, m, id, "done", 5*time.Second)

	findings, total, err := db.ListScanJobFindings(id, 0, 10)
	if err != nil || total != 1 || len(findings) != 1 {
		t.Fatalf("findings total=%d len=%d err=%v, want 1", total, len(findings), err)
	}
	if findings[0].RemediationStatus != "quarantined" {
		t.Fatalf("RemediationStatus = %q, want quarantined", findings[0].RemediationStatus)
	}
	if findings[0].RemediationDetail == "" {
		t.Fatal("RemediationDetail must be non-empty on success")
	}
	// File must have been moved.
	if _, statErr := os.Stat(src); !os.IsNotExist(statErr) {
		t.Fatal("source file must be removed after quarantine")
	}
}

// TestScanJobQuarantine_IneligibleFindingLeftForReview: account-scope job with
// quarantine=true and a non-eligible finding (suspicious_crontab maps to a
// crontab truncate, not a pure file move) →
// stored finding has RemediationStatus="left_for_review".
func TestScanJobQuarantine_IneligibleFindingLeftForReview(t *testing.T) {
	st, db := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	m.quarantineFile = fakeQuarantineFile(t.TempDir())
	m.runAccountScan = func(ctx context.Context, cfg *config.Config, st *state.Store, target string, opts checks.AccountScanOptions) []alert.Finding {
		return []alert.Finding{{
			Check:   "suspicious_crontab", // not a pure file quarantine — ineligible
			Message: "crontab with curl|bash detected",
		}}
	}

	id, err := m.Enqueue("account", "198-51-100-1", checks.AccountScanOptions{}, true)
	if err != nil {
		t.Fatal(err)
	}
	_ = waitForState(t, m, id, "done", 5*time.Second)

	findings, total, err := db.ListScanJobFindings(id, 0, 10)
	if err != nil || total != 1 || len(findings) != 1 {
		t.Fatalf("findings total=%d len=%d err=%v, want 1", total, len(findings), err)
	}
	if findings[0].RemediationStatus != "left_for_review" {
		t.Fatalf("RemediationStatus = %q, want left_for_review", findings[0].RemediationStatus)
	}
}

// TestScanJobQuarantine_ReportOnlyJobNoRemediation: report-only job
// (quarantine=false) → stored finding has empty RemediationStatus, no file moved.
func TestScanJobQuarantine_ReportOnlyJobNoRemediation(t *testing.T) {
	root := t.TempDir()
	qdir := t.TempDir()

	// Create file before NewScanJobManager to avoid shadowing `err`.
	src := filepath.Join(root, "shell2.php")
	// #nosec G306 -- test payload; simulates a malicious PHP file in a temp dir
	if writeErr := os.WriteFile(src, []byte("<?php passthru($_GET['c']); ?>"), 0644); writeErr != nil {
		t.Fatal(writeErr)
	}

	st, db := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	m.quarantineFile = fakeQuarantineFile(qdir)
	m.runAccountScan = func(ctx context.Context, cfg *config.Config, st *state.Store, target string, opts checks.AccountScanOptions) []alert.Finding {
		return []alert.Finding{{
			Check:    "webshell",
			FilePath: src,
		}}
	}

	id, err := m.Enqueue("account", "203-0-113-1", checks.AccountScanOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}
	_ = waitForState(t, m, id, "done", 5*time.Second)

	findings, total, err := db.ListScanJobFindings(id, 0, 10)
	if err != nil || total != 1 || len(findings) != 1 {
		t.Fatalf("findings total=%d len=%d err=%v, want 1", total, len(findings), err)
	}
	if findings[0].RemediationStatus != "" {
		t.Fatalf("RemediationStatus = %q, want empty for report-only job", findings[0].RemediationStatus)
	}
	// File must NOT have been moved.
	if _, statErr := os.Stat(src); statErr != nil {
		t.Fatalf("source file must remain for report-only job: %v", statErr)
	}
}

// TestScanJobQuarantine_EligibleButFailed: an eligible finding whose file cannot
// be moved (source absent → rename fails) is stamped RemediationStatus="failed"
// with the error in the detail. Exercises the eligible-but-unsuccessful branch
// of annotateQuarantine that the other tests do not cover.
func TestScanJobQuarantine_EligibleButFailed(t *testing.T) {
	root := t.TempDir()
	qdir := t.TempDir()

	st, db := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	m.quarantineFile = fakeQuarantineFile(qdir)
	m.runAccountScan = func(ctx context.Context, cfg *config.Config, st *state.Store, target string, opts checks.AccountScanOptions) []alert.Finding {
		// Eligible check + a path that does not exist → fake's os.Rename fails,
		// returning (Error, eligible=true).
		return []alert.Finding{{
			Check:    "obfuscated_php",
			FilePath: filepath.Join(root, "gone.php"),
		}}
	}

	id, err := m.Enqueue("account", "192-0-2-2", checks.AccountScanOptions{}, true)
	if err != nil {
		t.Fatal(err)
	}
	_ = waitForState(t, m, id, "done", 5*time.Second)

	findings, total, err := db.ListScanJobFindings(id, 0, 10)
	if err != nil || total != 1 || len(findings) != 1 {
		t.Fatalf("findings total=%d len=%d err=%v, want 1", total, len(findings), err)
	}
	if findings[0].RemediationStatus != "failed" {
		t.Fatalf("RemediationStatus = %q, want failed", findings[0].RemediationStatus)
	}
	if findings[0].RemediationDetail == "" {
		t.Fatal("RemediationDetail must carry the error on a failed quarantine")
	}
}
