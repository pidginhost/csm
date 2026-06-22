package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// scanJobQueueDepth is the maximum number of jobs that may wait in the queue
// while the single worker is busy. Enqueue returns an error when full.
const scanJobQueueDepth = 8

// scanJobIDCounter is a process-wide monotonic counter used to make job IDs
// unique when two Enqueue calls occur within the same millisecond.
var scanJobIDCounter atomic.Int64

// newScanJobID returns a lexically time-sortable, collision-free job ID.
// Format: "sj-<unix-ms-hex>-<counter-hex>".
// Lexical sort on the hex timestamp gives newest-first ordering consistent
// with the store's ListScanJobs sort key.
func newScanJobID() string {
	ms := time.Now().UnixMilli()
	seq := scanJobIDCounter.Add(1)
	return fmt.Sprintf("sj-%016x-%08x", ms, seq)
}

// scanJobRunner is the function the worker calls to perform the actual scan.
// It is a field on ScanJobManager so tests can substitute a blocking fixture
// without any sleep races.
type scanJobRunner func(ctx context.Context, cfg *config.Config, st *state.Store, target string, opts checks.AccountScanOptions) []alert.Finding

// scanJobRequest is what Enqueue pushes into the work channel.
type scanJobRequest struct {
	id        string
	opts      checks.AccountScanOptions
	cancelCtx context.Context    // per-job cancellable context
	cancelFn  context.CancelFunc // allows Cancel() to stop the runner
}

// ScanJobManager runs full-scan jobs as background work in the daemon.
// A single worker goroutine drains a bounded channel of job requests so
// jobs are strictly serialised; Phase 1 does not fan out across accounts.
//
// Lifecycle: the caller owns a sync.WaitGroup slot (d.wg). Stop() cancels
// all in-flight work and blocks until the worker goroutine exits.
type ScanJobManager struct {
	st  *state.Store
	cfg *config.Config
	db  *store.DB // bbolt handle; resolved from store.Global() at construction

	// runAccountScan is the runner called for each job. Tests replace this
	// with a fixture to control blocking / return values without sleep races.
	runAccountScan scanJobRunner

	workCh chan scanJobRequest // bounded; Enqueue returns an error when full
	stopCh chan struct{}       // closed by Stop()

	// cancelMu guards stopped and cancelFns across enqueue, cancel, run,
	// drain, and stop. Enqueue holds it until the work item is buffered so
	// Stop cannot close the worker before seeing the new job context.
	cancelMu  sync.Mutex
	stopped   bool
	cancelFns map[string]context.CancelFunc

	// workerDone is closed when the worker goroutine exits.
	workerDone chan struct{}

	// stopOnce ensures Stop() is idempotent: a second call is a no-op rather
	// than a panic on double-close of stopCh.
	stopOnce sync.Once
}

// NewScanJobManager creates a ScanJobManager and reconciles any job left in
// state "running" from a previous daemon crash to state "error" with reason
// "daemon_restarted". Returns an error if the global bbolt handle is nil.
func NewScanJobManager(st *state.Store, cfg *config.Config) (*ScanJobManager, error) {
	db := store.Global()
	if db == nil {
		return nil, errors.New("scan-job manager: global bbolt store is nil")
	}

	m := &ScanJobManager{
		st:             st,
		cfg:            cfg,
		db:             db,
		runAccountScan: defaultScanRunner,
		workCh:         make(chan scanJobRequest, scanJobQueueDepth),
		stopCh:         make(chan struct{}),
		cancelFns:      make(map[string]context.CancelFunc),
		workerDone:     make(chan struct{}),
	}

	if err := m.reconcileStaleRunning(); err != nil {
		return nil, fmt.Errorf("scan-job manager: reconcile: %w", err)
	}

	// The worker goroutine is tracked in its own WaitGroup so Stop() can
	// drain it independently of the daemon's wg. The daemon wires this
	// manager via d.wg + obs.Go when it calls startScanJobManager().
	obs.Go("scan-job-worker", m.worker)

	return m, nil
}

// defaultScanRunner delegates to checks.RunAccountScanWithOptions.
func defaultScanRunner(ctx context.Context, cfg *config.Config, st *state.Store, target string, opts checks.AccountScanOptions) []alert.Finding {
	return checks.RunAccountScanWithOptions(ctx, cfg, st, target, opts)
}

// reconcileStaleRunning marks any job persisted as "running" to "error" with
// reason "daemon_restarted". Called once on construction before the worker
// starts, so no concurrent writes race with this read-modify-write pass.
func (m *ScanJobManager) reconcileStaleRunning() error {
	jobs, err := m.db.ListScanJobs()
	if err != nil {
		return err
	}
	for _, rec := range jobs {
		if rec.State != "running" {
			continue
		}
		rec.State = "error"
		rec.Error = "daemon_restarted"
		rec.Finished = time.Now().UTC()
		if putErr := m.db.PutScanJob(rec); putErr != nil {
			return putErr
		}
		csmlog.Warn("scan job reconciled after restart", "job_id", rec.ID)
	}
	return nil
}

// Enqueue creates a new queued job record and pushes it into the work channel.
// Returns the job ID. Returns an error when the queue is full.
// A quarantine flag is recorded on the job record for use by a later phase;
// no live auto-response is wired in Phase 1.
func (m *ScanJobManager) Enqueue(scope, target string, opts checks.AccountScanOptions, quarantine bool) (string, error) {
	m.cancelMu.Lock()
	defer m.cancelMu.Unlock()
	if m.stopped {
		return "", errors.New("scan-job manager stopped")
	}

	id := newScanJobID()

	// Options map for storage (human-readable; not used by the worker).
	optsMap := map[string]any{
		"max_files":        opts.MaxFiles,
		"force_content":    opts.ForceContent,
		"force_file_index": opts.ForceFileIndex,
		"respect_ignores":  opts.RespectIgnores,
		"max_file_bytes":   opts.MaxFileBytes,
		"quarantine":       quarantine,
	}

	rec := store.ScanJobRecord{
		ID:      id,
		Scope:   scope,
		Target:  target,
		State:   "queued",
		Created: time.Now().UTC(),
		Options: optsMap,
	}
	if err := m.db.PutScanJob(rec); err != nil {
		return "", fmt.Errorf("scan-job enqueue: persist: %w", err)
	}

	// Build a per-job cancellable context. Cancel is called either by Cancel()
	// or by Stop(), which cancels all live job contexts before waiting for the
	// worker goroutine to exit.
	jobCtx, jobCancel := context.WithCancel(context.Background())
	m.cancelFns[id] = jobCancel

	req := scanJobRequest{
		id:        id,
		opts:      opts,
		cancelCtx: jobCtx,
		cancelFn:  jobCancel,
	}

	select {
	case m.workCh <- req:
		return id, nil
	default:
		// Queue full -- remove the persisted record and cancel the context.
		jobCancel()
		delete(m.cancelFns, id)
		// Mark the just-persisted record as error so it does not look queued.
		rec.State = "error"
		rec.Error = "queue_full"
		rec.Finished = time.Now().UTC()
		_ = m.db.PutScanJob(rec)
		return "", errors.New("scan-job queue is full")
	}
}

// Cancel cancels the job with the given ID. If the job is still queued the
// worker will transition it to "canceled" without running the scanner. If the
// job is running, its context is canceled and the worker persists any findings
// the runner returns after ctx.Done() before setting state "canceled".
// Returns an error when the ID is unknown or already in a terminal state.
func (m *ScanJobManager) Cancel(id string) error {
	m.cancelMu.Lock()
	fn, ok := m.cancelFns[id]
	m.cancelMu.Unlock()
	if !ok {
		return fmt.Errorf("scan-job cancel: unknown or already terminal job %q", id)
	}
	fn()
	return nil
}

// Progress returns the current record for the given job ID.
// ok is false when the ID is not found in the store.
func (m *ScanJobManager) Progress(id string) (store.ScanJobRecord, bool) {
	rec, ok, err := m.db.GetScanJob(id)
	if err != nil || !ok {
		return store.ScanJobRecord{}, false
	}
	return rec, true
}

// Stop cancels all in-flight or queued work and waits for the worker goroutine
// to exit. After Stop returns the manager must not be used. Stop is idempotent:
// a sync.Once guards the close of stopCh so repeated calls are safe.
// Canceling all live job contexts before blocking on workerDone ensures that
// any scan currently executing inside runAccountScan returns promptly; the
// runner honors ctx and the job lands in terminal state "canceled" with its
// partial findings retained.
func (m *ScanJobManager) Stop() {
	m.stopOnce.Do(func() {
		m.cancelMu.Lock()
		m.stopped = true
		close(m.stopCh)
		for _, fn := range m.cancelFns {
			fn()
		}
		m.cancelMu.Unlock()
	})
	<-m.workerDone
}

// worker is the single serialised goroutine that processes scan jobs.
// It holds no references to closed resources after Stop() returns because:
//  1. Stop() closes stopCh and cancels all live job contexts before blocking
//     on workerDone; any in-flight scan honors ctx.Done() and returns promptly
//     with partial findings, landing in terminal state "canceled".
//  2. The select below exits as soon as stopCh fires, and all remaining
//     queued jobs are drained as "canceled" -- none write to the store after
//     Close() because the daemon closes the store only after Stop() returns.
func (m *ScanJobManager) worker() {
	defer close(m.workerDone)
	for {
		select {
		case <-m.stopCh:
			// Drain the queue: mark any pending jobs canceled without running.
			m.drainQueueOnStop()
			return
		case req := <-m.workCh:
			m.runJob(req)
		}
	}
}

// drainQueueOnStop consumes all remaining items in workCh after stopCh closes
// and marks each as "canceled". Nothing writes to the store after this returns.
func (m *ScanJobManager) drainQueueOnStop() {
	for {
		select {
		case req := <-m.workCh:
			req.cancelFn()
			m.cancelMu.Lock()
			delete(m.cancelFns, req.id)
			m.cancelMu.Unlock()
			m.setTerminal(req.id, "canceled", "")
		default:
			return
		}
	}
}

// runJob executes a single scan job to completion and persists the result.
// The job context (req.cancelCtx) may be canceled externally by Cancel() or
// by Stop() -> drainQueueOnStop. This function handles both cases:
//   - If the context is already canceled when we check, skip the scan entirely.
//   - After the runner returns, inspect ctx.Err() to choose the terminal state.
func (m *ScanJobManager) runJob(req scanJobRequest) {
	defer func() {
		// Always remove the cancel function entry when the job is done.
		m.cancelMu.Lock()
		delete(m.cancelFns, req.id)
		m.cancelMu.Unlock()
		req.cancelFn()
	}()

	// If the job was canceled before the worker got to it (e.g. Cancel()
	// called while it was queued), skip the scan and go straight to terminal.
	if req.cancelCtx.Err() != nil {
		m.setTerminal(req.id, "canceled", "")
		return
	}

	// Transition to "running".
	rec, ok, err := m.db.GetScanJob(req.id)
	if err != nil || !ok {
		csmlog.Warn("scan job missing at run time", "job_id", req.id)
		return
	}
	rec.State = "running"
	rec.Started = time.Now().UTC()
	if putErr := m.db.PutScanJob(rec); putErr != nil {
		csmlog.Warn("scan job state update failed", "job_id", req.id, "err", putErr)
		return
	}

	cfg := m.cfg
	if cfg == nil {
		cfg = &config.Config{}
	}

	// Run the scan. The runner blocks until complete or ctx is canceled.
	findings := m.runAccountScan(req.cancelCtx, cfg, m.st, rec.Target, req.opts)

	// Persist every finding the runner returned, even if canceled mid-scan.
	// This preserves partial results for the "cancel keeps partial" guarantee.
	for i, f := range findings {
		if appendErr := m.db.AppendScanJobFinding(req.id, i, f); appendErr != nil {
			csmlog.Warn("scan job finding persist failed", "job_id", req.id, "seq", i, "err", appendErr)
		}
	}

	// Determine terminal state.
	jobState := "done"
	if req.cancelCtx.Err() != nil {
		jobState = "canceled"
	}

	// Refresh the record before writing the terminal state so FilesScanned
	// and FindingCount reflect any in-progress updates (future phases may
	// update these mid-scan via callbacks; for now we set them from findings).
	rec2, ok2, err2 := m.db.GetScanJob(req.id)
	if err2 != nil || !ok2 {
		// Fall back to the snapshot we already have.
		rec2 = rec
	}
	rec2.State = jobState
	rec2.Finished = time.Now().UTC()
	rec2.FindingCount = len(findings)
	if putErr := m.db.PutScanJob(rec2); putErr != nil {
		csmlog.Warn("scan job terminal state failed", "job_id", req.id, "err", putErr)
	}

	// Prune oldest jobs to keep the store within the configured retention.
	retention := cfg.Thresholds.ScanJobRetention
	if retention <= 0 {
		retention = 20
	}
	if _, pruneErr := m.db.PruneScanJobs(retention); pruneErr != nil {
		csmlog.Warn("scan job prune failed", "err", pruneErr)
	}
}

// setTerminal writes a terminal state for a job without running any scan.
// Used to transition queued-but-canceled jobs during drainQueueOnStop.
func (m *ScanJobManager) setTerminal(id, jobState, errMsg string) {
	rec, ok, err := m.db.GetScanJob(id)
	if err != nil || !ok {
		return
	}
	rec.State = jobState
	rec.Error = errMsg
	rec.Finished = time.Now().UTC()
	_ = m.db.PutScanJob(rec)
}

// startScanJobManager initialises the ScanJobManager and wires it into the
// daemon's lifecycle. Call this from Daemon.Run() after store.Global() is set
// and before startControlListener() so the control socket can immediately
// accept job submissions.
func (d *Daemon) startScanJobManager() (*ScanJobManager, error) {
	m, err := NewScanJobManager(d.store, d.cfg)
	if err != nil {
		return nil, err
	}

	// Track the manager's lifetime in the daemon wait-group using the same
	// obs.Go + defer d.wg.Done() pattern every other background worker uses.
	// NewScanJobManager already started the worker goroutine via its own
	// obs.Go call; this entry just blocks d.wg.Wait() until that goroutine
	// finishes draining. Stop() must be called before d.wg.Wait() so that
	// workerDone is already closed by the time we reach here.
	d.wg.Add(1)
	obs.Go("scan-job-manager", func() {
		defer d.wg.Done()
		<-m.workerDone
	})

	return m, nil
}
