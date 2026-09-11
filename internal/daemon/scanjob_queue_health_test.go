package daemon

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

func TestScanJobQueueHealthPublished(t *testing.T) {
	st, _ := openTestScanJobStores(t)
	d := &Daemon{store: st, cfg: &config.Config{}}
	m, err := d.startScanJobManager()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { m.Stop(); d.wg.Wait() }()
	rows := d.queueStatuses(time.Now())
	for _, name := range []string{"scans.jobs", "scans.admission"} {
		row, ok := rows[name]
		if !ok {
			t.Errorf("missing scan queue %s", name)
			continue
		}
		if row.Status != "ok" || row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 0 {
			t.Errorf("idle %s: %+v", name, row)
		}
	}
}

func scanJobHealthRow(t *testing.T, m *ScanJobManager, name string, now time.Time) queuehealth.Status {
	t.Helper()
	result := make(chan queuehealth.Status, 1)
	go func() { result <- m.QueueStatuses(now)[name] }()
	select {
	case got := <-result:
		return got
	case <-time.After(time.Second):
		t.Fatal("scan job health blocked on an operation lock")
		return queuehealth.Status{}
	}
}

func waitScanJobsEmpty(t *testing.T, m *ScanJobManager) queuehealth.Status {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		s := scanJobHealthRow(t, m, "jobs", time.Now())
		if s.Depth == 0 && s.InFlight == 0 {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("job ownership did not settle: %+v", s)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestScanJobQueueHealthCapacityAndCancellation(t *testing.T) {
	st, _ := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer func() { finish(); m.Stop() }()
	entered := make(chan struct{}, 1)
	m.runAccountScan = func(context.Context, *config.Config, *state.Store, string, checks.AccountScanOptions) []alert.Finding {
		entered <- struct{}{}
		<-release
		return nil
	}
	ids := make([]string, 0, 9)
	id, err := m.Enqueue("account", "account", checks.AccountScanOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}
	ids = append(ids, id)
	<-entered
	for range scanJobQueueDepth {
		id, err := m.Enqueue("account", "account", checks.AccountScanOptions{}, false)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	for range 3 {
		if _, err := m.Enqueue("account", "excess", checks.AccountScanOptions{}, false); err == nil {
			t.Fatal("full queue accepted excess job")
		}
	}
	now := time.Now()
	s := scanJobHealthRow(t, m, "jobs", now.Add(31*time.Second))
	if s.Depth != 8 || s.InFlight != 1 || s.Capacity != 8 || s.DroppedTotal != 3 || s.Reason != "queue_full" {
		t.Fatalf("saturated job queue: %+v", s)
	}
	for _, id := range ids {
		if err := m.Cancel(id); err != nil {
			t.Fatal(err)
		}
	}
	finish()
	s = waitScanJobsEmpty(t, m)
	if s.DroppedTotal != 3 {
		t.Errorf("manual cancellation invented loss: %+v", s)
	}
	for _, id := range ids {
		waitForState(t, m, id, "canceled", time.Second)
	}
	s = scanJobHealthRow(t, m, "jobs", time.Now().Add(time.Minute))
	if s.Status != "ok" || s.DroppedTotal != 3 {
		t.Errorf("recovery erased cumulative evidence: %+v", s)
	}
	if len(entered) != 0 {
		t.Error("canceled queued jobs executed")
	}
}

type scanJobHealthDB struct {
	*store.DB
	put            func(store.ScanJobRecord) error
	get            func(string) (store.ScanJobRecord, bool, error)
	appendFindings func(string, int, []alert.Finding) error
	prune          func(int, int) (int, error)
}

func (db scanJobHealthDB) PutScanJob(rec store.ScanJobRecord) error { return db.put(rec) }

func (db scanJobHealthDB) GetScanJob(id string) (store.ScanJobRecord, bool, error) {
	if db.get != nil {
		return db.get(id)
	}
	return db.DB.GetScanJob(id)
}

func (db scanJobHealthDB) AppendScanJobFindings(id string, seq int, findings []alert.Finding) error {
	if db.appendFindings != nil {
		return db.appendFindings(id, seq, findings)
	}
	return db.DB.AppendScanJobFindings(id, seq, findings)
}

func (db scanJobHealthDB) PruneScanJobs(keep, count int) (int, error) {
	if db.prune != nil {
		return db.prune(keep, count)
	}
	return db.DB.PruneScanJobs(keep, count)
}

func TestScanJobQueueHealthStalledPersistence(t *testing.T) {
	for _, phase := range []string{"queued", "done"} {
		t.Run(phase, func(t *testing.T) {
			st, db := openTestScanJobStores(t)
			m, err := NewScanJobManager(st, &config.Config{})
			if err != nil {
				t.Fatal(err)
			}
			release := make(chan struct{})
			finish := sync.OnceFunc(func() { close(release) })
			defer func() { finish(); m.Stop() }()
			entered := make(chan struct{})
			m.db = scanJobHealthDB{DB: db, put: func(rec store.ScanJobRecord) error {
				if rec.State == phase {
					close(entered)
					<-release
					return errors.New("test persist failure")
				}
				return db.PutScanJob(rec)
			}}
			m.runAccountScan = func(context.Context, *config.Config, *state.Store, string, checks.AccountScanOptions) []alert.Finding {
				return nil
			}
			done := make(chan error, 1)
			go func() {
				_, enqueueErr := m.Enqueue("account", "account", checks.AccountScanOptions{}, false)
				done <- enqueueErr
			}()
			<-entered
			name := "jobs"
			if phase == "queued" {
				name = "admission"
			}
			s := scanJobHealthRow(t, m, name, time.Now().Add(61*time.Second))
			if s.InFlight != 1 || s.Depth != 0 || s.Reason != "processing_lag" || s.DroppedTotal != 0 {
				t.Errorf("blocked %s write: %+v", phase, s)
			}
			finish()
			err = <-done
			if (err != nil) != (phase == "queued") {
				t.Errorf("enqueue outcome changed: %v", err)
			}
			waitScanJobsEmpty(t, m)
			s = scanJobHealthRow(t, m, name, time.Now())
			if s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 1 {
				t.Errorf("failed %s write: %+v", phase, s)
			}
		})
	}
}

func TestScanJobQueueHealthAdmissionWaitsOutsideLock(t *testing.T) {
	st, _ := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	m.cancelMu.Lock()
	unlock := sync.OnceFunc(m.cancelMu.Unlock)
	defer unlock()
	done := make(chan error, 1)
	go func() {
		_, enqueueErr := m.Enqueue("account", "account", checks.AccountScanOptions{}, false)
		done <- enqueueErr
	}()
	deadline := time.Now().Add(time.Second)
	var s queuehealth.Status
	for time.Now().Before(deadline) {
		s = scanJobHealthRow(t, m, "admission", time.Now().Add(61*time.Second))
		if s.Depth == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	unlock()
	if s.Depth != 1 || s.InFlight != 0 || !s.CapacityUnavailable || s.Reason != "backlog_lag" {
		t.Errorf("unadmitted caller: %+v", s)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestScanJobQueueHealthInterruptedPersistedJobs(t *testing.T) {
	st, db := openTestScanJobStores(t)
	for _, job := range []store.ScanJobRecord{
		{ID: "queued-before-restart", State: "queued"},
		{ID: "running-before-restart", State: "running"},
		{ID: "finished-before-restart", State: "done"},
	} {
		if err := db.PutScanJob(job); err != nil {
			t.Fatal(err)
		}
	}
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	for _, id := range []string{"queued-before-restart", "running-before-restart"} {
		rec, ok := m.Progress(id)
		if !ok || rec.State != "error" || rec.Error != "daemon_restarted" {
			t.Errorf("abandoned persisted job %s: %+v", id, rec)
		}
	}
	s := scanJobHealthRow(t, m, "jobs", time.Now())
	if s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 2 {
		t.Errorf("restart evidence: %+v", s)
	}
}

func TestScanJobQueueHealthWorkerExit(t *testing.T) {
	for _, exit := range []string{"panic", "goexit"} {
		t.Run(exit, func(t *testing.T) {
			st, db := openTestScanJobStores(t)
			// Own the panic boundary: production obs.Go deliberately repanics.
			// Exercise the real worker and its cleanup without crashing the suite.
			m := &ScanJobManager{st: st, db: db, cfg: &config.Config{}, health: newScanJobHealth(),
				workCh: make(chan scanJobRequest, scanJobQueueDepth), stopCh: make(chan struct{}),
				workerDone: make(chan struct{}), cancelFns: make(map[string]context.CancelFunc)}
			entered, release := make(chan struct{}), make(chan struct{})
			finish := sync.OnceFunc(func() { close(release) })
			defer func() { finish(); m.Stop() }()
			m.runAccountScan = func(context.Context, *config.Config, *state.Store, string, checks.AccountScanOptions) []alert.Finding {
				close(entered)
				<-release
				if exit == "goexit" {
					runtime.Goexit()
				}
				panic("test scan worker failure")
			}
			boundaryDone := make(chan bool, 1)
			go func() {
				defer func() { boundaryDone <- recover() != nil }()
				m.worker()
			}()
			if _, err := m.Enqueue("account", "first", checks.AccountScanOptions{}, false); err != nil {
				t.Fatal(err)
			}
			<-entered
			for range 3 {
				if _, err := m.Enqueue("account", "waiting", checks.AccountScanOptions{}, false); err != nil {
					t.Fatal(err)
				}
			}
			finish()
			select {
			case <-m.workerDone:
			case <-time.After(time.Second):
				t.Fatal("worker did not exit")
			}
			if got := <-boundaryDone; got != (exit == "panic") {
				t.Errorf("worker failure policy changed: panic=%v", got)
			}
			s := scanJobHealthRow(t, m, "jobs", time.Now())
			if s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 4 || s.Reason != "dropped_work" {
				t.Errorf("abandoned jobs after %s: %+v", exit, s)
			}
			if _, err := m.Enqueue("account", "late", checks.AccountScanOptions{}, false); err == nil {
				t.Error("dead worker accepted a new job")
			}
		})
	}
}

func TestScanJobQueueHealthFollowsChildProgress(t *testing.T) {
	h := newScanJobHealth()
	child := checks.DispatchProgressSnapshot{}
	w := h.begin(func(time.Time) checks.DispatchProgressSnapshot { return child })
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	go func() { defer close(done); w.run(func() { close(entered); <-release }) }()
	<-entered
	waiting := h.begin(func(time.Time) checks.DispatchProgressSnapshot { return checks.DispatchProgressSnapshot{} })
	now := time.Now().Add(3 * time.Hour)
	child = checks.DispatchProgressSnapshot{Active: true, LastProgress: now}
	s := h.snapshot(now)
	if s.Status != "ok" || s.Depth != 1 || s.InFlight != 1 || s.ProcessingSeconds < (3*time.Hour-time.Second).Seconds() || s.LagSeconds != 0 {
		t.Errorf("long progressing scan: %+v", s)
	}
	child.Overdue = true
	s = h.snapshot(now)
	if s.Reason != "processing_lag" {
		t.Errorf("overdue child hidden by other progress: %+v", s)
	}
	child.Active, child.Overdue = false, false
	if s := h.snapshot(now.Add(59 * time.Second)); s.Status != "ok" {
		t.Errorf("new result phase: %+v", s)
	}
	if s := h.snapshot(now.Add(61 * time.Second)); s.Reason != "processing_lag" {
		t.Errorf("stalled result phase: %+v", s)
	}
	waiting.finish(true)
	finish()
	<-done
	if s := h.snapshot(time.Now()); s.Status != "ok" || s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 {
		t.Errorf("completed scan: %+v", s)
	}
}

func TestScanJobQueueHealthStopDrainsWithoutLoss(t *testing.T) {
	st, _ := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	entered := make(chan struct{})
	m.runAccountScan = func(ctx context.Context, _ *config.Config, _ *state.Store, _ string, _ checks.AccountScanOptions) []alert.Finding {
		close(entered)
		<-ctx.Done()
		return nil
	}
	ids := make([]string, 0, 9)
	id, err := m.Enqueue("account", "first", checks.AccountScanOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}
	ids = append(ids, id)
	<-entered
	for range 8 {
		id, err := m.Enqueue("account", "waiting", checks.AccountScanOptions{}, false)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	m.Stop()
	for _, id := range ids {
		waitForState(t, m, id, "canceled", time.Second)
	}
	if _, err := m.Enqueue("account", "late", checks.AccountScanOptions{}, false); err == nil {
		t.Error("stopped worker accepted work")
	}
	for _, name := range []string{"jobs", "admission"} {
		if s := scanJobHealthRow(t, m, name, time.Now()); s.Status != "ok" || s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 {
			t.Errorf("clean shutdown %s: %+v", name, s)
		}
	}
}

func TestScanJobQueueHealthRemediationProgress(t *testing.T) {
	_, db := openTestScanJobStores(t)
	m := &ScanJobManager{db: db}
	synctest.Test(t, func(t *testing.T) {
		h := newScanJobHealth()
		w := h.begin(func(time.Time) checks.DispatchProgressSnapshot { return checks.DispatchProgressSnapshot{} })
		req := scanJobRequest{id: "remediation-progress", work: w}
		calls := 0
		w.run(func() {
			written, truncated := m.persistFindings(req, 0, make([]alert.Finding, 4), func(f alert.Finding) alert.Finding {
				calls++
				time.Sleep(40 * time.Second)
				if s := h.snapshot(time.Now()); s.Status != "ok" || s.InFlight != 1 || s.DroppedTotal != 0 {
					t.Errorf("progressing action %d reported stalled: %+v", calls, s)
				}
				return f
			})
			if written != 4 || truncated || calls != 4 {
				t.Errorf("persistence changed: written=%d truncated=%v actions=%d", written, truncated, calls)
			}
		})
		if s := h.snapshot(time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 {
			t.Errorf("completed persistence: %+v", s)
		}
	})
}

func TestScanJobQueueHealthRejectedDemandIsNotProgress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newScanJobHealth()
		for range 8 {
			h.begin(func(time.Time) checks.DispatchProgressSnapshot { return checks.DispatchProgressSnapshot{} })
		}
		for range 3 {
			time.Sleep(30 * time.Second)
			w := h.begin(func(time.Time) checks.DispatchProgressSnapshot { return checks.DispatchProgressSnapshot{} })
			w.finish(false)
		}
		if s := h.snapshot(time.Now()); s.Depth != 8 || s.InFlight != 0 || s.LagSeconds != 90 || s.Reason != "backlog_lag" || s.DroppedTotal != 3 {
			t.Errorf("rejected producers concealed stalled dispatch: %+v", s)
		}
	})
}

func TestScanJobQueueHealthCountsFailedJobOnce(t *testing.T) {
	for _, phase := range []string{"read", "missing", "running", "findings", "terminal", "prune", "multiple"} {
		t.Run(phase, func(t *testing.T) {
			st, db := openTestScanJobStores(t)
			m, err := NewScanJobManager(st, &config.Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer m.Stop()
			failure := errors.New("test job store failure")
			injected := 0
			m.db = scanJobHealthDB{DB: db,
				get: func(id string) (store.ScanJobRecord, bool, error) {
					if phase == "read" {
						injected++
						return store.ScanJobRecord{}, false, failure
					}
					if phase == "missing" {
						injected++
						return store.ScanJobRecord{}, false, nil
					}
					return db.GetScanJob(id)
				},
				put: func(rec store.ScanJobRecord) error {
					if (rec.State == "running" && phase == "running") || (rec.State == "done" && (phase == "terminal" || phase == "multiple")) {
						injected++
						return failure
					}
					return db.PutScanJob(rec)
				},
				appendFindings: func(id string, seq int, findings []alert.Finding) error {
					if phase == "findings" || phase == "multiple" {
						injected++
						return failure
					}
					return db.AppendScanJobFindings(id, seq, findings)
				},
				prune: func(keep, count int) (int, error) {
					if phase == "prune" || phase == "multiple" {
						injected++
						return 0, failure
					}
					return db.PruneScanJobs(keep, count)
				},
			}
			m.runAccountScan = func(context.Context, *config.Config, *state.Store, string, checks.AccountScanOptions) []alert.Finding {
				return []alert.Finding{{Check: "test_result", Severity: alert.Warning}}
			}
			if _, err := m.Enqueue("account", "account", checks.AccountScanOptions{}, false); err != nil {
				t.Fatal(err)
			}
			s := waitScanJobsEmpty(t, m)
			wantFailures := 1
			if phase == "multiple" {
				wantFailures = 3
			}
			if injected != wantFailures || s.DroppedTotal != 1 {
				t.Errorf("failed operations=%d want %d; job evidence=%+v", injected, wantFailures, s)
			}
		})
	}
}
