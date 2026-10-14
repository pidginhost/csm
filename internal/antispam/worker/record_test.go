package worker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/reconcile"
	"github.com/pidginhost/csm/internal/eximlock"
)

// A restarted daemon can need no transaction at all. That decision must
// still stop an older worker that has not acquired the lock yet.
func TestReconcileWithoutWorkerSupersedesPendingRequest(t *testing.T) {
	for _, observe := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled and absent", true: "observe"}[observe], func(t *testing.T) {
			dir := t.TempDir()
			prev := requestDir
			requestDir = dir
			t.Cleanup(func() { requestDir = prev })
			if recorded, err := recordRequest(context.Background(), dir, []byte(applyBody)); err != nil || !recorded {
				t.Fatalf("recorded=%v err=%v", recorded, err)
			}
			r := reconcile.Reconciler{
				Invalidate: Invalidate,
				Installed: func() antispam.HostFacts {
					if err := Lock(dir)([]byte(applyBody), func() error {
						t.Fatal("stale worker was still authorized when host read began")
						return nil
					}); !errors.Is(err, errSuperseded) {
						t.Fatalf("stale worker at host read: %v", err)
					}
					return antispam.HostFacts{Record: antispam.RecordFacts{Missing: !observe}}
				},
				Run: func(context.Context, antispam.Request) (antispam.Result, error) {
					t.Fatal("pass launched an unnecessary worker")
					return antispam.Result{}, nil
				},
				Now: time.Now,
			}
			if out := r.Pass(context.Background(), reconcile.Desired{Observe: observe}); out.Err != nil || out.Retry != 0 {
				t.Fatalf("outcome=%+v", out)
			}
			tr := &fakeTransactor{result: antispam.Result{OK: true, Generation: "old"}}
			result, code := run(t, applyBody, tr, Lock(dir))
			if code != 1 || !result.Busy || len(tr.applied) != 0 || tr.removed != 0 {
				t.Fatalf("stale worker: code=%d result=%+v transactor=%+v", code, result, tr)
			}
		})
	}
}

func TestInvalidateWaitsForActiveTransaction(t *testing.T) {
	prev := requestDir
	requestDir = t.TempDir()
	t.Cleanup(func() { requestDir = prev })
	older := []byte(applyBody)
	if recorded, err := recordRequest(context.Background(), requestDir, older); err != nil || !recorded {
		t.Fatalf("recorded=%v err=%v", recorded, err)
	}
	lock := Lock(requestDir)
	if err := lock(older, func() error {
		if err := Invalidate(context.Background()); !errors.Is(err, eximlock.ErrBusy) {
			t.Fatalf("invalidation interrupted an active transaction: %v", err)
		}
		// The running transaction already checked its request; the
		// cancellation lands at once for every worker that checks later.
		got, err := os.ReadFile(filepath.Join(requestDir, RequestFile))
		if err != nil || string(got) != "null" {
			t.Fatalf("busy invalidation did not cancel: record %q: %v", got, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := Invalidate(context.Background()); err != nil {
		t.Fatal(err)
	}
	ran := 0
	mutate := func() error { ran++; return nil }
	if err := lock(older, mutate); !errors.Is(err, errSuperseded) || ran != 0 {
		t.Fatalf("invalidated worker: err=%v ran=%d", err, ran)
	}
	latest := []byte(`{"operation":"remove"}`)
	if recorded, err := recordRequest(context.Background(), requestDir, latest); err != nil || !recorded {
		t.Fatalf("recorded=%v err=%v", recorded, err)
	}
	if err := lock(latest, mutate); err != nil || ran != 1 {
		t.Fatalf("latest worker: err=%v ran=%d", err, ran)
	}
}

// Limit writes in a child process so a real partial write cannot corrupt
// other tests or their fixtures.
func TestRecordRequestPreservesPreviousOnWriteFailure(t *testing.T) {
	if os.Getenv("CSM_ANTISPAM_TEST_LIMIT_WRITE") != "1" {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(self, "-test.run=^TestRecordRequestPreservesPreviousOnWriteFailure$")
		cmd.Env = append(os.Environ(), "CSM_ANTISPAM_TEST_LIMIT_WRITE=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("limited writer: %v\n%s", err, out)
		}
		return
	}
	dir := t.TempDir()
	previous := []byte(applyBody)
	if recorded, err := recordRequest(context.Background(), dir, previous); err != nil || !recorded {
		t.Fatalf("recorded=%v err=%v", recorded, err)
	}
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
		t.Fatal(err)
	}
	limited := limit
	limited.Cur = 1
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limited); err != nil {
		t.Fatal(err)
	}
	recorded, err := recordRequest(context.Background(), dir, []byte(`{"operation":"remove"}`))
	if restoreErr := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit); restoreErr != nil {
		t.Fatal(restoreErr)
	}
	if recorded || !errors.Is(err, syscall.EFBIG) {
		t.Fatalf("limited write: recorded=%v err=%v", recorded, err)
	}
	got, err := os.ReadFile(filepath.Join(dir, RequestFile))
	if err != nil || !bytes.Equal(got, previous) {
		t.Fatalf("failed write replaced previous request with %q: %v", got, err)
	}
}

// Run and Invalidate record from the daemon. A brief hold by the daemon's
// other record writer must not turn into a busy retry.
func TestRecordRequestWaitsOutABriefHolder(t *testing.T) {
	dir := t.TempDir()
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() { finished <- eximlock.With(dir, func() error { close(entered); <-release; return nil }) }()
	<-entered
	time.AfterFunc(50*time.Millisecond, func() { close(release) })
	recorded, err := recordRequest(context.Background(), dir, []byte(applyBody))
	if lockErr := <-finished; lockErr != nil {
		t.Fatal(lockErr)
	}
	if !recorded || err != nil {
		t.Fatalf("recorded=%v err=%v", recorded, err)
	}
}

// A pass that meets a running transaction cancels pending workers at once,
// without waiting for the lock, and reports busy before it reads the host.
// A pass already canceled at shutdown writes nothing.
func TestPassDuringTransactionCancelsAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		prev := requestDir
		requestDir = t.TempDir()
		defer func() { requestDir = prev }()
		previous := []byte(applyBody)
		if recorded, err := recordRequest(context.Background(), requestDir, previous); err != nil || !recorded {
			t.Fatalf("recorded=%v err=%v", recorded, err)
		}
		reads := 0
		r := reconcile.Reconciler{
			Invalidate: Invalidate,
			Installed:  func() antispam.HostFacts { reads++; return antispam.HostFacts{} },
			Now:        time.Now,
		}
		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		if out := r.Pass(canceled, reconcile.Desired{}); !errors.Is(out.Err, context.Canceled) || reads != 0 {
			t.Fatalf("canceled pass: outcome=%+v reads=%d", out, reads)
		}
		if got, err := os.ReadFile(filepath.Join(requestDir, RequestFile)); err != nil || !bytes.Equal(got, previous) {
			t.Fatalf("canceled pass replaced the record with %q: %v", got, err)
		}
		var out reconcile.Outcome
		if err := eximlock.With(requestDir, func() error {
			finished := make(chan struct{})
			go func() {
				out = r.Pass(context.Background(), reconcile.Desired{})
				close(finished)
			}()
			synctest.Wait()
			if got, err := os.ReadFile(filepath.Join(requestDir, RequestFile)); err != nil || string(got) != "null" {
				t.Errorf("pass waited for the lock to cancel pending workers: record=%q err=%v", got, err)
			}
			if reads != 0 {
				t.Error("pass read the host during a transaction")
			}
			time.Sleep(eximlock.RecordWait)
			synctest.Wait()
			select {
			case <-finished:
			default:
				t.Error("pass waited past the lock retry deadline")
			}
			<-finished
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if out.Err != nil || out.Retry != reconcile.BusyRetry || len(out.Findings) != 0 || len(out.Checks) != 0 || reads != 0 {
			t.Errorf("pass during a transaction: outcome=%+v reads=%d", out, reads)
		}
		if got, err := os.ReadFile(filepath.Join(requestDir, RequestFile)); err != nil || string(got) != "null" {
			t.Errorf("pass during a transaction left the record %q: %v", got, err)
		}
	})
}

// Writing and flushing the record can take long on a busy disk. That work
// happens before the lock is taken, so the shared lock is held only for the
// rename that publishes the record.
func TestRecordRequestHoldsTheLockOnlyToPublish(t *testing.T) {
	dir := t.TempDir()
	prev := stageRecord
	t.Cleanup(func() { stageRecord = prev })
	staged := 0
	stageRecord = func(path string, body []byte) (string, error) {
		staged++
		if err := eximlock.With(dir, func() error { return nil }); err != nil {
			t.Errorf("lock held while staging the record: %v", err)
		}
		return prev(path, body)
	}
	recorded, err := recordRequest(context.Background(), dir, []byte(applyBody))
	got, readErr := os.ReadFile(filepath.Join(dir, RequestFile))
	if !recorded || err != nil || staged != 1 || readErr != nil || string(got) != applyBody {
		t.Fatalf("recorded=%v err=%v staged=%d record=%q (%v)", recorded, err, staged, got, readErr)
	}
}

// The first record on a host creates the lock directory, as the lock does.
func TestRecordRequestCreatesItsDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "forward_guard")
	recorded, err := recordRequest(context.Background(), dir, []byte(applyBody))
	got, readErr := os.ReadFile(filepath.Join(dir, RequestFile))
	if !recorded || err != nil || readErr != nil || string(got) != applyBody {
		t.Fatalf("recorded=%v err=%v record=%q (%v)", recorded, err, got, readErr)
	}
}

// A record that loses the race for the lock leaves no staged file behind.
func TestRecordRequestRemovesAnUnpublishedStage(t *testing.T) {
	dir := t.TempDir()
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() { finished <- eximlock.With(dir, func() error { close(entered); <-release; return nil }) }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prev := stageRecord
	t.Cleanup(func() { stageRecord = prev })
	staged := 0
	stageRecord = func(path string, body []byte) (string, error) {
		tmp, err := prev(path, body)
		staged++
		cancel()
		return tmp, err
	}
	recorded, err := recordRequest(ctx, dir, []byte(applyBody))
	close(release)
	if lockErr := <-finished; lockErr != nil {
		t.Fatal(lockErr)
	}
	entries, readErr := os.ReadDir(dir)
	if recorded || !errors.Is(err, context.Canceled) || readErr != nil || staged != 1 {
		t.Fatalf("recorded=%v err=%v readErr=%v staged=%d", recorded, err, readErr, staged)
	}
	for _, e := range entries {
		if e.Name() != "mutation.lock" {
			t.Fatalf("left %s behind", e.Name())
		}
	}
}

func TestRecordRequestCanceledBeforeStaging(t *testing.T) {
	for _, name := range []string{"missing directory", "invalid directory"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "requests")
			if name == "invalid directory" {
				if err := os.WriteFile(dir, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			prev := stageRecord
			t.Cleanup(func() { stageRecord = prev })
			staged := 0
			stageRecord = func(path string, body []byte) (string, error) {
				staged++
				return prev(path, body)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			recorded, err := recordRequest(ctx, dir, []byte(applyBody))
			if recorded || !errors.Is(err, context.Canceled) || staged != 0 {
				t.Errorf("recorded=%v err=%v staged=%d", recorded, err, staged)
			}
			if name == "missing directory" {
				if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("canceled request created its directory: %v", err)
				}
			}
		})
	}
}

// A stale worker waits up to RecordWait for a busy lock. Cancellation must
// not wait behind the same holder: when the holder releases, the waiting
// worker must find the cancellation, not its own request.
func TestInvalidateLandsBeforeAWaitingStaleWorker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		prev := requestDir
		requestDir = t.TempDir()
		defer func() { requestDir = prev }()
		older := []byte(applyBody)
		if recorded, err := recordRequest(context.Background(), requestDir, older); err != nil || !recorded {
			t.Fatalf("recorded=%v err=%v", recorded, err)
		}
		ran := 0
		stale, invalidated := make(chan error, 1), make(chan error, 1)
		if err := eximlock.With(requestDir, func() error {
			go func() { stale <- Lock(requestDir)(older, func() error { ran++; return nil }) }()
			synctest.Wait()
			go func() { invalidated <- Invalidate(context.Background()) }()
			synctest.Wait()
			if got, err := os.ReadFile(filepath.Join(requestDir, RequestFile)); err != nil || string(got) != "null" {
				t.Errorf("busy invalidation did not cancel: record=%q err=%v", got, err)
			}
			time.Sleep(50 * time.Millisecond)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := <-invalidated; err != nil {
			t.Errorf("invalidation after the lock released: %v", err)
		}
		if err := <-stale; !errors.Is(err, errSuperseded) || ran != 0 {
			t.Fatalf("stale worker after a busy cancellation: err=%v ran=%d", err, ran)
		}
	})
}
