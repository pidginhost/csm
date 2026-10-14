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
		got, err := os.ReadFile(filepath.Join(requestDir, RequestFile))
		if err != nil || !bytes.Equal(got, older) {
			t.Fatalf("busy invalidation replaced active request with %q: %v", got, err)
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

func TestPassCanceledDuringInvalidationPreservesPendingRequest(t *testing.T) {
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
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		finished := make(chan struct{})
		var out reconcile.Outcome
		if err := eximlock.With(requestDir, func() error {
			go func() {
				out = r.Pass(ctx, reconcile.Desired{})
				close(finished)
			}()
			synctest.Wait()
			cancel()
			synctest.Wait()
			select {
			case <-finished:
			default:
				t.Error("canceled pass still waits to invalidate")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		<-finished
		if !errors.Is(out.Err, context.Canceled) || len(out.Findings) != 0 || len(out.Checks) != 0 || out.Retry != 0 || reads != 0 {
			t.Errorf("canceled pass: outcome=%+v reads=%d", out, reads)
		}
		got, err := os.ReadFile(filepath.Join(requestDir, RequestFile))
		if err != nil || !bytes.Equal(got, previous) {
			t.Errorf("canceled pass invalidated pending request with %q: %v", got, err)
		}
	})
}
