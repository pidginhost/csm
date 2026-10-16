package worker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/eximlock"
)

type fakeTransactor struct {
	applied []antispam.Settings
	removed int
	result  antispam.Result
}

func (f *fakeTransactor) Apply(s antispam.Settings) antispam.Result {
	f.applied = append(f.applied, s)
	return f.result
}

func (f *fakeTransactor) Remove() antispam.Result {
	f.removed++
	return f.result
}

func freeLock(_ []byte, mutate func() error) error { return mutate() }

const applyBody = `{"operation":"apply","enabled":true,"dry_run":true,"rspamd_socket":"/run/rspamd/csm-normal.sock","reject_score":15,"tag_score":6}`

func run(t *testing.T, body string, tr Transactor, lock Locker) (antispam.Result, int) {
	t.Helper()
	var out bytes.Buffer
	code := Handle(strings.NewReader(body), &out, tr, lock)
	if strings.Count(out.String(), "\n") != 1 || !strings.HasSuffix(out.String(), "\n") {
		t.Fatalf("output is not one line: %q", out.String())
	}
	result, err := antispam.ParseResult(out.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return result, code
}

func TestHandleRunsApplyWithValidatedSettings(t *testing.T) {
	tr := &fakeTransactor{result: antispam.Result{OK: true, Generation: "g1"}}
	result, code := run(t, applyBody, tr, freeLock)
	want := antispam.Settings{DryRun: true, Socket: antispam.DefaultSocket, RejectScore: 15, TagScore: 6}
	if code != 0 || !result.OK || result.Operation != antispam.OpApply || result.Generation != "g1" ||
		len(tr.applied) != 1 || !reflect.DeepEqual(tr.applied[0], want) || tr.removed != 0 {
		t.Fatalf("code=%d result=%+v transactor=%+v", code, result, tr)
	}
}

func TestHandleRunsRemove(t *testing.T) {
	tr := &fakeTransactor{result: antispam.Result{OK: true}}
	result, code := run(t, `{"operation":"remove"}`, tr, freeLock)
	if code != 0 || !result.OK || result.Operation != antispam.OpRemove || tr.removed != 1 || len(tr.applied) != 0 {
		t.Fatalf("code=%d result=%+v transactor=%+v", code, result, tr)
	}
}

func TestHandleReportsTransactionFailure(t *testing.T) {
	tr := &fakeTransactor{result: antispam.Result{FailedStep: "buildeximconf", Rollback: antispam.RollbackVerified, Error: "exit status 1"}}
	result, code := run(t, `{"operation":"remove"}`, tr, freeLock)
	if code != 1 || result.OK || result.FailedStep != "buildeximconf" || result.Rollback != antispam.RollbackVerified || result.Operation != antispam.OpRemove {
		t.Fatalf("code=%d result=%+v", code, result)
	}
}

func TestHandleRunsTransactionsBeforeReleasingLock(t *testing.T) {
	for name, body := range map[string]string{"apply": applyBody, "remove": `{"operation":"remove"}`} {
		for outcome, want := range map[string]antispam.Result{
			"success": {OK: true},
			"failure": {FailedStep: "reload", Rollback: antispam.RollbackVerified, Error: "reload failed"},
		} {
			t.Run(name+"/"+outcome, func(t *testing.T) {
				if want.OK && name == antispam.OpApply {
					want.Generation = "g1"
				}
				dir := t.TempDir()
				tr := &fakeTransactor{result: want}
				locked := 0
				result, code := run(t, body, tr, func(_ []byte, mutate func() error) error {
					locked++
					return eximlock.With(dir, func() error {
						if len(tr.applied)+tr.removed != 0 {
							t.Fatal("transaction ran before acquiring the lock")
						}
						err := mutate()
						if len(tr.applied)+tr.removed != 1 {
							t.Fatal("transaction did not finish while holding the lock")
						}
						return err
					})
				})
				want.Operation = name
				wantCode := 1
				if want.OK {
					wantCode = 0
				}
				if result != want || code != wantCode || locked != 1 {
					t.Fatalf("code=%d result=%+v locked=%d, want code=%d result=%+v locked=1", code, result, locked, wantCode, want)
				}
				if err := eximlock.With(dir, func() error { return nil }); err != nil {
					t.Fatalf("lock not released: %v", err)
				}
			})
		}
	}
}

func TestHandleRejectsReadFailureBeforeSideEffects(t *testing.T) {
	tr := &fakeTransactor{result: antispam.Result{OK: true}}
	locked := 0
	input := io.MultiReader(strings.NewReader(`{"operation":"remove"}`), iotest.ErrReader(errors.New("reader failure details")))
	var out bytes.Buffer
	code := Handle(input, &out, tr, func(_ []byte, mutate func() error) error { locked++; return mutate() })
	result, err := antispam.ParseResult(out.Bytes())
	want := antispam.Result{FailedStep: "request", Rollback: antispam.RollbackNone, Error: "cannot read request"}
	if err != nil || result != want || code != 1 || locked != 0 || tr.removed != 0 || len(tr.applied) != 0 {
		t.Fatalf("code=%d result=%+v err=%v locked=%d transactor=%+v", code, result, err, locked, tr)
	}
	if strings.Count(out.String(), "\n") != 1 || !strings.HasSuffix(out.String(), "\n") {
		t.Fatalf("output is not one line: %q", out.String())
	}
}

// A bad request is refused before the lock is taken or anything runs.
func TestHandleRejectsBadRequestBeforeSideEffects(t *testing.T) {
	for name, body := range map[string]string{
		"invalid":   `{"operation":"remove","path":"/etc/exim.conf"}`,
		"oversized": `{"operation":"remove"}` + strings.Repeat(" ", 10<<20),
	} {
		t.Run(name, func(t *testing.T) {
			tr := &fakeTransactor{result: antispam.Result{OK: true}}
			locked := 0
			result, code := run(t, body, tr, func(_ []byte, m func() error) error { locked++; return m() })
			if code != 1 || result.OK || result.FailedStep != "request" || result.Rollback != antispam.RollbackNone ||
				locked != 0 || tr.removed != 0 || len(tr.applied) != 0 {
				t.Fatalf("code=%d result=%+v locked=%d transactor=%+v", code, result, locked, tr)
			}
		})
	}
}

// While forward guard holds the shared lock, the worker reports busy and
// runs nothing; the daemon retries.
func TestHandleReportsBusyLock(t *testing.T) {
	dir := t.TempDir()
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() { finished <- eximlock.With(dir, func() error { close(entered); <-release; return nil }) }()
	<-entered
	tr := &fakeTransactor{result: antispam.Result{OK: true}}
	result, code := run(t, applyBody, tr, Lock(dir))
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if code != 1 || result.OK || !result.Busy || result.FailedStep != "lock" || result.Rollback != antispam.RollbackNone ||
		result.Operation != antispam.OpApply || len(tr.applied) != 0 {
		t.Fatalf("code=%d result=%+v transactor=%+v", code, result, tr)
	}
}

func TestHandleReportsLockSetupFailureAsNotBusy(t *testing.T) {
	tr := &fakeTransactor{result: antispam.Result{OK: true}}
	result, code := run(t, `{"operation":"remove"}`, tr, func([]byte, func() error) error { return errors.New("read-only file system") })
	if code != 1 || result.Busy || result.FailedStep != "lock" || tr.removed != 0 {
		t.Fatalf("code=%d result=%+v", code, result)
	}
}

func TestHandleKeepsResultErrorsOnOneLine(t *testing.T) {
	for _, source := range []string{"lock", "busy", "transaction"} {
		t.Run(source, func(t *testing.T) {
			message := "first\r\nsecond\rthird\nfourth"
			want := antispam.Result{Operation: antispam.OpRemove, FailedStep: "lock", Rollback: antispam.RollbackNone,
				Error: "first; second; third; fourth"}
			tr := &fakeTransactor{}
			lock := func([]byte, func() error) error { return errors.New(message) }
			switch source {
			case "busy":
				lock = func([]byte, func() error) error { return errors.Join(eximlock.ErrBusy, errors.New(message)) }
				want.Busy = true
				want.Error = eximlock.ErrBusy.Error() + "; " + want.Error
			case "transaction":
				tr.result = antispam.Result{FailedStep: "exim_build", Rollback: antispam.RollbackFailed, Error: message}
				lock = freeLock
				want.FailedStep, want.Rollback = tr.result.FailedStep, tr.result.Rollback
			}
			result, code := run(t, `{"operation":"remove"}`, tr, lock)
			if code != 1 || result != want {
				t.Errorf("code=%d result=%+v, want code=1 result=%+v", code, result, want)
			}
			wantRemoved := 0
			if source == "transaction" {
				wantRemoved = 1
			}
			if tr.removed != wantRemoved || len(tr.applied) != 0 {
				t.Errorf("transactor=%+v, want %d removals and no applies", tr, wantRemoved)
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestHandleFailsWhenResultCannotBeWritten(t *testing.T) {
	tr := &fakeTransactor{result: antispam.Result{OK: true}}
	if code := Handle(strings.NewReader(`{"operation":"remove"}`), failingWriter{}, tr, freeLock); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
}

type shortWriter struct {
	bytes.Buffer
}

func (w *shortWriter) Write(data []byte) (int, error) {
	return w.Buffer.Write(data[:len(data)-1])
}

func TestHandleFailsWhenResultWriteIsShort(t *testing.T) {
	tr := &fakeTransactor{result: antispam.Result{OK: true}}
	var out shortWriter
	code := Handle(strings.NewReader(`{"operation":"remove"}`), &out, tr, freeLock)
	if code != 1 {
		t.Fatalf("code=%d for incomplete reply %q, want 1", code, out.String())
	}
	if tr.removed != 1 || len(tr.applied) != 0 {
		t.Fatalf("transactor=%+v, want exactly one removal", tr)
	}
}

func TestHandleRejectsInvalidTransactorResult(t *testing.T) {
	for name, bad := range map[string]antispam.Result{
		"apply without generation": {OK: true},
		"failure without step":     {Rollback: antispam.RollbackNone},
		"unknown rollback":         {FailedStep: "exim_build", Rollback: "maybe"},
	} {
		result, code := run(t, applyBody, &fakeTransactor{result: bad}, freeLock)
		if code != 1 || result.OK || result.FailedStep != "result" || result.Rollback != antispam.RollbackFailed || result.Operation != antispam.OpApply {
			t.Errorf("%s: code=%d result=%+v", name, code, result)
		}
	}
}

// A request the daemon replaced before this worker reached the lock is busy,
// not failed, and runs no transaction.
func TestHandleReportsASupersededRequestAsBusy(t *testing.T) {
	tr := &fakeTransactor{result: antispam.Result{OK: true}}
	result, code := run(t, `{"operation":"remove"}`, tr, func([]byte, func() error) error { return errSuperseded })
	if code != 1 || result.OK || !result.Busy || result.FailedStep != "lock" || result.Rollback != antispam.RollbackNone || tr.removed != 0 {
		t.Fatalf("code=%d result=%+v transactor=%+v", code, result, tr)
	}
}

// Lock runs a request under the shared lock, and only while it is the latest
// one recorded. A missing record comes from a daemon that predates it.
func TestLockRunsOnlyTheLatestRequest(t *testing.T) {
	dir := t.TempDir()
	lock := Lock(dir)
	ran := 0
	mutate := func() error { ran++; return nil }
	older, latest := []byte(`{"operation":"remove"}`), []byte(applyBody)
	if err := lock(older, mutate); err != nil || ran != 1 {
		t.Fatalf("without a record: err=%v ran=%d", err, ran)
	}
	for _, body := range [][]byte{older, latest} {
		if recorded, err := recordRequest(context.Background(), dir, body); err != nil || !recorded {
			t.Fatalf("record: recorded=%v err=%v", recorded, err)
		}
	}
	if err := lock(older, mutate); !errors.Is(err, errSuperseded) || ran != 1 {
		t.Fatalf("replaced request: err=%v ran=%d", err, ran)
	}
	if err := lock(latest, mutate); err != nil || ran != 2 {
		t.Fatalf("latest request: err=%v ran=%d", err, ran)
	}
}

// Recording takes the shared lock too: while another transaction holds it,
// nothing is recorded and the caller learns it is busy.
func TestRecordRequestWaitsForNoTransaction(t *testing.T) {
	dir := t.TempDir()
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() { finished <- eximlock.With(dir, func() error { close(entered); <-release; return nil }) }()
	<-entered
	recorded, err := recordRequest(context.Background(), dir, []byte(applyBody))
	close(release)
	if lockErr := <-finished; lockErr != nil {
		t.Fatal(lockErr)
	}
	if recorded || err != nil {
		t.Fatalf("recorded=%v err=%v, want busy", recorded, err)
	}
	if _, err := os.Stat(filepath.Join(dir, RequestFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("busy record wrote the file: %v", err)
	}
}

// A worker started before a daemon restart reaches the lock after the new
// daemon recorded its own request. It runs no transaction and reports busy;
// the newer request still runs.
func TestStaleRequestFromBeforeARestartChangesNothing(t *testing.T) {
	dir := t.TempDir()
	older, latest := []byte(applyBody), []byte(`{"operation":"remove"}`)
	for _, body := range [][]byte{older, latest} {
		if recorded, err := recordRequest(context.Background(), dir, body); err != nil || !recorded {
			t.Fatalf("record: recorded=%v err=%v", recorded, err)
		}
	}
	tr := &fakeTransactor{result: antispam.Result{OK: true}}
	result, code := run(t, string(older), tr, Lock(dir))
	if code != 1 || !result.Busy || len(tr.applied) != 0 || tr.removed != 0 {
		t.Fatalf("stale request: code=%d result=%+v transactor=%+v", code, result, tr)
	}
	result, code = run(t, string(latest), tr, Lock(dir))
	if code != 0 || !result.OK || tr.removed != 1 {
		t.Fatalf("latest request: code=%d result=%+v transactor=%+v", code, result, tr)
	}
}

// The worker waits out a brief hold by the daemon's record writer instead of
// reporting busy.
func TestLockWaitsOutABriefHolder(t *testing.T) {
	dir := t.TempDir()
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() { finished <- eximlock.With(dir, func() error { close(entered); <-release; return nil }) }()
	<-entered
	time.AfterFunc(50*time.Millisecond, func() { close(release) })
	ran := 0
	err := Lock(dir)([]byte(applyBody), func() error { ran++; return nil })
	if lockErr := <-finished; lockErr != nil {
		t.Fatal(lockErr)
	}
	if err != nil || ran != 1 {
		t.Fatalf("err=%v ran=%d", err, ran)
	}
}
