package worker

import (
	"bytes"
	"errors"
	"strings"
	"testing"

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

func freeLock(mutate func() error) error { return mutate() }

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
		len(tr.applied) != 1 || tr.applied[0] != want || tr.removed != 0 {
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

// A bad request is refused before the lock is taken or anything runs.
func TestHandleRejectsBadRequestBeforeSideEffects(t *testing.T) {
	for name, body := range map[string]string{
		"invalid":   `{"operation":"remove","path":"/etc/exim.conf"}`,
		"oversized": `{"operation":"remove"}` + strings.Repeat(" ", 10<<20),
	} {
		t.Run(name, func(t *testing.T) {
			tr := &fakeTransactor{result: antispam.Result{OK: true}}
			locked := 0
			result, code := run(t, body, tr, func(m func() error) error { locked++; return m() })
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
	result, code := run(t, applyBody, tr, func(m func() error) error { return eximlock.With(dir, m) })
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
	result, code := run(t, `{"operation":"remove"}`, tr, func(func() error) error { return errors.New("read-only file system") })
	if code != 1 || result.Busy || result.FailedStep != "lock" || tr.removed != 0 {
		t.Fatalf("code=%d result=%+v", code, result)
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
