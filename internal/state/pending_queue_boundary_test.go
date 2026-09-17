package state

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/atomicio"
)

func TestPendingQueueWriteReadback(t *testing.T) {
	for _, outcome := range []string{"old", "committed", "unreadable", "identical"} {
		t.Run(outcome, func(t *testing.T) {
			st, openErr := Open(t.TempDir())
			if openErr != nil {
				t.Fatal(openErr)
			}
			old := []alert.Finding{{Check: "fixture", Message: "old"}}
			if outcome == "identical" {
				old = make([]alert.Finding, pendingFindingsMax)
			}
			if err := st.AppendPendingFindings(old); err != nil {
				t.Fatal(err)
			}
			next := []alert.Finding{{Check: "fixture", Message: "new"}}
			if outcome == "identical" {
				next = []alert.Finding{{}}
			}
			st.writePendingFile = func(path string, perm os.FileMode, value any) error {
				if outcome == "committed" || outcome == "identical" {
					if err := atomicio.AtomicWriteJSON(path, perm, value); err != nil {
						return err
					}
				}
				if outcome == "unreadable" {
					st.readPendingFile = func(string) ([]byte, error) { return nil, errors.New("fixture unreadable") }
				}
				return errors.New("fixture write failed")
			}
			if err := st.AppendPendingFindings(next); err == nil {
				t.Fatal("write error was hidden")
			}
			row := pendingQueueStatus(t, st, time.Now())
			switch outcome {
			case "old":
				if row.Depth != 1 || row.DroppedTotal != 1 || row.DroppedLowerBound || row.DepthUnavailable {
					t.Fatalf("old file result: %+v", row)
				}
			case "committed":
				if row.Depth != 2 || row.DroppedTotal != 0 || row.DroppedLowerBound || row.DepthUnavailable {
					t.Fatalf("committed despite error result: %+v", row)
				}
			case "identical":
				if row.Depth != pendingFindingsMax || row.DroppedTotal != 1 || row.DroppedLowerBound || row.DepthUnavailable {
					t.Fatalf("identical occurrences lost their multiplicity: %+v", row)
				}
			case "unreadable":
				if !row.DepthUnavailable || !row.DroppedLowerBound || row.DroppedTotal != 0 {
					t.Fatalf("unreadable outcome invented exact evidence: %+v", row)
				}
			}
			if row.Reason != "state_io" || row.InFlight != 0 {
				t.Fatalf("failed storage outcome hidden: %+v", row)
			}
			st.readPendingFile = nil
			got, err := st.TakePendingFindings()
			if err != nil {
				t.Fatal(err)
			}
			want := len(old)
			if outcome == "committed" {
				want++
			}
			if len(got) != want {
				t.Fatalf("readback changed actual stored findings: got=%d want=%d", len(got), want)
			}
			row = pendingQueueStatus(t, st, time.Now().Add(2*time.Minute))
			if row.Depth != 0 || row.DepthUnavailable || row.DroppedLowerBound != (outcome == "unreadable") || row.Status != "ok" {
				t.Fatalf("read recovery: %+v", row)
			}
		})
	}
}

func TestPendingQueueBlockedWriteAndConcurrentAppend(t *testing.T) {
	st, openErr := Open(t.TempDir())
	if openErr != nil {
		t.Fatal(openErr)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 2)
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	outstanding := 0
	t.Cleanup(func() {
		unblock()
		for range outstanding {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("append cleanup did not join")
			}
		}
	})
	calls := 0
	st.writePendingFile = func(path string, perm os.FileMode, value any) error {
		calls++
		if calls == 1 {
			close(entered)
			<-release
		}
		return atomicio.AtomicWriteJSON(path, perm, value)
	}
	outstanding++
	go func() { done <- st.AppendPendingFindings([]alert.Finding{{Message: "first"}}) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first write did not start")
	}
	outstanding++
	go func() { done <- st.AppendPendingFindings([]alert.Finding{{Message: "second"}, {Message: "third"}}) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rows := st.QueueStatuses(time.Now().Add(2 * time.Minute))
		op := rows["pending_operations"]
		if op.Depth == 1 {
			if op.InFlight != 1 || op.CapacityUnavailable != true || op.Reason != "backlog_lag" {
				t.Fatalf("serialized operations lost ownership: %+v", op)
			}
			if row := rows["pending"]; row.Depth != 0 || row.InFlight != 3 || row.DroppedTotal != 0 {
				t.Fatalf("incoming findings vanished during blocked I/O: %+v", row)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("second append not admitted to operation health")
		}
		runtime.Gosched()
	}
	unblock()
	for range 2 {
		select {
		case err := <-done:
			outstanding--
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("append did not join")
		}
	}
	got, err := st.TakePendingFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Message != "first" || got[1].Message != "second" || got[2].Message != "third" {
		t.Fatal("concurrent append changed serialized file contents")
	}
	if row := pendingQueueStatus(t, st, time.Now()); row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 0 {
		t.Fatalf("completed append retained phantom ownership: %+v", row)
	}
}

func TestPendingQueueReplayOwnsDetachedBatch(t *testing.T) {
	for _, outcome := range []string{"return", "panic", "goexit"} {
		t.Run(outcome, func(t *testing.T) {
			st, openErr := Open(t.TempDir())
			if openErr != nil {
				t.Fatal(openErr)
			}
			if err := st.AppendPendingFindings([]alert.Finding{{Message: "first"}, {Message: "second"}}); err != nil {
				t.Fatal(err)
			}
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			t.Cleanup(func() {
				unblock()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("replay did not join")
				}
			})
			returned, panicked := false, false
			go func() {
				defer close(done)
				defer func() { panicked = recover() != nil }()
				err := st.ReplayPendingFindings(func(findings []alert.Finding) {
					if len(findings) != 2 || findings[0].Message != "first" || findings[1].Message != "second" {
						t.Error("replay received wrong durable batch")
					}
					close(entered)
					<-release
					if outcome == "panic" {
						panic("fixture replay interrupted")
					}
					if outcome == "goexit" {
						runtime.Goexit()
					}
				})
				if err != nil {
					t.Error(err)
				}
				returned = true
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("replay callback did not start")
			}
			if _, err := os.Stat(filepath.Join(st.path, pendingFindingsFile)); !os.IsNotExist(err) {
				t.Fatal("replay changed clear-before-dispatch policy")
			}
			row := pendingQueueStatus(t, st, time.Now().Add(2*time.Minute))
			if row.Depth != 0 || row.InFlight != 2 || row.DroppedTotal != 0 {
				t.Fatalf("detached findings disappeared during dispatch: %+v", row)
			}
			if op := st.QueueStatuses(time.Now().Add(2 * time.Minute))["pending_operations"]; op.InFlight != 1 || op.Reason != "processing_lag" {
				t.Fatalf("stalled replay hidden: %+v", op)
			}
			if err := st.AppendPendingFindings([]alert.Finding{{Message: "next"}}); err != nil {
				t.Fatal(err)
			}
			row = pendingQueueStatus(t, st, time.Now())
			if row.Depth != 1 || row.InFlight != 2 {
				t.Fatalf("replay consumed later append ownership: %+v", row)
			}
			unblock()
			<-done
			if returned != (outcome == "return") || panicked != (outcome == "panic") {
				t.Fatal("replay changed abnormal-exit policy")
			}
			row = pendingQueueStatus(t, st, time.Now())
			if row.Depth != 1 || row.InFlight != 0 || row.DroppedTotal != 0 || row.DroppedLowerBound != (outcome != "return") {
				t.Fatalf("partial replay outcome became false exact evidence: %+v", row)
			}
			got, err := st.TakePendingFindings()
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].Message != "next" {
				t.Fatal("interrupted replay changed later durable batch")
			}
		})
	}
}

func TestPendingQueueOverflowRetainsSurvivorAge(t *testing.T) {
	st, openErr := Open(t.TempDir())
	if openErr != nil {
		t.Fatal(openErr)
	}
	if err := st.AppendPendingFindings([]alert.Finding{{Message: "old"}}); err != nil {
		t.Fatal(err)
	}
	first := time.Now()
	next := make([]alert.Finding, pendingFindingsMax)
	if err := st.AppendPendingFindings(next); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(2 * time.Minute)
	row := pendingQueueStatus(t, st, now)
	if row.LagSeconds > now.Sub(first).Seconds() {
		t.Fatalf("evicted finding still determines backlog age: %+v", row)
	}
	if row.DroppedTotal != 1 || row.Depth != pendingFindingsMax {
		t.Fatalf("overflow result: %+v", row)
	}
}

func TestPendingQueueEncodingFailureHasKnownLoss(t *testing.T) {
	st, openErr := Open(t.TempDir())
	if openErr != nil {
		t.Fatal(openErr)
	}
	st.writePendingFile = func(path string, perm os.FileMode, value any) error {
		err := atomicio.AtomicWriteJSON(path, perm, value)
		st.readPendingFile = func(string) ([]byte, error) { return nil, errors.New("fixture read failed") }
		return err
	}
	invalid := alert.Finding{Timestamp: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}
	if err := st.AppendPendingFindings([]alert.Finding{invalid, invalid, invalid}); err == nil {
		t.Fatal("invalid timestamp encoded successfully")
	}
	row := pendingQueueStatus(t, st, time.Now())
	if row.DroppedTotal != 3 || !row.DepthUnavailable || !row.DroppedLowerBound {
		t.Fatalf("known unencodable findings lost behind readback uncertainty: %+v", row)
	}
}

func TestPendingQueueClearErrorReadsActualOutcome(t *testing.T) {
	for _, removed := range []bool{false, true} {
		t.Run(map[bool]string{false: "retained", true: "removed"}[removed], func(t *testing.T) {
			st, openErr := Open(t.TempDir())
			if openErr != nil {
				t.Fatal(openErr)
			}
			if err := st.AppendPendingFindings([]alert.Finding{{Message: "one"}, {Message: "two"}}); err != nil {
				t.Fatal(err)
			}
			previous := removePendingFindingsFile
			t.Cleanup(func() { removePendingFindingsFile = previous })
			removePendingFindingsFile = func(path string) error {
				if removed {
					if err := os.Remove(path); err != nil {
						return err
					}
				}
				return errors.New("fixture clear failed")
			}
			called := false
			if err := st.ReplayPendingFindings(func([]alert.Finding) { called = true }); err == nil || called {
				t.Fatal("failed clear changed replay policy")
			}
			row := pendingQueueStatus(t, st, time.Now())
			wantDepth, wantLoss := 2, uint64(0)
			if removed {
				wantDepth, wantLoss = 0, 2
			}
			if row.Depth != wantDepth || row.DroppedTotal != wantLoss || row.InFlight != 0 || row.DroppedLowerBound || row.DepthUnavailable || row.Reason != "state_io" {
				t.Fatalf("clear result: %+v", row)
			}
		})
	}
}

func TestPendingQueueInterruptedWriteKeepsKnownOverflow(t *testing.T) {
	for _, outcome := range []string{"panic", "goexit"} {
		t.Run(outcome, func(t *testing.T) {
			st, openErr := Open(t.TempDir())
			if openErr != nil {
				t.Fatal(openErr)
			}
			st.writePendingFile = func(string, os.FileMode, any) error {
				if outcome == "panic" {
					panic("fixture writer interrupted")
				}
				runtime.Goexit()
				return nil
			}
			done := make(chan struct{})
			returned, panicked := false, false
			go func() {
				defer close(done)
				defer func() { panicked = recover() != nil }()
				_ = st.AppendPendingFindings(make([]alert.Finding, pendingFindingsMax+3))
				returned = true
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("interrupted writer did not join")
			}
			if returned || panicked != (outcome == "panic") {
				t.Fatal("abnormal write policy changed")
			}
			row := pendingQueueStatus(t, st, time.Now())
			if row.InFlight != 0 || row.DroppedTotal != 3 || !row.DepthUnavailable || !row.DroppedLowerBound || row.Reason != "persistence_uncertain" {
				t.Fatalf("interrupted write hid known overflow or invented exact outcome: %+v", row)
			}
			st.writePendingFile = nil
			if err := st.AppendPendingFindings([]alert.Finding{{Message: "recovered"}}); err != nil {
				t.Fatal(err)
			}
			got, err := st.TakePendingFindings()
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].Message != "recovered" {
				t.Fatal("interrupted write retained state lock or changed recovery")
			}
		})
	}
}
