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
)

type pendingReadError struct {
	entered, release chan struct{}
	once             sync.Once
}

func (e *pendingReadError) Error() string {
	e.once.Do(func() { close(e.entered) })
	<-e.release
	return "fixture read failure"
}

func TestPendingQueueReadFailureVisibleBeforeFormatting(t *testing.T) {
	st, openErr := Open(t.TempDir())
	if openErr != nil {
		t.Fatal(openErr)
	}
	fault := &pendingReadError{entered: make(chan struct{}), release: make(chan struct{})}
	st.readPendingFile = func(string) ([]byte, error) { return nil, fault }
	done := make(chan error, 1)
	var once sync.Once
	unblock := func() { once.Do(func() { close(fault.release) }) }
	joined := false
	t.Cleanup(func() {
		unblock()
		if !joined {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("read failure did not join")
			}
		}
	})
	go func() { done <- st.AppendPendingFindings(make([]alert.Finding, 3)) }()
	select {
	case <-fault.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("error formatting not entered")
	}
	row := pendingQueueStatus(t, st, time.Now())
	if row.DroppedTotal != 3 || !row.DepthUnavailable || !row.DroppedLowerBound || row.Reason != "state_io" {
		t.Errorf("returned read failure hidden during formatting: %+v", row)
	}
	if op := st.QueueStatuses(time.Now())["pending_operations"]; op.InFlight != 1 {
		t.Errorf("formatting operation lost ownership: %+v", op)
	}
	unblock()
	if err := <-done; err == nil {
		t.Error("read error was hidden")
	}
	joined = true
}

func TestPendingQueueInterruptedIOSettlesBeforeStateUnlock(t *testing.T) {
	for _, operation := range []string{"append", "take"} {
		t.Run(operation, func(t *testing.T) {
			st, openErr := Open(t.TempDir())
			if openErr != nil {
				t.Fatal(openErr)
			}
			if operation == "take" {
				if err := st.AppendPendingFindings([]alert.Finding{{Message: "parked"}}); err != nil {
					t.Fatal(err)
				}
			}
			q := st.pendingHealth()
			exited, done := make(chan struct{}), make(chan struct{})
			interrupt := func() {
				q.mu.Lock()
				defer close(exited)
				runtime.Goexit()
			}
			st.writePendingFile = func(string, os.FileMode, any) error { interrupt(); return nil }
			previous := removePendingFindingsFile
			if operation == "take" {
				removePendingFindingsFile = func(string) error { interrupt(); return nil }
			}
			t.Cleanup(func() { removePendingFindingsFile = previous })
			go func() {
				defer close(done)
				if operation == "append" {
					_ = st.AppendPendingFindings([]alert.Finding{{Message: "new"}})
				} else {
					_, _ = st.TakePendingFindings()
				}
			}()
			select {
			case <-exited:
			case <-time.After(5 * time.Second):
				t.Fatal("I/O did not exit")
			}
			unlocked := false
			deadline := time.Now().Add(100 * time.Millisecond)
			for time.Now().Before(deadline) {
				if st.mu.TryLock() {
					unlocked = true
					st.mu.Unlock()
					break
				}
				runtime.Gosched()
			}
			q.mu.Unlock()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("settlement did not join")
			}
			if unlocked {
				t.Error("state mutation could run before interrupted I/O uncertainty was settled")
			}
			row := pendingQueueStatus(t, st, time.Now())
			if !row.DepthUnavailable || !row.DroppedLowerBound || row.InFlight != 0 {
				t.Fatalf("interrupted I/O settlement: %+v", row)
			}
		})
	}
}

func TestPendingQueueCorruptStartupAndRecovery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, pendingFindingsFile)
	if err := os.WriteFile(path, []byte("[invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	st, openErr := Open(dir)
	if openErr != nil {
		t.Fatal("pending health changed store-open error policy")
	}
	row := pendingQueueStatus(t, st, time.Now())
	if !row.DepthUnavailable || !row.DroppedLowerBound || row.Reason != "state_io" {
		t.Fatalf("corrupt startup state reported empty healthy: %+v", row)
	}
	if err := st.AppendPendingFindings(make([]alert.Finding, 3)); err == nil {
		t.Fatal("corrupt input accepted")
	}
	row = pendingQueueStatus(t, st, time.Now())
	if row.DroppedTotal != 3 {
		t.Fatalf("known new losses hidden behind old corruption: %+v", row)
	}
	if err := os.WriteFile(path, []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.TakePendingFindings(); err != nil {
		t.Fatal(err)
	}
	row = pendingQueueStatus(t, st, time.Now().Add(2*time.Minute))
	if row.Depth != 0 || row.DepthUnavailable || !row.DroppedLowerBound || row.DroppedTotal != 3 || row.Status != "ok" {
		t.Fatalf("readable recovery erased lifetime evidence: %+v", row)
	}
	st.readPendingFile = func(string) ([]byte, error) { return nil, errors.New("fixture failure") }
	if _, err := st.TakePendingFindings(); err == nil {
		t.Fatal("failed read accepted")
	}
}
