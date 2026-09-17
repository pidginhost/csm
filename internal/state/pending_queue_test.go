package state

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/queuehealth"
)

func pendingQueueStatus(t *testing.T, s *Store, now time.Time) queuehealth.Status {
	t.Helper()
	source, ok := any(s).(interface {
		QueueStatuses(time.Time) map[string]queuehealth.Status
	})
	if !ok {
		t.Fatal("state store does not publish parked finding ownership")
	}
	row, ok := source.QueueStatuses(now)["pending"]
	if !ok {
		t.Fatal("parked finding queue is missing")
	}
	if row.Capacity != pendingFindingsMax || row.CapacityUnavailable {
		t.Fatalf("parked queue capacity differs from actual bound: %+v", row)
	}
	return row
}

func TestPendingQueueCountsActualOverflowAndTake(t *testing.T) {
	st, openErr := Open(t.TempDir())
	if openErr != nil {
		t.Fatal(openErr)
	}
	findings := make([]alert.Finding, pendingFindingsMax+3)
	for i := range findings {
		findings[i] = alert.Finding{Check: "fixture", Message: fmt.Sprintf("pending %d", i), Timestamp: time.Now().Add(-24 * time.Hour)}
	}
	if err := st.AppendPendingFindings(findings); err != nil {
		t.Fatal(err)
	}
	if s := pendingQueueStatus(t, st, time.Now()); s.Depth != pendingFindingsMax || s.InFlight != 0 || s.DroppedTotal != 3 || s.RecentDrops != 3 || s.DroppedLowerBound || s.DepthUnavailable {
		t.Fatalf("actual bounded append outcome: %+v", s)
	}
	got, err := st.TakePendingFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != pendingFindingsMax || got[0].Message != "pending 3" || got[len(got)-1].Message != fmt.Sprintf("pending %d", pendingFindingsMax+2) {
		t.Fatal("parked FIFO did not retain exactly the newest bounded findings")
	}
	if s := pendingQueueStatus(t, st, time.Now().Add(2*time.Minute)); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 3 || s.RecentDrops != 0 || s.Status != "ok" {
		t.Fatalf("take lost ownership or historical overflow: %+v", s)
	}
	if _, err := os.Stat(filepath.Join(st.path, pendingFindingsFile)); !os.IsNotExist(err) {
		t.Fatalf("successful take did not clear actual file: %v", err)
	}
}

func TestPendingQueueFailedAppendPreservesOldFindings(t *testing.T) {
	st, openErr := Open(t.TempDir())
	if openErr != nil {
		t.Fatal(openErr)
	}
	if err := st.AppendPendingFindings([]alert.Finding{{Check: "fixture", Message: "old"}}); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(st.path, pendingFindingsFile) + ".tmp"
	if err := os.Mkdir(stale, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "occupied"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendPendingFindings([]alert.Finding{{Check: "fixture", Message: "new 1"}, {Check: "fixture", Message: "new 2"}, {Check: "fixture", Message: "new 3"}}); err == nil {
		t.Fatal("blocked atomic append unexpectedly succeeded")
	}
	if s := pendingQueueStatus(t, st, time.Now()); s.Depth != 1 || s.InFlight != 0 || s.DroppedTotal != 3 || s.DepthUnavailable || s.DroppedLowerBound || s.Reason != "state_io" {
		t.Fatalf("failed append misreported retained old work: %+v", s)
	}
	got, err := st.TakePendingFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Message != "old" {
		t.Fatal("failed append damaged the old persisted finding")
	}
	if s := pendingQueueStatus(t, st, time.Now().Add(2*time.Minute)); s.Depth != 0 || s.DroppedTotal != 3 || s.Status != "ok" {
		t.Fatalf("successful take did not recover health: %+v", s)
	}
}

func TestPendingQueueHealthDoesNotWaitForStoreLock(t *testing.T) {
	st, openErr := Open(t.TempDir())
	if openErr != nil {
		t.Fatal(openErr)
	}
	if err := st.AppendPendingFindings([]alert.Finding{{Check: "fixture", Message: "parked"}}); err != nil {
		t.Fatal(err)
	}
	source, ok := any(st).(interface {
		QueueStatuses(time.Time) map[string]queuehealth.Status
	})
	if !ok {
		t.Fatal("state store does not publish queue health")
	}
	st.mu.Lock()
	done := make(chan map[string]queuehealth.Status, 1)
	go func() { done <- source.QueueStatuses(time.Now().Add(24 * time.Hour)) }()
	select {
	case rows := <-done:
		s, exists := rows["pending"]
		if !exists || s.Depth != 1 || s.InFlight != 0 || s.Status != "ok" || s.LagBasis != "deferred_checkpoint" {
			t.Errorf("parked work waiting for restart was misreported: %+v", s)
		}
	case <-time.After(time.Second):
		t.Error("queue health waited for store state lock")
	}
	st.mu.Unlock()
}

func TestPendingQueueTakePreservesEmptySliceResult(t *testing.T) {
	st, openErr := Open(t.TempDir())
	if openErr != nil {
		t.Fatal(openErr)
	}
	path := filepath.Join(st.path, pendingFindingsFile)
	if err := os.WriteFile(path, []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := st.TakePendingFindings()
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got) != 0 {
		t.Fatal("empty JSON array no longer returns a non-nil empty slice")
	}
	got, err = st.TakePendingFindings()
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatal("absent file no longer returns nil")
	}
}
