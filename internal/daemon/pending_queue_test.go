package daemon

import (
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func TestDaemonReportsActualParkedAndReplayedFindings(t *testing.T) {
	dir := t.TempDir()
	_, restore := openTestBoltStore(t, dir)
	defer restore()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	stopping := New(&config.Config{StatePath: dir}, st, nil, "")
	stopping.persistPendingFindingsOnShutdown([]alert.Finding{{Severity: alert.Critical, Check: "fixture_pending", Message: "shutdown finding"}})
	if row, ok := stopping.QueueStatuses()["state.pending"]; !ok || row.Depth != 1 || row.InFlight != 0 {
		t.Fatalf("actual parked finding missing from daemon health: found=%v row=%+v", ok, row)
	}
	reopened, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	starting := New(&config.Config{StatePath: dir}, reopened, nil, "")
	if row, ok := starting.QueueStatuses()["state.pending"]; !ok || row.Depth != 1 || row.InFlight != 0 {
		t.Fatalf("startup did not observe actual durable queue: found=%v row=%+v", ok, row)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	previous := alert.CentralHook
	calls := 0
	alert.SetCentralHook(func(f alert.Finding) {
		calls++
		if f.Check != "fixture_pending" || f.Message != "shutdown finding" {
			t.Error("replay changed parked payload")
		}
		close(entered)
		<-release
	})
	t.Cleanup(func() {
		unblock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("daemon replay did not join")
		}
		alert.SetCentralHook(previous)
	})
	go func() { defer close(done); starting.replayPendingFindings() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("actual dispatcher did not receive parked finding")
	}
	rows := starting.queueStatuses(time.Now().Add(2 * time.Minute))
	if row := rows["state.pending"]; row.Depth != 0 || row.InFlight != 1 || row.DroppedTotal != 0 {
		t.Fatalf("daemon lost replay ownership in the real alert hook: %+v", row)
	}
	if row := rows["state.pending_operations"]; row.InFlight != 1 || row.Reason != "processing_lag" {
		t.Fatalf("daemon hid stalled replay: %+v", row)
	}
	unblock()
	<-done
	if calls != 1 {
		t.Fatalf("replayed %d findings, want exactly 1", calls)
	}
	if row := starting.QueueStatuses()["state.pending"]; row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 0 || row.DroppedLowerBound {
		t.Fatalf("completed dispatch left false ownership: %+v", row)
	}
}
