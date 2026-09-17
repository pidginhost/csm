package checks

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/store"
)

func cleanupQueueRow(t *testing.T, now time.Time) queuehealth.Status {
	t.Helper()
	row, ok := AutoBlockQueueStatuses(now)["cleanup"]
	if !ok {
		t.Fatal("automatic block cleanup queue missing")
	}
	return row
}

// Acknowledgments belong to the cleaned block generation. A failed removal of
// its tracker record must neither lose the old success nor complete a new block.
func TestAutoBlockCleanupAcknowledgmentSurvivesOnlyItsBlock(t *testing.T) {
	for _, newBlock := range []bool{false, true} {
		t.Run(map[bool]string{false: "old-completed", true: "new-block"}[newBlock], func(t *testing.T) {
			cfg := autoBlockQueueFixture(t, func() error { return nil })
			const ip = "192.0.2.131"
			if err := writeBlockState(cfg.StatePath, &blockState{IPs: []blockedIP{{IP: ip, BlockedAt: time.Now().Add(-time.Minute)}}}); err != nil {
				t.Fatal(err)
			}
			writeFirewallFlushState(t, cfg.StatePath)
			restoreWrite := failRetryWrite(t, cfg.StatePath)
			if err := flushAutoBlockStateForTest(t, cfg.StatePath); err == nil {
				t.Fatal("fixture did not fail persistence after successful cleanup")
			}
			row := cleanupQueueRow(t, time.Now())
			if row.Depth != 1 || row.DroppedTotal != 0 {
				t.Fatalf("failed record removal lost acknowledged cleanup: %+v", row)
			}
			restoreWrite()
			if newBlock {
				result, err := ApplyBlock(cfg, ApplyBlockRequest{IP: ip, Reason: "new generation", TTL: time.Hour, Source: BlockSourceCentral})
				if err != nil || result.Outcome != firewall.BlockOutcomeLive || len(result.Findings) != 1 {
					t.Fatalf("new live block missing: result=%+v err=%v", result, err)
				}
			}
			db, err := store.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			store.SetGlobal(db)
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			// Use a different old fixture name; no cleanup deletes test evidence.
			if err = os.Rename(filepath.Join(cfg.StatePath, blockStateFile+".tmp.saved"), filepath.Join(cfg.StatePath, "first-write-failure")); err != nil {
				t.Fatal(err)
			}
			restoreWrite = failRetryWrite(t, cfg.StatePath)
			if err = flushAutoBlockStateForTest(t, cfg.StatePath); err == nil {
				t.Fatal("closed database and blocked writer did not fail")
			}
			restoreWrite()
			store.SetGlobal(nil)
			// The next real scan drops tracker entries absent from the engine.
			AutoBlockIPs(cfg, nil)
			row = cleanupQueueRow(t, time.Now())
			wantLoss := uint64(0)
			if newBlock {
				wantLoss = 1
			}
			if row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != wantLoss {
				t.Fatalf("block generation acknowledgment changed: %+v want loss%d", row, wantLoss)
			}
			state, err := readBlockState(cfg.StatePath)
			if err != nil || len(state.IPs) != 0 || len(state.CleanupPending) != 0 {
				t.Fatalf("scan did not remove original retry sources: state=%+v err=%v", state, err)
			}
		})
	}
}

type cleanupQueueReadHook struct {
	OS
	path string
	read func()
}

func (f cleanupQueueReadHook) ReadFile(path string) ([]byte, error) {
	if path == f.path {
		f.read()
	}
	return f.OS.ReadFile(path)
}

func TestAutoBlockCleanupAdmissionPrecedesTrackerRead(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { return nil })
	if err := writeBlockState(cfg.StatePath, &blockState{
		CleanupPending: []string{"192.0.2.126"},
		IPs:            []blockedIP{{IP: "192.0.2.129"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := InitAutoBlockQueueHealth(cfg.StatePath); err != nil {
		t.Fatal(err)
	}
	writeFirewallFlushState(t, cfg.StatePath, "192.0.2.127", "192.0.2.128", "192.0.2.127")
	oldOS, oldWriter := osFS, persistAutoBlockState
	defer func() { osFS, persistAutoBlockState = oldOS, oldWriter }()
	reads, writes := 0, 0
	osFS = cleanupQueueReadHook{OS: realOS{}, path: filepath.Join(cfg.StatePath, blockStateFile), read: func() {
		reads++
		row := cleanupQueueRow(t, time.Now())
		if row.Depth != 3 || row.InFlight != 0 || row.DroppedTotal != 0 {
			t.Errorf("engine admission delayed or duplicated: %+v", row)
		}
		late := cleanupQueueRow(t, time.Now().Add(61*time.Second))
		if late.Reason != "processing_lag" {
			t.Errorf("accepted cleanup stuck behind tracker read stayed healthy: %+v", late)
		}
	}}
	persistAutoBlockState = func(path string, state *blockState) error {
		writes++
		row := cleanupQueueRow(t, time.Now())
		if row.Depth != 0 || row.InFlight != 4 || row.DroppedTotal != 0 {
			t.Errorf("cleanup union released before persistence: %+v", row)
		}
		return writeBlockState(path, state)
	}
	result, err := FlushAutoBlockState(cfg.StatePath, func() error {
		row := cleanupQueueRow(t, time.Now())
		if row.Depth != 1 || row.InFlight != 0 {
			t.Errorf("cleanup admitted before successful firewall flush: %+v", row)
		}
		writeFirewallFlushState(t, cfg.StatePath)
		return nil
	})
	if err != nil || !result.Flushed || reads != 1 || writes != 1 {
		t.Fatalf("real cleanup path missing: result=%+v err=%v reads=%d writes=%d", result, err, reads, writes)
	}
	row := cleanupQueueRow(t, time.Now())
	if row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 0 || row.Status != "ok" {
		t.Fatalf("successful union cleanup leaked: %+v", row)
	}
}

func TestAutoBlockCleanupStoreFailureVisibleBeforeThreatLock(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { return nil })
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(db)
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	const ip = "192.0.2.130"
	writeFirewallFlushState(t, cfg.StatePath, ip)
	tdb := GetThreatDB()
	tdb.mu.Lock()
	var unlock sync.Once
	release := func() { unlock.Do(tdb.mu.Unlock) }
	done := make(chan error, 1)
	joined := false
	defer func() {
		release()
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("cleanup did not join")
			}
		}
	}()
	go func() {
		_, flushErr := FlushAutoBlockState(cfg.StatePath, func() error { return nil })
		done <- flushErr
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		blocked := false
		for _, stack := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(stack, ".FlushAutoBlockState(") && strings.Contains(stack, "(*ThreatDB).RemoveTemporary(") {
				blocked = true
				break
			}
		}
		if blocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real cleanup did not reach held threat lock")
		}
		time.Sleep(time.Millisecond)
	}
	row := cleanupQueueRow(t, time.Now())
	if row.Depth != 0 || row.InFlight != 1 || row.DroppedTotal != 0 || row.Reason != "retry_failed" {
		t.Errorf("known database failure hidden behind secondary cleanup: %+v", row)
	}
	release()
	select {
	case err = <-done:
		joined = true
		if err == nil || !strings.Contains(err.Error(), "removing auto-block store row") {
			t.Fatalf("original database failure changed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cleanup did not return after releasing threat lock")
	}
	row = cleanupQueueRow(t, time.Now())
	if row.Depth != 1 || row.InFlight != 0 || row.DroppedTotal != 0 || row.Reason != "retry_failed" {
		t.Fatalf("failed cleanup was not retained: %+v", row)
	}
}

func TestAutoBlockCleanupStartupObservesDistinctDeferredRecords(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { t.Error("startup blocked an IP"); return nil })
	if err := writeBlockState(cfg.StatePath, &blockState{
		CleanupPending: []string{"192.0.2.120", "192.0.2.120", "192.0.2.121"},
		IPs:            []blockedIP{{IP: "192.0.2.122"}},
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.StatePath, blockStateFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = InitAutoBlockQueueHealth(cfg.StatePath); err != nil {
		t.Fatal(err)
	}
	row := cleanupQueueRow(t, time.Now().Add(24*time.Hour))
	if row.Depth != 2 || row.InFlight != 0 || !row.CapacityUnavailable || row.DepthUnavailable || row.DroppedTotal != 0 || row.Status != "ok" || row.LagBasis != "deferred_checkpoint" || row.LagSeconds < (24*time.Hour).Seconds() {
		t.Fatalf("deferred records misreported: %+v", row)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("startup rewrote state: %v", err)
	}
	if err = os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if got := cleanupQueueRow(t, time.Now()).Depth; got != 2 {
		t.Fatalf("snapshot consulted disk: depth=%d", got)
	}
}

// A real closed database rejects cleanup. Retention belongs to the actual
// atomic file outcome, including the old tracker as a source for a later flush.
func TestAutoBlockCleanupWriteOutcomeControlsRetention(t *testing.T) {
	for _, mode := range []string{"saved", "rollback", "post-rename"} {
		t.Run(mode, func(t *testing.T) {
			cfg := autoBlockQueueFixture(t, func() error { return nil })
			storePath := t.TempDir()
			db, err := store.Open(storePath)
			if err != nil {
				t.Fatal(err)
			}
			store.SetGlobal(db)
			for _, ip := range []string{"192.0.2.123", "192.0.2.124", "192.0.2.125"} {
				if err = db.AddTempBlock(ip, "cleanup fixture", time.Now().Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
			}
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			if err = writeBlockState(cfg.StatePath, &blockState{
				CleanupPending: []string{"192.0.2.123"},
				IPs:            []blockedIP{{IP: "192.0.2.124"}},
			}); err != nil {
				t.Fatal(err)
			}
			writeFirewallFlushState(t, cfg.StatePath, "192.0.2.125", "192.0.2.124")
			var restoreWrite func()
			if mode == "rollback" {
				restoreWrite = failRetryWrite(t, cfg.StatePath)
			}
			originalWriter := persistAutoBlockState
			t.Cleanup(func() { persistAutoBlockState = originalWriter })
			if mode == "post-rename" {
				persistAutoBlockState = func(path string, state *blockState) error {
					if writeErr := writeBlockState(path, state); writeErr != nil {
						return writeErr
					}
					return errors.New("synthetic directory sync failure")
				}
			}
			result, err := FlushAutoBlockState(cfg.StatePath, func() error {
				writeFirewallFlushState(t, cfg.StatePath)
				return nil
			})
			if !result.Flushed || err == nil {
				t.Fatalf("closed database did not fail after flush: result=%+v err=%v", result, err)
			}
			wantDepth, wantLoss := 3, uint64(0)
			wantReason := "retry_failed"
			if mode != "saved" {
				wantReason = "state_io"
			}
			if mode == "rollback" {
				wantDepth, wantLoss = 2, 1
			}
			row := cleanupQueueRow(t, time.Now())
			if row.Depth != wantDepth || row.InFlight != 0 || row.DepthUnavailable || row.DroppedTotal != wantLoss || row.Reason != wantReason {
				t.Fatalf("%s cleanup settlement: %+v", mode, row)
			}
			actual, err := readBlockState(cfg.StatePath)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "rollback" {
				if !reflect.DeepEqual(actual.CleanupPending, []string{"192.0.2.123"}) || len(actual.IPs) != 1 || actual.IPs[0].IP != "192.0.2.124" {
					t.Fatalf("rollback fixture did not preserve original retry sources: %+v", actual)
				}
				restoreWrite()
			} else if len(actual.CleanupPending) != 3 || len(actual.IPs) != 0 {
				t.Fatalf("new state did not retain three distinct retries: %+v", actual)
			}
			persistAutoBlockState = originalWriter
			reopened, err := store.Open(storePath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reopened.Close() })
			store.SetGlobal(reopened)
			if err = flushAutoBlockStateForTest(t, cfg.StatePath); err != nil {
				t.Fatal(err)
			}
			row = cleanupQueueRow(t, time.Now())
			if row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != wantLoss || row.Status != "ok" {
				t.Fatalf("successful retry did not settle: %+v", row)
			}
			for _, ip := range []string{"192.0.2.123", "192.0.2.124"} {
				if _, found := reopened.GetPermanentBlock(ip); found {
					t.Errorf("retained retry did not delete %s", ip)
				}
			}
			if _, found := reopened.GetPermanentBlock("192.0.2.125"); found != (mode == "rollback") {
				t.Fatalf("engine-only row survival=%v, mode=%s", found, mode)
			}
		})
	}
}

func TestAutoBlockCleanupTimesOperationProgress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := autoBlockQueueFixture(t, func() error { return nil })
		writeFirewallFlushState(t, cfg.StatePath, "192.0.2.168", "192.0.2.169")
		oldOS, oldWriter := osFS, persistAutoBlockState
		defer func() { osFS, persistAutoBlockState = oldOS, oldWriter }()
		started := time.Now()
		reads, writes := 0, 0
		osFS = cleanupQueueReadHook{OS: realOS{}, path: filepath.Join(cfg.StatePath, blockStateFile), read: func() {
			reads++
			time.Sleep(45 * time.Second)
			row := cleanupQueueRow(t, time.Now())
			if row.Depth != 2 || row.InFlight != 0 || row.Status != "ok" || row.ProcessingSeconds != 45 {
				t.Errorf("tracker read ownership or budget changed: %+v", row)
			}
		}}
		persistAutoBlockState = func(path string, state *blockState) error {
			writes++
			time.Sleep(45 * time.Second)
			row := cleanupQueueRow(t, time.Now())
			if time.Since(started) != 90*time.Second || row.Depth != 0 || row.InFlight != 2 || row.Status != "ok" || row.ProcessingSeconds != 45 {
				t.Errorf("progressing cleanup used total batch duration: elapsed=%v row=%+v", time.Since(started), row)
			}
			time.Sleep(15 * time.Second)
			row = cleanupQueueRow(t, time.Now())
			if row.InFlight != 2 || row.Reason != "processing_lag" || row.ProcessingSeconds != 60 {
				t.Errorf("stalled state write lost cleanup ownership: %+v", row)
			}
			return writeBlockState(path, state)
		}
		result, err := FlushAutoBlockState(cfg.StatePath, func() error { writeFirewallFlushState(t, cfg.StatePath); return nil })
		if err != nil || !result.Flushed || reads != 1 || writes != 1 {
			t.Fatalf("timed cleanup did not complete: result=%+v err=%v reads=%d writes=%d", result, err, reads, writes)
		}
		row := cleanupQueueRow(t, time.Now())
		if row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 0 || row.Status != "ok" {
			t.Fatalf("successful slow cleanup did not recover: %+v", row)
		}
	})
}
