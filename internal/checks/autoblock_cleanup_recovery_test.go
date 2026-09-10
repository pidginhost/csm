package checks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// A rolled-back tracker can still identify cleanup work without an explicit
// cleanup marker. Readback uncertainty must preserve that last bounded batch.
func TestAutoBlockCleanupRecoversTrackerFallbackAfterUnknownWrite(t *testing.T) {
	for _, completed := range []bool{false, true} {
		t.Run(fmt.Sprintf("completed=%v", completed), func(t *testing.T) {
			cfg := autoBlockQueueFixture(t, func() error { return nil })
			if !completed {
				db, err := store.Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				store.SetGlobal(db)
				if err = db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := writeBlockState(cfg.StatePath, &blockState{IPs: []blockedIP{{IP: "192.0.2.159", BlockedAt: time.Now()}}}); err != nil {
				t.Fatal(err)
			}
			writeFirewallFlushState(t, cfg.StatePath)
			restoreWrite := failRetryWrite(t, cfg.StatePath)
			oldOS := osFS
			defer func() { osFS = oldOS }()
			osFS = &retryQueueReadFailure{OS: realOS{}, path: filepath.Join(cfg.StatePath, blockStateFile), fail: true}
			if err := flushAutoBlockStateForTest(t, cfg.StatePath); err == nil {
				t.Fatal("write failure missing")
			}
			row := cleanupQueueRow(t, time.Now())
			if !row.DepthUnavailable || !row.DroppedLowerBound || row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 0 {
				t.Fatalf("unknown state claimed exact queue depth: %+v", row)
			}
			osFS = oldOS
			restoreWrite()
			if err := InitAutoBlockQueueHealth(cfg.StatePath); err != nil {
				t.Fatal(err)
			}
			row = cleanupQueueRow(t, time.Now())
			if row.DepthUnavailable || row.Depth != 1 || row.DroppedTotal != 0 {
				t.Fatalf("known recovered tracker retry vanished: %+v", row)
			}
			store.SetGlobal(nil)
			AutoBlockIPs(cfg, nil)
			row = cleanupQueueRow(t, time.Now())
			wantLoss := uint64(1)
			if completed {
				wantLoss = 0
			}
			if row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != wantLoss || !row.DroppedLowerBound {
				t.Fatalf("recovered cleanup outcome changed: %+v want loss%d", row, wantLoss)
			}
		})
	}
}

func TestAutoBlockCleanupUnreadableWriteRecovery(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { return nil })
	if err := writeBlockState(cfg.StatePath, &blockState{CleanupPending: []string{"192.0.2.150"}}); err != nil {
		t.Fatal(err)
	}
	writeFirewallFlushState(t, cfg.StatePath)
	restoreWrite := failRetryWrite(t, cfg.StatePath)
	oldOS := osFS
	defer func() { osFS = oldOS }()
	osFS = &retryQueueReadFailure{OS: realOS{}, path: filepath.Join(cfg.StatePath, blockStateFile), fail: true}
	if err := flushAutoBlockStateForTest(t, cfg.StatePath); err == nil {
		t.Fatal("actual write failure missing")
	}
	row := cleanupQueueRow(t, time.Now())
	if !row.DepthUnavailable || !row.DroppedLowerBound || row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 0 || row.Reason != "state_io" {
		t.Fatalf("unknown write fabricated completion or loss: %+v", row)
	}
	osFS = oldOS
	restoreWrite()
	if err := InitAutoBlockQueueHealth(cfg.StatePath); err != nil {
		t.Fatal(err)
	}
	row = cleanupQueueRow(t, time.Now())
	if row.DepthUnavailable || row.Depth != 1 || row.DroppedTotal != 0 || !row.DroppedLowerBound {
		t.Fatalf("read recovery lost observed records or historical uncertainty: %+v", row)
	}
	if err := writeBlockState(cfg.StatePath, &blockState{}); err != nil {
		t.Fatal(err)
	}
	if err := InitAutoBlockQueueHealth(cfg.StatePath); err != nil {
		t.Fatal(err)
	}
	if row = cleanupQueueRow(t, time.Now()); row.DroppedTotal != 0 || row.Depth != 0 {
		t.Fatalf("recovered cleanup acknowledgment became a false loss: %+v", row)
	}
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(db)
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(filepath.Join(cfg.StatePath, blockStateFile+".tmp.saved"), filepath.Join(cfg.StatePath, "first-write-failure")); err != nil {
		t.Fatal(err)
	}
	restoreWrite = failRetryWrite(t, cfg.StatePath)
	writeFirewallFlushState(t, cfg.StatePath, "192.0.2.151", "192.0.2.152", "192.0.2.153")
	result, err := FlushAutoBlockState(cfg.StatePath, func() error { writeFirewallFlushState(t, cfg.StatePath); return nil })
	if err == nil || !result.Flushed {
		t.Fatalf("fresh failed cleanup path missing: result=%+v err=%v", result, err)
	}
	row = cleanupQueueRow(t, time.Now())
	if row.DepthUnavailable || row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 3 || !row.DroppedLowerBound {
		t.Fatalf("old uncertainty hid new confirmed loss: %+v", row)
	}
	restoreWrite()
	store.SetGlobal(nil)
	if err = flushAutoBlockStateForTest(t, cfg.StatePath); err != nil {
		t.Fatal(err)
	}
	if row = cleanupQueueRow(t, time.Now()); row.Status != "degraded" || row.Reason != "dropped_work" || row.DroppedTotal != 3 {
		t.Fatalf("confirmed loss threshold not reported: %+v", row)
	}
	if row = cleanupQueueRow(t, time.Now().Add(2*time.Minute)); row.Status != "ok" || row.DroppedTotal != 3 || !row.DroppedLowerBound {
		t.Fatalf("recovery cleared lifetime evidence: %+v", row)
	}
}

// Every state writer can retain cleanup records. An abnormal scan writer must
// expose uncertainty just as the flush writer does, even without cleanup calls.
func TestAutoBlockCleanupInterruptedStateIO(t *testing.T) {
	for _, phase := range []string{"tracker-read", "before-write", "after-write"} {
		for _, route := range []string{"flush", "scan"} {
			for _, mode := range []string{"panic", "goexit"} {
				t.Run(phase+"/"+route+"/"+mode, func(t *testing.T) {
					cfg := autoBlockQueueFixture(t, func() error { return nil })
					if err := writeBlockState(cfg.StatePath, &blockState{CleanupPending: []string{"192.0.2.154"}}); err != nil {
						t.Fatal(err)
					}
					if err := InitAutoBlockQueueHealth(cfg.StatePath); err != nil {
						t.Fatal(err)
					}
					writeFirewallFlushState(t, cfg.StatePath, "192.0.2.155")
					entered, release := make(chan struct{}), make(chan struct{})
					var once sync.Once
					unblock := func() { once.Do(func() { close(release) }) }
					interrupt := func() {
						defer func() { close(entered); <-release }()
						if mode == "panic" {
							panic("cleanup state interruption")
						}
						runtime.Goexit()
					}
					oldOS, oldWriter := osFS, persistAutoBlockState
					defer func() { osFS, persistAutoBlockState = oldOS, oldWriter }()
					if phase == "tracker-read" {
						osFS = cleanupQueueReadHook{OS: realOS{}, path: filepath.Join(cfg.StatePath, blockStateFile), read: interrupt}
					} else {
						persistAutoBlockState = func(path string, state *blockState) error {
							if phase == "after-write" {
								if err := writeBlockState(path, state); err != nil {
									return err
								}
							}
							interrupt()
							return errors.New("unreachable interruption return")
						}
					}
					exited := make(chan any, 1)
					returned := false
					joined := false
					defer func() {
						unblock()
						if !joined {
							select {
							case <-exited:
							case <-time.After(3 * time.Second):
								t.Error("interrupted state owner did not join")
							}
						}
					}()
					go func() {
						defer func() { exited <- recover() }()
						if route == "flush" {
							_, _ = FlushAutoBlockState(cfg.StatePath, func() error { writeFirewallFlushState(t, cfg.StatePath); return nil })
						} else {
							AutoBlockIPs(cfg, nil)
						}
						returned = true
					}()
					select {
					case <-entered:
					case <-time.After(3 * time.Second):
						t.Fatal("state interruption did not reach deferred cleanup")
					}
					row := cleanupQueueRow(t, time.Now())
					wantDepth, wantFlight := 1, 0
					if route == "flush" {
						wantDepth = 2
						if phase != "tracker-read" {
							wantDepth, wantFlight = 0, 2
						}
					}
					if row.Depth != wantDepth || row.InFlight != wantFlight || row.DroppedTotal != 0 || AutoBlockQueueStatuses(time.Now())["active"].InFlight != 1 {
						t.Fatalf("deferred state cleanup lost ownership: %+v want depth%d flight%d", row, wantDepth, wantFlight)
					}
					unblock()
					select {
					case got := <-exited:
						joined = true
						if mode == "panic" && got != "cleanup state interruption" || mode == "goexit" && got != nil {
							t.Fatalf("abnormal exit changed: %v", got)
						}
					case <-time.After(3 * time.Second):
						t.Fatal("state owner stayed blocked")
					}
					if returned {
						t.Fatal("abnormal exit became normal return")
					}
					row = cleanupQueueRow(t, time.Now())
					pending, _ := retryQueueRows(t, time.Now())
					if !pending.DepthUnavailable || !pending.DroppedLowerBound || pending.DroppedTotal != 0 || pending.Reason != "state_io" {
						t.Errorf("shared interrupted state I/O concealed pending uncertainty: %+v", pending)
					}
					if !row.DepthUnavailable || !row.DroppedLowerBound || row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 0 || row.Reason != "state_io" {
						t.Fatalf("abnormal state outcome claimed known cleanup state: %+v", row)
					}
					assertAutoBlockQueueDrained(t, 1)
					osFS, persistAutoBlockState = oldOS, oldWriter
					if err := InitAutoBlockQueueHealth(cfg.StatePath); err != nil {
						t.Fatal(err)
					}
					wantRecovered := 1
					wantLoss := uint64(0)
					if phase == "tracker-read" && route == "flush" {
						// Cleanup never started. The recovered tracker now proves
						// that the flushed engine-only IP has no retry source.
						wantLoss = 1
					}
					if phase == "after-write" && route == "flush" {
						wantRecovered = 0
					}
					row = cleanupQueueRow(t, time.Now())
					if row.DepthUnavailable || row.Depth != wantRecovered || row.InFlight != 0 || row.DroppedTotal != wantLoss || !row.DroppedLowerBound {
						t.Fatalf("real old/new state recovery changed: %+v", row)
					}
				})
			}
		}
	}
}

func TestAutoBlockCleanupUnknownBatchesRetainBoundedHistory(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { return nil })
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(db)
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.StatePath, blockStateFile)
	if err = os.WriteFile(path, []byte("{corrupt cleanup tracker"), 0600); err != nil {
		t.Fatal(err)
	}
	const batches = 8
	lastIP := ""
	for i := 0; i < batches; i++ {
		lastIP = fmt.Sprintf("192.0.2.%d", 160+i)
		writeFirewallFlushState(t, cfg.StatePath, lastIP)
		result, flushErr := FlushAutoBlockState(cfg.StatePath, func() error { writeFirewallFlushState(t, cfg.StatePath); return nil })
		if !result.Flushed || flushErr == nil {
			t.Fatalf("batch %d did not reach failed cleanup: result=%+v err=%v", i, result, flushErr)
		}
		row := cleanupQueueRow(t, time.Now())
		if !row.DepthUnavailable || !row.DroppedLowerBound || row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 0 || row.Reason != "state_io" {
			t.Fatalf("batch %d claimed unknown work as measured: %+v", i, row)
		}
		autoBlockQueues.mu.Lock()
		n := len(autoBlockQueues.cleanup.records)
		last := autoBlockQueues.cleanup.records[lastIP]
		autoBlockQueues.mu.Unlock()
		if n != 1 || last == nil {
			t.Fatalf("batch %d retained %d records, latest present=%v; want only latest batch", i, n, last != nil)
		}
	}
	if err = writeBlockState(cfg.StatePath, &blockState{IPs: []blockedIP{{IP: lastIP}}}); err != nil {
		t.Fatal(err)
	}
	if err = InitAutoBlockQueueHealth(cfg.StatePath); err != nil {
		t.Fatal(err)
	}
	row := cleanupQueueRow(t, time.Now())
	if row.DepthUnavailable || row.Depth != 1 || row.DroppedTotal != 0 || !row.DroppedLowerBound || row.Reason != "retry_failed" {
		t.Fatalf("known last batch was not recovered: %+v", row)
	}
	store.SetGlobal(nil)
	AutoBlockIPs(cfg, nil)
	row = cleanupQueueRow(t, time.Now())
	if row.Depth != 0 || row.DroppedTotal != 1 || !row.DroppedLowerBound {
		t.Fatalf("last batch's confirmed loss was hidden by older uncertainty: %+v", row)
	}
}

func TestAutoBlockCleanupIncompleteEngineSnapshotIsExplicit(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { return nil })
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store.SetGlobal(db)
	for _, ip := range []string{"192.0.2.156", "192.0.2.157"} {
		if err = db.AddTempBlock(ip, "cleanup fixture", time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if err = writeBlockState(cfg.StatePath, &blockState{CleanupPending: []string{"192.0.2.156"}}); err != nil {
		t.Fatal(err)
	}
	if err = InitAutoBlockQueueHealth(cfg.StatePath); err != nil {
		t.Fatal(err)
	}
	writeFirewallFlushState(t, cfg.StatePath)
	if err = os.WriteFile(filepath.Join(cfg.StatePath, "firewall", "state.json"), []byte("{incomplete snapshot"), 0600); err != nil {
		t.Fatal(err)
	}
	refusal := errors.New("synthetic flush refusal")
	result, err := FlushAutoBlockState(cfg.StatePath, func() error { return refusal })
	if result.Flushed || result.SnapshotErr == nil || !errors.Is(err, refusal) {
		t.Fatalf("failed firewall flush semantics changed: result=%+v err=%v", result, err)
	}
	row := cleanupQueueRow(t, time.Now())
	if row.Depth != 1 || row.InFlight != 0 || row.DroppedTotal != 0 || row.DroppedLowerBound || row.Status != "ok" {
		t.Fatalf("failed firewall flush admitted cleanup: %+v", row)
	}
	if _, found := db.GetPermanentBlock("192.0.2.156"); !found {
		t.Fatal("failed firewall flush removed retry evidence")
	}
	result, err = FlushAutoBlockState(cfg.StatePath, func() error { writeFirewallFlushState(t, cfg.StatePath); return nil })
	if !result.Flushed || result.SnapshotErr == nil || result.BlockedCount != 0 || err != nil {
		t.Fatalf("advisory snapshot failure changed return policy: result=%+v err=%v", result, err)
	}
	row = cleanupQueueRow(t, time.Now())
	if row.Depth != 0 || row.InFlight != 0 || row.DepthUnavailable || row.DroppedTotal != 0 || !row.DroppedLowerBound || row.Reason != "state_io" {
		t.Fatalf("incomplete cleanup input was reported as exact: %+v", row)
	}
	if _, found := db.GetPermanentBlock("192.0.2.156"); found {
		t.Fatal("known tracker retry was not cleaned")
	}
	if _, found := db.GetPermanentBlock("192.0.2.157"); !found {
		t.Fatal("snapshot failure unexpectedly invented an untracked cleanup input")
	}
	if err = flushAutoBlockStateForTest(t, cfg.StatePath); err != nil {
		t.Fatal(err)
	}
	row = cleanupQueueRow(t, time.Now())
	if row.Status != "ok" || row.DroppedTotal != 0 || !row.DroppedLowerBound {
		t.Fatalf("snapshot recovery erased historical uncertainty: %+v", row)
	}
}

func TestAutoBlockCleanupCorruptTrackerDoesNotInventLoss(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { return nil })
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(db)
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.StatePath, blockStateFile)
	const corrupt = "{corrupt cleanup tracker"
	if err = os.WriteFile(path, []byte(corrupt), 0600); err != nil {
		t.Fatal(err)
	}
	writeFirewallFlushState(t, cfg.StatePath, "192.0.2.158")
	result, err := FlushAutoBlockState(cfg.StatePath, func() error { writeFirewallFlushState(t, cfg.StatePath); return nil })
	if !result.Flushed || result.SnapshotErr != nil || err == nil {
		t.Fatalf("corrupt tracker and closed database path missing: result=%+v err=%v", result, err)
	}
	row := cleanupQueueRow(t, time.Now())
	if !row.DepthUnavailable || !row.DroppedLowerBound || row.DroppedTotal != 0 || row.Depth != 0 || row.InFlight != 0 || row.Reason != "state_io" {
		t.Fatalf("unknown retry source became fabricated loss: %+v", row)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != corrupt {
		t.Fatalf("flush overwrote corrupt state: %v", err)
	}
}
