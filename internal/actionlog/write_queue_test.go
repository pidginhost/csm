package actionlog

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestWriteQueueRetainsSlowWriterAndCountsRefusedRecords(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := newWritePool(1)
		release := make(chan struct{})
		releaseWrite := sync.OnceFunc(func() { close(release) })
		defer releaseWrite()
		calls := 0
		s := sinkFunc(func(Record) error { calls++; <-release; return nil })
		start := time.Now()
		pool.write(s, Record{Op: "first"})
		synctest.Wait()
		if time.Since(start) != writeTimeout {
			t.Fatalf("caller waited %s, want %s", time.Since(start), writeTimeout)
		}
		got := pool.stats.Snapshot(time.Now())
		if calls != 1 || got.Capacity != 1 || got.Depth != 0 || got.InFlight != 1 || got.DroppedTotal != 0 || got.ProcessingSeconds != writeTimeout.Seconds() || got.Status != "ok" {
			t.Fatalf("caller timeout hid or discarded active writer: calls=%d status=%+v", calls, got)
		}
		for range 3 {
			pool.write(s, Record{Op: "refused"})
		}
		synctest.Wait()
		got = pool.stats.Snapshot(time.Now())
		if calls != 1 || got.Depth != 0 || got.InFlight != 1 || got.DroppedTotal != 3 || got.RecentDrops != 3 {
			t.Fatalf("saturated writes were accepted or lost without evidence: calls=%d status=%+v", calls, got)
		}
		releaseWrite()
		synctest.Wait()
		got = pool.stats.Snapshot(time.Now().Add(time.Minute))
		if got.InFlight != 0 || got.Depth != 0 || got.DroppedTotal != 3 || got.Status != "ok" {
			t.Fatalf("late success or slot recovery counted incorrectly: %+v", got)
		}
		pool.write(s, Record{Op: "after-recovery"})
		if calls != 2 {
			t.Fatalf("recovered slot did not accept new work: calls=%d", calls)
		}
	})
}

func TestWriteQueueSinkFailureCountsOnce(t *testing.T) {
	for _, outcome := range []string{"success", "error", "panic"} {
		for _, late := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/late=%v", outcome, late), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					pool := newWritePool(2)
					release := make(chan struct{})
					if !late {
						close(release)
					}
					calls := 0
					pool.write(sinkFunc(func(Record) error {
						calls++
						<-release
						switch outcome {
						case "error":
							return errors.New("write failed")
						case "panic":
							panic("write panicked")
						}
						return nil
					}), Record{Op: "test"})
					if late {
						got := pool.stats.Snapshot(time.Now())
						if got.InFlight != 1 || got.DroppedTotal != 0 {
							t.Errorf("counted failure before sink completed: %+v", got)
						}
						close(release)
						synctest.Wait()
					}
					var lost uint64
					if outcome != "success" {
						lost = 1
					}
					got := pool.stats.Snapshot(time.Now())
					if calls != 1 || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != lost || got.RecentDrops != lost {
						t.Fatalf("outcome settled incorrectly: calls=%d status=%+v", calls, got)
					}
				})
			})
		}
	}
}

func TestWriteQueueConcurrentFailuresConserveRecords(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := newWritePool(8)
		var succeeded, failed atomic.Uint64
		var writers sync.WaitGroup
		var seenMu sync.Mutex
		seen := make(map[int]int)
		for i := range 256 {
			writers.Go(func() {
				pool.write(sinkFunc(func(Record) error {
					seenMu.Lock()
					seen[i]++
					seenMu.Unlock()
					if i%3 == 0 {
						failed.Add(1)
						return errors.New("write refused")
					}
					succeeded.Add(1)
					return nil
				}), Record{Op: "test"})
			})
		}
		writers.Wait()
		got := pool.stats.Snapshot(time.Now())
		if got.Depth != 0 || got.InFlight != 0 || succeeded.Load() != 170 || failed.Load() != 86 || got.DroppedTotal != 86 || len(seen) != 256 {
			t.Fatalf("concurrent records disappeared: success=%d failed=%d unique=%d status=%+v", succeeded.Load(), failed.Load(), len(seen), got)
		}
		for id, count := range seen {
			if count != 1 {
				t.Errorf("record %d written %d times", id, count)
			}
		}
	})
}

func TestWriteOwnsRecordAfterCallerDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		recorded := make(chan Record, 1)
		SetSink(sinkFunc(func(r Record) error { <-release; recorded <- r; return nil }), "host.example")
		defer SetSink(nil, "")
		r := Record{Op: "test", Command: []string{"original"}, Before: &FileState{Digest: "before"}, After: &FileState{Digest: "after"}}
		Write(r)
		r.Command[0], r.Before.Digest, r.After.Digest = "changed", "changed", "changed"
		close(release)
		got := <-recorded
		synctest.Wait()
		if len(got.Command) != 1 || got.Command[0] != "original" || got.Before.Digest != "before" || got.After.Digest != "after" || got.Hostname != "host.example" || got.V != SchemaVersion || got.Timestamp.IsZero() {
			t.Fatalf("late sink read caller-owned buffers or lost stamping: %+v", got)
		}
	})
}

type blockedPanicLog struct{ release <-chan struct{} }

func (b blockedPanicLog) Write(p []byte) (int, error) {
	<-b.release
	return len(p), nil
}

func TestWriteQueueReportsLossBeforeBlockedPanicLog(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		previous := log.Writer()
		defer log.SetOutput(previous)
		release := make(chan struct{})
		releaseLog := sync.OnceFunc(func() { close(release) })
		defer releaseLog()
		log.SetOutput(blockedPanicLog{release: release})
		pool := newWritePool(1)
		pool.write(sinkFunc(func(Record) error { panic("failed") }), Record{Op: "panic"})
		synctest.Wait()
		got := pool.stats.Snapshot(time.Now())
		if got.InFlight != 1 || got.Depth != 0 || got.DroppedTotal != 1 {
			t.Fatalf("panic log hid known loss or released the writer early: %+v", got)
		}
		if late := pool.stats.Snapshot(time.Now().Add(time.Minute)); late.Reason != "processing_lag" {
			t.Fatalf("a writer blocked for a minute was not reported: %+v", late)
		}
		pool.write(sinkFunc(func(Record) error { t.Error("occupied slot accepted another writer"); return nil }), Record{Op: "refused"})
		releaseLog()
		synctest.Wait()
		got = pool.stats.Snapshot(time.Now())
		if got.InFlight != 0 || got.Depth != 0 || got.DroppedTotal != 2 {
			t.Fatalf("panic log recovery settled records incorrectly: %+v", got)
		}
	})
}

func TestWriteQueueDoesNotDegradeOnTheCallerBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := newWritePool(64)
		release := make(chan struct{})
		releaseWrite := sync.OnceFunc(func() { close(release) })
		defer releaseWrite()
		pool.write(sinkFunc(func(Record) error { <-release; return nil }), Record{Op: "slow"})
		synctest.Wait()
		got := pool.stats.Snapshot(time.Now())
		if got.InFlight != 1 || got.Status != "ok" || got.Reason != "" {
			t.Fatalf("a write past the caller budget was reported as a stalled queue: %+v", got)
		}
		if late := pool.stats.Snapshot(time.Now().Add(time.Minute)); late.Reason != "processing_lag" {
			t.Fatalf("a writer stalled for a minute was not reported: %+v", late)
		}
		releaseWrite()
		synctest.Wait()
	})
}
