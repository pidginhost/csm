package processctx

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestProcReadQueueRetainsTimedOutSyscalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := newProcReadPool(64)
		release := make(chan struct{})
		releaseReads := sync.OnceFunc(func() { close(release) })
		defer func() { releaseReads(); synctest.Wait() }()
		var calls, returned atomic.Int32
		for range 64 {
			go func() {
				data, ok := runProcReadWithDeadline(pool, time.Second, func() ([]byte, error) {
					calls.Add(1)
					<-release
					return []byte("late"), nil
				})
				if ok || data != nil {
					t.Errorf("timed-out read delivered a result: ok=%v data=%q", ok, data)
				}
				returned.Add(1)
			}()
		}
		synctest.Wait()
		got := pool.stats.Snapshot(time.Now())
		if calls.Load() != 64 || returned.Load() != 0 || got.Capacity != 64 || got.Depth != 0 || got.InFlight != 64 || got.DroppedTotal != 0 {
			t.Fatalf("admitted syscalls missing from health: calls=%d returned=%d status=%+v", calls.Load(), returned.Load(), got)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		got = pool.stats.Snapshot(time.Now())
		if returned.Load() != 64 || got.InFlight != 64 || got.DroppedTotal != 64 {
			t.Fatalf("deadline expiry released occupied slots or concealed loss: returned=%d status=%+v", returned.Load(), got)
		}
		for range 2 {
			if _, ok := runProcReadWithDeadline(pool, time.Second, func() (string, error) {
				t.Error("saturated pool started another syscall")
				return "unexpected", nil
			}); ok {
				t.Error("saturated pool accepted another request")
			}
		}
		time.Sleep(61 * time.Second)
		got = pool.stats.Snapshot(time.Now())
		if got.Depth != 0 || got.InFlight != 64 || got.DroppedTotal != 66 || got.RecentDrops != 0 || got.ProcessingSeconds != 62 || got.Status != "degraded" {
			t.Fatalf("old timeouts concealed still-running syscalls: %+v", got)
		}
		releaseReads()
		synctest.Wait()
		got = pool.stats.Snapshot(time.Now())
		if len(pool.slots) != 0 || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 66 || got.Status != "ok" {
			t.Fatalf("late completion erased loss, counted it twice or failed to recover: slots=%d status=%+v", len(pool.slots), got)
		}
	})
}

func TestProcReadQueueDistinguishesDisappearanceFromReadFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := newProcReadPool(2)
		var calls atomic.Int32
		for _, readErr := range []error{nil, fs.ErrNotExist, &fs.PathError{Op: "read", Path: "gone", Err: fs.ErrNotExist}, fs.ErrPermission} {
			got, ok := runProcReadWithDeadline(pool, time.Second, func() (string, error) {
				calls.Add(1)
				return "result", readErr
			})
			if ok != (readErr == nil) || (readErr == nil && got != "result") || (readErr != nil && got != "") {
				t.Fatalf("read return semantics changed: error=%v result=%q ok=%v", readErr, got, ok)
			}
		}
		synctest.Wait()
		got := pool.stats.Snapshot(time.Now())
		if calls.Load() != 4 || len(pool.slots) != 0 || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 1 || got.Status != "ok" {
			t.Fatalf("expected process disappearance counted as failure: calls=%d slots=%d status=%+v", calls.Load(), len(pool.slots), got)
		}
	})
}

func TestProcReadQueueCountsLateFailureOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := newProcReadPool(2)
		release := make(chan struct{})
		releaseRead := sync.OnceFunc(func() { close(release) })
		defer func() { releaseRead(); synctest.Wait() }()
		if _, ok := runProcReadWithDeadline(pool, time.Second, func() ([]byte, error) {
			<-release
			return nil, errors.New("late I/O failure")
		}); ok {
			t.Fatal("blocked read completed before its deadline")
		}
		got := pool.stats.Snapshot(time.Now())
		if got.InFlight != 1 || got.DroppedTotal != 1 {
			t.Fatalf("timeout lost occupied work: %+v", got)
		}
		releaseRead()
		synctest.Wait()
		got = pool.stats.Snapshot(time.Now())
		if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 1 || len(pool.slots) != 0 {
			t.Fatalf("late error counted the timed-out result twice: %+v", got)
		}
	})
}

func TestProcReadQueueSynchronousReadsDoNotConsumeSlots(t *testing.T) {
	pool := newProcReadPool(1)
	pool.slots <- struct{}{}
	defer func() { <-pool.slots }()
	for _, readErr := range []error{nil, fs.ErrPermission} {
		got, ok := runProcReadWithDeadline(pool, 0, func() (string, error) { return "direct", readErr })
		if got != "direct" || ok != (readErr == nil) {
			t.Fatalf("synchronous read changed: error=%v result=%q ok=%v", readErr, got, ok)
		}
	}
	got := pool.stats.Snapshot(time.Now())
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 {
		t.Fatalf("synchronous work was counted against deadline slots: %+v", got)
	}
}

func TestProcReadQueueRetainsUndeliveredResults(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := newProcReadPool(1)
		work := pool.acquire()
		if work == nil {
			t.Fatal("empty pool refused a read")
		}
		out := make(chan procReadResult[string], 1)
		executeProcRead(work, func() (string, error) { return "ready", nil }, out)
		time.Sleep(61 * time.Second)
		got := pool.stats.Snapshot(time.Now())
		if len(pool.slots) != 1 || got.Depth != 0 || got.InFlight != 1 || got.ProcessingSeconds != 61 || got.Status != "degraded" {
			t.Fatalf("completed syscall concealed its undelivered result: slots=%d status=%+v", len(pool.slots), got)
		}
		if _, ok := runProcReadWithDeadline(pool, time.Second, func() (string, error) {
			t.Error("undelivered result released its admission slot")
			return "unexpected", nil
		}); ok {
			t.Error("pool admitted a read while its result slot was occupied")
		}
		if res := <-out; res.value != "ready" || res.err != nil {
			t.Fatalf("held result changed: %+v", res)
		}
		work.release()
		got = pool.stats.Snapshot(time.Now())
		if len(pool.slots) != 0 || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 1 || got.Status != "ok" {
			t.Fatalf("consuming a result did not release its slot: slots=%d status=%+v", len(pool.slots), got)
		}
	})
}

func TestProcReadQueuePanicCountsOnlyItsOwnedRead(t *testing.T) {
	pool := newProcReadPool(2)
	failed, waiting := pool.acquire(), pool.acquire()
	if failed == nil || waiting == nil {
		t.Fatal("empty pool refused initial reads")
	}
	var caught any
	func() {
		defer func() { caught = recover() }()
		executeProcRead(failed, func() (string, error) { panic("read failed") }, make(chan procReadResult[string], 1))
	}()
	if caught != "read failed" {
		t.Fatalf("syscall panic was concealed: %v", caught)
	}
	got := pool.stats.Snapshot(time.Now())
	if got.Depth != 1 || got.InFlight != 1 || got.DroppedTotal != 1 {
		t.Fatalf("panic damaged waiting work or lost the result still awaited: %+v", got)
	}
	failed.fail()
	failed.release()
	got = pool.stats.Snapshot(time.Now())
	if got.Depth != 1 || got.InFlight != 0 || got.DroppedTotal != 1 || len(pool.slots) != 1 {
		t.Fatalf("caller timeout after panic counted the loss twice: %+v", got)
	}
	out := make(chan procReadResult[string], 1)
	executeProcRead(waiting, func() (string, error) { return "unrelated", nil }, out)
	if res := <-out; res.value != "unrelated" || res.err != nil {
		t.Fatalf("panic damaged an unrelated result: %+v", res)
	}
	waiting.release()
	got = pool.stats.Snapshot(time.Now())
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 1 || len(pool.slots) != 0 {
		t.Fatalf("later success changed panic evidence: %+v", got)
	}
}

func TestProcReadQueueConcurrentDeadlinesConserveResults(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := newProcReadPool(8)
		const attempts = 256
		var calls, successful atomic.Int32
		var callers sync.WaitGroup
		for range attempts {
			callers.Go(func() {
				value, ok := runProcReadWithDeadline(pool, time.Second, func() (string, error) {
					calls.Add(1)
					time.Sleep(time.Second)
					return "complete", nil
				})
				if ok {
					if value != "complete" {
						t.Errorf("successful read lost its value: %q", value)
					}
					successful.Add(1)
				} else if value != "" {
					t.Errorf("failed read leaked a late value: %q", value)
				}
			})
		}
		synctest.Wait()
		if calls.Load() != 8 {
			t.Fatalf("concurrent callers exceeded or failed to fill the cap: calls=%d", calls.Load())
		}
		callers.Wait()
		synctest.Wait()
		got := pool.stats.Snapshot(time.Now())
		if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != uint64(attempts-successful.Load()) || len(pool.slots) != 0 {
			t.Fatalf("deadline/completion races lost or repeated results: successes=%d status=%+v", successful.Load(), got)
		}
	})
}

func TestProcReadQueueFileAndLinkHelpersPublishTheirFailures(t *testing.T) {
	waitForProcReadSlots(t, 0)
	root := t.TempDir()
	regular := filepath.Join(root, "regular")
	if err := os.WriteFile(regular, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	reader := NewProcReader(root, time.Second)
	before := reader.QueueStatuses(time.Now())["proc_reads"]
	if _, ok := readFileWithDeadline(root, time.Second); ok {
		t.Error("directory was read as a process file")
	}
	if _, ok := readlinkWithDeadline(regular, time.Second); ok {
		t.Error("regular file was read as a symlink")
	}
	if _, ok := runBytesWithDeadline(time.Second, func() ([]byte, error) { return nil, fs.ErrPermission }); ok {
		t.Error("failed byte read returned success")
	}
	missing := filepath.Join(root, "gone")
	if _, ok := readFileWithDeadline(missing, time.Second); ok {
		t.Error("missing file was read successfully")
	}
	if _, ok := readlinkWithDeadline(missing, time.Second); ok {
		t.Error("missing symlink was read successfully")
	}
	waitForProcReadSlots(t, 0)
	got := reader.QueueStatuses(time.Now())["proc_reads"]
	if got.Capacity != 64 || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != before.DroppedTotal+3 || got.Status != "degraded" {
		t.Fatalf("file/link errors did not reach the shared provider: before=%+v after=%+v", before, got)
	}
}

func TestProcReadQueueIsAdvisory(t *testing.T) {
	reader := NewProcReader(t.TempDir(), time.Second)
	if got := reader.QueueStatuses(time.Now())["proc_reads"]; !got.Advisory {
		t.Fatalf("expired process context reads can degrade the host: %+v", got)
	}
}
