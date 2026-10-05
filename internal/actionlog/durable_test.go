package actionlog

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

type durableSinkFunc func(Record) error

func (f durableSinkFunc) Write(Record) error {
	panic("best-effort method must not acknowledge durable delivery")
}
func (f durableSinkFunc) WriteDurable(r Record) error { return f(r) }

func TestWriteDurableRequiresAcknowledgingSink(t *testing.T) {
	for _, s := range []Sink{nil, &capturingSink{}} {
		SetSink(s, "")
		if err := WriteDurable(Record{ActionID: "action-1"}); err == nil {
			t.Fatal("unavailable durable sink acknowledged delivery")
		}
	}
	t.Cleanup(func() { SetSink(nil, "") })
}

// The file sink does real I/O. In a synctest bubble the write deadline only
// advances when every goroutine is blocked, so a slow disk on a loaded host
// cannot turn a durable append into a timeout.
func TestWriteDurableRetainsIdentityAcrossRetries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "nested", "logs", "actions.jsonl")
		SetSink(NewFileSink(func() string { return path }, nil), "example.test")
		t.Cleanup(func() { SetSink(nil, "") })
		r := Record{ActionID: "action-1", ActionVersion: 3, IncidentID: "incident-1", FindingID: "finding-1", UndoOf: "action-0", Op: "respond.block_ip", Target: "192.0.2.1", Result: Applied, Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
		for range 2 {
			if err := WriteDurable(r); err != nil {
				t.Fatal(err)
			}
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) != 2 {
			t.Fatalf("records=%d", len(lines))
		}
		for _, line := range lines {
			var got Record
			if err := json.Unmarshal([]byte(line), &got); err != nil {
				t.Fatal(err)
			}
			if got.ActionID != "action-1" || got.ActionVersion != 3 || got.IncidentID != "incident-1" || got.FindingID != "finding-1" || got.UndoOf != "action-0" || got.Timestamp != r.Timestamp || got.Hostname != "example.test" || got.V != SchemaVersion {
				t.Fatalf("identity or defaults lost: %+v", got)
			}
		}
	})
}

func TestWriteDurableReportsSinkErrorsAndTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		t.Cleanup(func() { SetSink(nil, "") })
		want := errors.New("durability failure")
		SetSink(durableSinkFunc(func(Record) error { return want }), "")
		if err := WriteDurable(Record{}); !errors.Is(err, want) {
			t.Fatalf("error=%v", err)
		}
		release := make(chan struct{})
		SetSink(durableSinkFunc(func(Record) error { <-release; return nil }), "")
		start := time.Now()
		if err := WriteDurable(Record{}); err == nil {
			t.Fatal("unacknowledged delivery reported success")
		}
		if time.Since(start) > writeTimeout {
			t.Fatalf("unbounded wait: %s", time.Since(start))
		}
		close(release)
		synctest.Wait()
	})
}

func TestFileSinkDurableReportsSyncFailureAfterAppend(t *testing.T) {
	for _, failDirectory := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "directory"}[failDirectory], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "actions.jsonl")
			sink := NewFileSink(func() string { return path }, nil)
			want := errors.New("sync failed")
			sink.syncFile = func(f *os.File) error {
				info, err := f.Stat()
				if err != nil {
					return err
				}
				if info.IsDir() == failDirectory {
					return want
				}
				return f.Sync()
			}
			if err := sink.WriteDurable(Record{ActionID: "action-1"}); !errors.Is(err, want) {
				t.Fatalf("error=%v", err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), `"action_id":"action-1"`) {
				t.Fatalf("record missing after uncertain sync: %s", data)
			}
		})
	}
}

func TestFileSinkDurableRotationSyncsNewDirectoryEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "actions.jsonl")
	if err := os.WriteFile(path, make([]byte, maxFileSize+1), 0600); err != nil {
		t.Fatal(err)
	}
	sink := NewFileSink(func() string { return path }, nil)
	var fileSynced, directorySynced bool
	sink.syncFile = func(f *os.File) error {
		if f.Name() == path {
			fileSynced = true
		}
		if f.Name() == dir {
			if !fileSynced {
				t.Error("directory synced before record")
			}
			if _, err := os.Stat(path + ".1"); err != nil {
				t.Error(err)
			}
			directorySynced = true
		}
		return f.Sync()
	}
	if err := sink.WriteDurable(Record{ActionID: "action-1"}); err != nil {
		t.Fatal(err)
	}
	if !fileSynced || !directorySynced {
		t.Fatal("rotation acknowledged without syncing new file and parent directory")
	}
}

func TestWriteDurableSharesOutstandingWorkBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		priorPool := actionWrites
		actionWrites = newWritePool(2)
		defer func() { actionWrites = priorPool }()
		t.Cleanup(func() { SetSink(nil, "") })
		release := make(chan struct{})
		SetSink(sinkFunc(func(Record) error { <-release; return nil }), "")
		for range cap(actionWrites.slots) {
			Write(Record{})
		}
		called := false
		SetSink(durableSinkFunc(func(Record) error { called = true; return nil }), "")
		err := WriteDurable(Record{})
		synctest.Wait()
		if !errors.Is(err, ErrDurableUnacknowledged) || called {
			t.Errorf("saturated shared pool started another write: called=%v err=%v", called, err)
		}
		close(release)
		synctest.Wait()
		if err := WriteDurable(Record{}); err != nil {
			t.Fatal(err)
		}
		if !called {
			t.Fatal("recovered capacity did not admit durable delivery")
		}
	})
}

func TestWriteDurableCopiesBuffersBeforeCallerTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		t.Cleanup(func() { SetSink(nil, "") })
		release := make(chan struct{})
		delivered := make(chan Record, 1)
		SetSink(durableSinkFunc(func(r Record) error { <-release; delivered <- r; return nil }), "")
		r := Record{Command: []string{"original"}, Before: &FileState{Size: 1}, After: &FileState{Size: 2}}
		if err := WriteDurable(r); !errors.Is(err, ErrDurableUnacknowledged) {
			t.Errorf("error=%v", err)
		}
		r.Command[0] = "changed"
		r.Before.Size = 9
		r.After.Size = 10
		close(release)
		synctest.Wait()
		got := <-delivered
		if got.Command[0] != "original" || got.Before.Size != 1 || got.After.Size != 2 {
			t.Fatalf("late write retained caller-owned memory: %+v", got)
		}
	})
}

func TestWriteDurableDoesNotAcknowledgeSinkPanic(t *testing.T) {
	SetSink(durableSinkFunc(func(Record) error { panic("sink failure") }), "")
	t.Cleanup(func() { SetSink(nil, "") })
	if err := WriteDurable(Record{}); !errors.Is(err, ErrDurableUnacknowledged) {
		t.Fatalf("panic acknowledged: %v", err)
	}
}

type batchSinkFunc func([]Record) error

func (f batchSinkFunc) Write(Record) error {
	panic("best-effort method must not acknowledge durable delivery")
}
func (f batchSinkFunc) WriteDurableBatch(rs []Record) error { return f(rs) }

// Spec 5.5: a delivery batch is written and synced once. Every record gets
// the stream's defaults, and an empty batch writes nothing.
func TestFileSinkDurableBatchSyncsOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "actions.jsonl")
	sink := NewFileSink(func() string { return path }, nil)
	syncs := 0
	sink.syncFile = func(f *os.File) error {
		if f.Name() == path {
			syncs++
		}
		return f.Sync()
	}
	SetSink(sink, "example.test")
	t.Cleanup(func() { SetSink(nil, "") })
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	batch := []Record{{ActionID: "act-1", ActionVersion: 2, Timestamp: at, Op: "respond.block_ip"}, {ActionID: "act-1", ActionVersion: 3, Timestamp: at, Op: "respond.block_ip"}}
	if err := WriteDurableBatch(batch); err != nil {
		t.Fatal(err)
	}
	if err := WriteDurableBatch(nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 || syncs != 1 {
		t.Fatalf("%d lines with %d syncs, want 2 lines and one sync", len(lines), syncs)
	}
	for i, line := range lines {
		var got Record
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatal(err)
		}
		if got.ActionVersion != batch[i].ActionVersion || got.Hostname != "example.test" || got.V != SchemaVersion || got.Actor != Daemon {
			t.Fatalf("record %d = %+v", i, got)
		}
	}
	sink.syncFile = func(*os.File) error { return errors.New("sync failed") }
	if err := WriteDurableBatch(batch); err == nil {
		t.Fatal("a failed sync acknowledged the batch")
	}
}

func TestWriteDurableBatchNeedsABatchSink(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		t.Cleanup(func() { SetSink(nil, "") })
		for _, s := range []Sink{nil, &capturingSink{}, durableSinkFunc(func(Record) error { return nil })} {
			SetSink(s, "")
			if err := WriteDurableBatch([]Record{{}}); !errors.Is(err, ErrDurableUnavailable) {
				t.Fatalf("sink %T: %v", s, err)
			}
		}
		want := errors.New("durability failure")
		SetSink(batchSinkFunc(func([]Record) error { return want }), "")
		if err := WriteDurableBatch([]Record{{}}); !errors.Is(err, want) {
			t.Fatalf("error=%v", err)
		}
		release := make(chan struct{})
		SetSink(batchSinkFunc(func([]Record) error { <-release; return nil }), "")
		if err := WriteDurableBatch([]Record{{}}); !errors.Is(err, ErrDurableUnacknowledged) {
			t.Fatalf("an unfinished batch = %v", err)
		}
		close(release)
		synctest.Wait()
	})
}

// Batches share one bounded writer slot while every failed record is counted.
func TestWriteDurableBatchConservesPoolRecords(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		previous := actionWrites
		actionWrites = newWritePool(1)
		defer func() { actionWrites = previous; SetSink(nil, "") }()
		batch := []Record{{Command: []string{"original"}}, {}, {}}
		want := errors.New("batch failed")
		SetSink(batchSinkFunc(func([]Record) error { return want }), "")
		if err := WriteDurableBatch(batch); !errors.Is(err, want) {
			t.Fatalf("batch failure: %v", err)
		}
		assertState := func(inFlight int, lost uint64) {
			t.Helper()
			got := QueueStatus(time.Now())
			if got.Depth != 0 || got.InFlight != inFlight || got.DroppedTotal != lost || got.RecentDrops != lost {
				t.Fatalf("batch accounting: %+v, want active=%d lost=%d", got, inFlight, lost)
			}
		}
		assertState(0, 3)
		release := make(chan struct{})
		releaseWrite := sync.OnceFunc(func() { close(release) })
		defer releaseWrite()
		calls, command := 0, ""
		SetSink(batchSinkFunc(func(rs []Record) error { calls++; <-release; command = rs[0].Command[0]; return nil }), "")
		if err := WriteDurableBatch(batch); !errors.Is(err, ErrDurableUnacknowledged) {
			t.Fatalf("late batch acknowledged: %v", err)
		}
		synctest.Wait()
		assertState(1, 3)
		batch[0].Command[0] = "changed"
		if err := WriteDurableBatch(batch); !errors.Is(err, ErrDurableUnacknowledged) {
			t.Fatalf("saturated batch acknowledged: %v", err)
		}
		synctest.Wait()
		assertState(1, 6)
		if calls != 1 {
			t.Fatalf("saturated pool started %d writes", calls)
		}
		releaseWrite()
		synctest.Wait()
		assertState(0, 6)
		if command != "original" {
			t.Fatalf("late batch read caller-owned command: %q", command)
		}
		SetSink(batchSinkFunc(func([]Record) error { panic("batch failed") }), "")
		if err := WriteDurableBatch(batch); !errors.Is(err, ErrDurableUnacknowledged) {
			t.Fatalf("panic acknowledged: %v", err)
		}
		synctest.Wait()
		assertState(0, 9)
	})
}
