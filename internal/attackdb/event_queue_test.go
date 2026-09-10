package attackdb

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/store"
)

func eventQueueStatus(t *testing.T, db *DB, now time.Time) queuehealth.Status {
	t.Helper()
	source, ok := any(db).(interface {
		QueueStatuses(time.Time) map[string]queuehealth.Status
	})
	if !ok {
		t.Fatal("attack database does not publish its event queue")
	}
	row, ok := source.QueueStatuses(now)["events"]
	if !ok {
		t.Fatal("attack database event queue is missing")
	}
	if !row.CapacityUnavailable || row.Capacity != 0 {
		t.Fatalf("unbounded event buffer invented a capacity: %+v", row)
	}
	return row
}

func eventQueueFlatDB(t *testing.T) *DB {
	t.Helper()
	previous := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(previous) })
	return newTestDB(t)
}

func TestAttackEventQueueAdmissionUsesArrivalTime(t *testing.T) {
	db := eventQueueFlatDB(t)
	if s := eventQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.Status != "ok" {
		t.Fatalf("new queue: %+v", s)
	}
	for _, stamp := range []time.Time{time.Now().Add(-24 * time.Hour), time.Now().Add(24 * time.Hour), {}} {
		db.RecordFinding(alert.Finding{Check: "webshell", SourceIP: "198.51.100.23", Timestamp: stamp})
	}
	db.RecordFinding(alert.Finding{Check: "unmapped", SourceIP: "198.51.100.23"})
	db.RecordFinding(alert.Finding{Check: "webshell"})
	if s := eventQueueStatus(t, db, time.Now()); s.Depth != 3 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "ok" || s.LagSeconds >= 1 {
		t.Fatalf("arrival accounting: %+v", s)
	}
	if s := eventQueueStatus(t, db, time.Now().Add(2*time.Minute)); s.Depth != 3 || s.Status != "degraded" || s.Reason != "backlog_lag" {
		t.Fatalf("waiting backlog concealed: %+v", s)
	}
	db.mu.Lock()
	done := make(chan queuehealth.Status, 1)
	go func() {
		source := any(db).(interface {
			QueueStatuses(time.Time) map[string]queuehealth.Status
		})
		done <- source.QueueStatuses(time.Now())["events"]
	}()
	select {
	case s := <-done:
		if s.Depth != 3 {
			t.Errorf("locked-state snapshot: %+v", s)
		}
	case <-time.After(time.Second):
		t.Error("health waits for attack database state lock")
	}
	db.mu.Unlock()
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	if s := eventQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "ok" {
		t.Fatalf("completed queue: %+v", s)
	}
	if got := db.QueryEvents("198.51.100.23", 10); len(got) != 3 {
		t.Fatalf("persisted %d events, want 3", len(got))
	}
}

func TestAttackEventQueuePersistenceOutcomes(t *testing.T) {
	for _, backend := range []string{"file", "bbolt"} {
		t.Run(backend, func(t *testing.T) {
			db := eventQueueFlatDB(t)
			if backend == "bbolt" {
				_, cleanup := setupBboltStore(t)
				t.Cleanup(cleanup)
			}
			for i := 0; i < 3; i++ {
				db.RecordFinding(findingFromIP("198.51.100.23"))
			}
			if err := db.Flush(); err != nil {
				t.Fatal(err)
			}
			if got := db.QueryEvents("198.51.100.23", 10); len(got) != 3 {
				t.Fatalf("persisted %d events, want 3", len(got))
			}
			if s := eventQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "ok" {
				t.Fatalf("successful flush: %+v", s)
			}
			if backend == "bbolt" {
				if err := store.Global().Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				// A directory in place of the append target gives a deterministic open error.
				db.dbPath = t.TempDir()
				if err := os.Mkdir(filepath.Join(db.dbPath, eventsFile), 0700); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 3; i++ {
				db.RecordFinding(findingFromIP("198.51.100.23"))
			}
			if err := db.Flush(); err != nil {
				t.Fatal(err)
			}
			if s := eventQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 3 || s.RecentDrops != 3 || s.Status != "degraded" || s.Reason != "dropped_work" || s.DroppedLowerBound {
				t.Fatalf("failed flush: %+v", s)
			}
			if err := db.Flush(); err != nil {
				t.Fatal(err)
			}
			if s := eventQueueStatus(t, db, time.Now().Add(2*time.Minute)); s.DroppedTotal != 3 || s.RecentDrops != 0 || s.Status != "ok" {
				t.Fatalf("loss counter did not survive recovery: %+v", s)
			}
		})
	}
}

func TestAttackEventQueueSeedAndShutdown(t *testing.T) {
	db := eventQueueFlatDB(t)
	statePath := t.TempDir()
	if err := os.Mkdir(filepath.Join(statePath, "threat_db"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(statePath, "threat_db", "permanent.txt"), []byte("198.51.100.23\n203.0.113.24\n198.51.100.23\ninvalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if n := db.SeedFromPermanentBlocklist(statePath); n != 2 {
		t.Fatalf("seeded %d, want 2", n)
	}
	if s := eventQueueStatus(t, db, time.Now()); s.Depth != 2 || s.InFlight != 0 || s.DroppedTotal != 0 {
		t.Fatalf("seed queue: %+v", s)
	}
	db.Stop()
	if s := eventQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 {
		t.Fatalf("shutdown queue: %+v", s)
	}
	for _, ip := range []string{"198.51.100.23", "203.0.113.24"} {
		if got := db.QueryEvents(ip, 10); len(got) != 1 || got[0].CheckName != "permanent_blocklist_import" {
			t.Fatalf("persisted seed %s: %+v", ip, got)
		}
	}
}

func TestAttackEventQueueMemoryOnlyHasNoPersistenceWork(t *testing.T) {
	_ = eventQueueFlatDB(t)
	db := NewForTest(nil)
	db.RecordFinding(findingFromIP("198.51.100.23"))
	if s := eventQueueStatus(t, db, time.Now().Add(time.Hour)); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "ok" {
		t.Fatalf("memory-only database invented persistence: %+v", s)
	}
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	if s := eventQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "ok" {
		t.Fatalf("memory-only flush: %+v", s)
	}
}

type eventQueueFaultFile struct {
	write func([]byte) (int, error)
	close func() error
}

func (f eventQueueFaultFile) Write(p []byte) (int, error) { return f.write(p) }
func (f eventQueueFaultFile) Close() error                { return f.close() }

func TestAttackEventQueuePartialWriteAndCloseOwnership(t *testing.T) {
	for _, tc := range []struct {
		name     string
		complete int
		closeErr bool
	}{
		{"partial", 1, false}, {"short_write", 1, false}, {"close_error", 3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := eventQueueFlatDB(t)
			closing := make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			done := make(chan struct{})
			t.Cleanup(func() {
				unblock()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("event append did not finish")
				}
			})
			var written bytes.Buffer
			db.openEvents = func(string) (io.WriteCloser, error) {
				return eventQueueFaultFile{
					write: func(p []byte) (int, error) {
						if tc.complete == 3 {
							return written.Write(p)
						}
						n := bytes.IndexByte(p, '\n') + 1
						if n <= 0 {
							panic("encoder did not produce a complete record")
						}
						_, _ = written.Write(p[:n])
						if tc.name == "short_write" {
							return n, nil
						}
						return n, errors.New("test partial event write")
					},
					close: func() error {
						close(closing)
						<-release
						if tc.closeErr {
							return errors.New("test event close failure")
						}
						return nil
					},
				}, nil
			}
			for i := 0; i < 3; i++ {
				db.RecordFinding(findingFromIP("198.51.100.23"))
			}
			go func() { _ = db.Flush(); close(done) }()
			select {
			case <-closing:
			case <-time.After(5 * time.Second):
				t.Fatal("append did not reach close")
			}
			wantLoss := uint64(3 - tc.complete)
			if s := eventQueueStatus(t, db, time.Now().Add(2*time.Minute)); s.Depth != 0 || s.InFlight != 3 || s.DroppedTotal != wantLoss || s.Reason != "processing_lag" {
				t.Fatalf("cleanup hid ownership or known write loss: %+v", s)
			}
			unblock()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("append did not finish")
			}
			if n := bytes.Count(written.Bytes(), []byte{'\n'}); n != tc.complete {
				t.Fatalf("writer accepted %d complete records, want %d", n, tc.complete)
			}
			s := eventQueueStatus(t, db, time.Now())
			if s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != wantLoss || s.DroppedLowerBound != tc.closeErr {
				t.Fatalf("partial persistence outcome: %+v", s)
			}
			if tc.closeErr {
				if s.Status != "degraded" || s.Reason != "persistence_uncertain" {
					t.Fatalf("close error reported success: %+v", s)
				}
				if later := eventQueueStatus(t, db, time.Now().Add(2*time.Minute)); later.Status != "ok" || !later.DroppedLowerBound || later.DroppedTotal != 0 {
					t.Fatalf("uncertain historical loss forgotten: %+v", later)
				}
			}
		})
	}
}

func TestAttackEventQueueAppendPanicReleasesOwnership(t *testing.T) {
	for _, phase := range []string{"before_write", "after_write", "close"} {
		t.Run(phase, func(t *testing.T) {
			db := eventQueueFlatDB(t)
			closed := false
			var accepted bytes.Buffer
			db.openEvents = func(string) (io.WriteCloser, error) {
				return eventQueueFaultFile{
					write: func(p []byte) (int, error) {
						if phase == "before_write" {
							panic("test writer panic")
						}
						n, err := accepted.Write(p)
						if phase == "after_write" {
							panic("test writer panic after accepting bytes")
						}
						return n, err
					},
					close: func() error {
						closed = true
						if phase == "close" {
							panic("test close panic")
						}
						return nil
					},
				}, nil
			}
			for i := 0; i < 3; i++ {
				db.RecordFinding(findingFromIP("198.51.100.23"))
			}
			func() {
				defer func() {
					if recover() == nil {
						t.Error("file panic was not propagated")
					}
				}()
				_ = db.Flush()
			}()
			if !closed {
				t.Fatal("panicking append leaked its file")
			}
			want := 3
			if phase == "before_write" {
				want = 0
			}
			if n := bytes.Count(accepted.Bytes(), []byte{'\n'}); n != want {
				t.Fatalf("writer accepted %d records, want %d", n, want)
			}
			if s := eventQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || !s.DroppedLowerBound || s.Reason != "persistence_uncertain" {
				t.Fatalf("unreturned I/O invented an exact outcome: %+v", s)
			}
		})
	}
}

func TestAttackEventQueueWriterProgressResetsStall(t *testing.T) {
	db := eventQueueFlatDB(t)
	entered := make(chan int, 2)
	releaseFirst := make(chan struct{})
	releaseSecond := make(chan struct{})
	var firstOnce, secondOnce sync.Once
	unblock := func() { firstOnce.Do(func() { close(releaseFirst) }); secondOnce.Do(func() { close(releaseSecond) }) }
	done := make(chan struct{})
	t.Cleanup(func() {
		unblock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("progress flush did not finish")
		}
	})
	var data bytes.Buffer
	writes := 0
	db.openEvents = func(string) (io.WriteCloser, error) {
		return eventQueueFaultFile{
			write: func(p []byte) (int, error) {
				writes++
				if writes <= 2 {
					entered <- writes
					if writes == 1 {
						<-releaseFirst
					} else {
						<-releaseSecond
					}
				}
				return data.Write(p)
			}, close: func() error { return nil },
		}, nil
	}
	for i := 0; i < 100; i++ {
		db.RecordFinding(findingFromIP("198.51.100.23"))
	}
	go func() { _ = db.Flush(); close(done) }()
	select {
	case n := <-entered:
		if n != 1 {
			t.Fatalf("first write=%d", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first write missing")
	}
	q := db.eventHealth()
	q.mu.Lock()
	q.active.progress = time.Now().Add(-2 * time.Minute)
	q.mu.Unlock()
	if s := eventQueueStatus(t, db, time.Now()); s.Reason != "processing_lag" || s.InFlight != 100 {
		t.Fatalf("stalled write missing: %+v", s)
	}
	firstOnce.Do(func() { close(releaseFirst) })
	select {
	case n := <-entered:
		if n != 2 {
			t.Fatalf("second write=%d", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second write missing")
	}
	if s := eventQueueStatus(t, db, time.Now()); s.Status != "ok" || s.InFlight != 100 || s.ProcessingSeconds >= 1 || s.LagBasis != "operation_progress" {
		t.Fatalf("completed write did not advance batch progress: %+v", s)
	}
	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("flush did not finish")
	}
	if n := bytes.Count(data.Bytes(), []byte{'\n'}); n != 100 {
		t.Fatalf("wrote %d records, want 100", n)
	}
	if s := eventQueueStatus(t, db, time.Now()); s.Status != "ok" || s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 {
		t.Fatalf("completed progressing batch: %+v", s)
	}
}

func TestAttackEventQueueEncodingFailureCountsOnlyMissingEvent(t *testing.T) {
	for _, backend := range []string{"file", "bbolt"} {
		t.Run(backend, func(t *testing.T) {
			db := eventQueueFlatDB(t)
			if backend == "bbolt" {
				_, cleanup := setupBboltStore(t)
				t.Cleanup(cleanup)
			}
			for _, stamp := range []time.Time{time.Now(), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), time.Now()} {
				db.RecordFinding(alert.Finding{Check: "webshell", SourceIP: "198.51.100.23", Timestamp: stamp})
			}
			if err := db.Flush(); err != nil {
				t.Fatal(err)
			}
			if got := db.QueryEvents("198.51.100.23", 10); len(got) != 2 {
				t.Fatalf("persisted %d events, want 2", len(got))
			}
			if s := eventQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 1 || s.DroppedLowerBound {
				t.Fatalf("encoding failure lost healthy neighbors: %+v", s)
			}
		})
	}
}

func TestAttackEventQueueAbandonedTailIsKnownLoss(t *testing.T) {
	for _, exitMode := range []string{"panic", "goexit"} {
		for _, scenario := range []string{"large_first", "marshal_before"} {
			t.Run(exitMode+"/"+scenario, func(t *testing.T) {
				db := eventQueueFlatDB(t)
				first := findingFromIP("198.51.100.23")
				wantLoss, wantSubmitted := uint64(2), 1
				if scenario == "large_first" {
					first.TenantID = strings.Repeat("a", 12000)
				} else {
					first.Timestamp = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
					wantLoss, wantSubmitted = 1, 2
				}
				db.RecordFinding(first)
				db.RecordFinding(findingFromIP("203.0.113.24"))
				db.RecordFinding(findingFromIP("203.0.113.25"))
				submitted := 0
				closed := false
				db.openEvents = func(string) (io.WriteCloser, error) {
					return eventQueueFaultFile{
						write: func(p []byte) (int, error) {
							submitted = bytes.Count(p, []byte{'\n'})
							if exitMode == "goexit" {
								runtime.Goexit()
							}
							panic("interrupted event writer")
						},
						close: func() error { closed = true; return nil },
					}, nil
				}
				done := make(chan struct{})
				returned, recovered := false, false
				go func() {
					defer close(done)
					defer func() { recovered = recover() != nil }()
					_ = db.Flush()
					returned = true
				}()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("interrupted flush did not release its caller")
				}
				if returned || recovered != (exitMode == "panic") || !closed {
					t.Fatalf("wrong exit lifecycle: returned=%v recovered=%v closed=%v", returned, recovered, closed)
				}
				if submitted != wantSubmitted {
					t.Fatalf("writer received %d complete events, want %d", submitted, wantSubmitted)
				}
				if s := eventQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != wantLoss || !s.DroppedLowerBound || s.Reason != "persistence_uncertain" {
					t.Fatalf("known abandoned work was hidden by uncertain current I/O: %+v", s)
				}
			})
		}
	}
}

func TestAttackEventQueueKnownLossVisibleBeforeCleanup(t *testing.T) {
	db := eventQueueFlatDB(t)
	for i := 0; i < 4; i++ {
		f := findingFromIP("198.51.100.23")
		if i == 0 {
			f.Timestamp = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		}
		if i == 1 {
			f.TenantID = strings.Repeat("a", 12000)
		}
		db.RecordFinding(f)
	}
	writing, closing := make(chan struct{}), make(chan struct{})
	releaseWrite, releaseClose := make(chan struct{}), make(chan struct{})
	var writeOnce, closeOnce sync.Once
	done := make(chan struct{})
	t.Cleanup(func() {
		writeOnce.Do(func() { close(releaseWrite) })
		closeOnce.Do(func() { close(releaseClose) })
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("interrupted flush still blocked")
		}
	})
	var accepted bytes.Buffer
	db.openEvents = func(string) (io.WriteCloser, error) {
		return eventQueueFaultFile{
			write: func(p []byte) (int, error) {
				close(writing)
				<-releaseWrite
				_, _ = accepted.Write(p)
				panic("writer interrupted after accepting bytes")
			},
			close: func() error { close(closing); <-releaseClose; return nil },
		}, nil
	}
	panicked := false
	go func() { defer close(done); defer func() { panicked = recover() != nil }(); _ = db.Flush() }()
	select {
	case <-writing:
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not start")
	}
	if s := eventQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 4 || s.DroppedTotal != 1 {
		t.Fatalf("returned marshal failure hidden by blocked writer: %+v", s)
	}
	writeOnce.Do(func() { close(releaseWrite) })
	select {
	case <-closing:
	case <-time.After(5 * time.Second):
		t.Fatal("close did not start")
	}
	if s := eventQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 4 || s.DroppedTotal != 3 || !s.DroppedLowerBound || s.Reason != "persistence_uncertain" {
		t.Fatalf("cleanup hid known tail loss or uncertain write: %+v", s)
	}
	closeOnce.Do(func() { close(releaseClose) })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("flush did not release")
	}
	if !panicked || bytes.Count(accepted.Bytes(), []byte{'\n'}) != 1 {
		t.Fatalf("incorrect fault setup: panicked=%v accepted=%d", panicked, bytes.Count(accepted.Bytes(), []byte{'\n'}))
	}
	if s := eventQueueStatus(t, db, time.Now()); s.InFlight != 0 || s.DroppedTotal != 3 || !s.DroppedLowerBound {
		t.Fatalf("cleanup double-counted abandoned work: %+v", s)
	}
}
