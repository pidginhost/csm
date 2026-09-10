package reporting

import (
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

func enqueueSpoolBody(t *testing.T, s *Spool, body string) int {
	t.Helper()
	dropped, err := s.Enqueue("collector", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return dropped
}

func TestSpoolHealthOverflowAndFIFO(t *testing.T) {
	s := newSpool(t, 3)
	for i, body := range []string{"a", "b", "c", "d", "e", "f"} {
		want := 0
		if i >= 3 {
			want = 1
		}
		if got := enqueueSpoolBody(t, s, body); got != want {
			t.Fatalf("enqueue %s dropped %d, want %d", body, got, want)
		}
	}
	got := s.QueueStatuses(time.Now())["spool"]
	if got.Depth != 3 || got.Capacity != 3 || got.InFlight != 0 || got.DroppedTotal != 3 || got.RecentDrops != 3 || got.Reason != "dropped_work" || got.Status != "degraded" || got.LagBasis != "observed_age" {
		t.Fatalf("overflow evidence: %+v", got)
	}
	var bodies []string
	n, err := s.Drain(func(target string, body []byte) error {
		if target != "collector" {
			t.Errorf("target = %s", target)
		}
		bodies = append(bodies, string(body))
		return nil
	})
	if err != nil || n != 3 || !reflect.DeepEqual(bodies, []string{"d", "e", "f"}) {
		t.Fatalf("drain %d, %v, %v", n, err, bodies)
	}
	got = s.QueueStatuses(time.Now().Add(time.Minute))["spool"]
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 || got.RecentDrops != 0 || got.Status != "ok" {
		t.Fatalf("recovered queue lost its cumulative evidence: %+v", got)
	}
}

func TestSpoolHealthRetryPreservesAgeAndReportsFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSpool(t, 8)
		enqueueSpoolBody(t, s, "a")
		enqueueSpoolBody(t, s, "b")
		outage := errors.New("collector unavailable")
		for i := range 2 {
			time.Sleep(61 * time.Second)
			n, err := s.Drain(func(string, []byte) error { return outage })
			if n != 0 || !errors.Is(err, outage) {
				t.Fatalf("retry %d: delivered=%d err=%v", i, n, err)
			}
			got := s.QueueStatuses(time.Now())["spool"]
			if got.Depth != 2 || got.InFlight != 0 || got.DroppedTotal != 0 || got.LagSeconds != float64((i+1)*61) || got.Status != "degraded" || got.Reason != "delivery_failed" {
				t.Fatalf("retry reset age or lost retained work: %+v", got)
			}
		}
		calls := 0
		n, err := s.Drain(func(string, []byte) error { calls++; return nil })
		if n != 2 || calls != 2 || err != nil {
			t.Fatalf("recovery delivered=%d calls=%d err=%v", n, calls, err)
		}
		got := s.QueueStatuses(time.Now())["spool"]
		if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 || got.Status != "ok" || got.Reason != "" {
			t.Fatalf("delivery failure did not recover: %+v", got)
		}
	})
}

func TestSpoolHealthBlockedSenderAndConcurrentEviction(t *testing.T) {
	for _, outcome := range []string{"success", "error", "panic"} {
		t.Run(outcome, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newSpool(t, 2)
				enqueueSpoolBody(t, s, "a")
				enqueueSpoolBody(t, s, "b")
				release, done := make(chan struct{}), make(chan struct{})
				releaseSend := sync.OnceFunc(func() { close(release) })
				var delivered int
				var drainErr error
				var caught any
				var bodies []string
				outage := errors.New("send failed")
				go func() {
					defer close(done)
					defer func() { caught = recover() }()
					delivered, drainErr = s.Drain(func(_ string, body []byte) error {
						bodies = append(bodies, string(body))
						if string(body) != "a" {
							return nil
						}
						<-release
						switch outcome {
						case "error":
							return outage
						case "panic":
							panic("send panic")
						}
						return nil
					})
				}()
				defer func() { releaseSend(); <-done }()
				synctest.Wait()
				time.Sleep(121 * time.Second)
				got := s.QueueStatuses(time.Now())["spool"]
				if got.Depth != 1 || got.InFlight != 1 || got.DroppedTotal != 0 || got.LagSeconds != 121 || got.ProcessingSeconds != 121 || got.Status != "degraded" {
					t.Fatalf("blocked sender hidden: %+v", got)
				}
				if enqueueSpoolBody(t, s, "c") != 1 || enqueueSpoolBody(t, s, "d") != 1 {
					t.Fatal("expected eviction of active a and queued b")
				}
				got = s.QueueStatuses(time.Now())["spool"]
				if got.Depth != 2 || got.InFlight != 1 || got.DroppedTotal != 1 {
					t.Fatalf("active eviction counted as loss before outcome: %+v", got)
				}
				releaseSend()
				<-done
				got = s.QueueStatuses(time.Now())["spool"]
				if outcome == "success" {
					if delivered != 3 || drainErr != nil || caught != nil || !reflect.DeepEqual(bodies, []string{"a", "c", "d"}) || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 1 {
						t.Fatalf("successful evicted send: n=%d err=%v panic=%v bodies=%v status=%+v", delivered, drainErr, caught, bodies, got)
					}
				} else {
					if outcome == "error" && (!errors.Is(drainErr, outage) || caught != nil) {
						t.Fatalf("error=%v panic=%v", drainErr, caught)
					}
					if outcome == "panic" && caught != "send panic" {
						t.Fatalf("panic = %v", caught)
					}
					if delivered != 0 || got.Depth != 2 || got.InFlight != 0 || got.DroppedTotal != 2 || got.Reason != "delivery_failed" || !reflect.DeepEqual(bodies, []string{"a"}) {
						t.Fatalf("failed evicted send: n=%d bodies=%v status=%+v", delivered, bodies, got)
					}
					n, err := s.Drain(func(string, []byte) error { return nil })
					if n != 2 || err != nil {
						t.Fatalf("remaining reports: %d %v", n, err)
					}
				}
			})
		})
	}
}

func TestSpoolHealthReopenObservesExistingWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "reports.db")
		s, err := NewSpool(path, "reports", 3)
		if err != nil {
			t.Fatal(err)
		}
		for _, body := range []string{"a", "b", "c"} {
			enqueueSpoolBody(t, s, body)
		}
		time.Sleep(time.Hour)
		if closeErr := s.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		got := s.QueueStatuses(time.Now())["spool"]
		if got.Depth != 3 || got.DroppedTotal != 0 || got.LagSeconds != 3600 {
			t.Fatalf("close discarded durable evidence: %+v", got)
		}
		s, err = NewSpool(path, "reports", 2)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Close() }()
		got = s.QueueStatuses(time.Now())["spool"]
		if got.Depth != 3 || got.Capacity != 2 || got.DroppedTotal != 0 || got.LagSeconds != 0 || got.LagBasis != "observed_age" {
			t.Fatalf("reopen invented age or trimmed stored work: %+v", got)
		}
		time.Sleep(121 * time.Second)
		if got = s.QueueStatuses(time.Now())["spool"]; got.LagSeconds != 121 || got.Reason != "backlog_lag" {
			t.Fatalf("reopened work does not age: %+v", got)
		}
		n, err := s.Drain(func(string, []byte) error { return nil })
		if n != 3 || err != nil {
			t.Fatalf("reopened drain = %d, %v", n, err)
		}
	})
}

func TestSpoolHealthClosedDatabaseKeepsCommittedWork(t *testing.T) {
	s := newSpool(t, 3)
	enqueueSpoolBody(t, s, "retained")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if dropped, err := s.Enqueue("collector", []byte("refused")); dropped != 0 || !errors.Is(err, bolterrors.ErrDatabaseNotOpen) {
		t.Fatalf("failed admission: dropped=%d err=%v", dropped, err)
	}
	got := s.QueueStatuses(time.Now())["spool"]
	if got.Depth != 1 || got.InFlight != 0 || got.DroppedTotal != 1 || got.Status != "degraded" || got.Reason != "spool_io" {
		t.Fatalf("failed admission changed committed work: %+v", got)
	}
}

func TestSpoolHealthCorruptHeadIsVisibleAndRetained(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reports.db")
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if writeErr := db.Update(func(tx *bolt.Tx) error {
		b, bucketErr := tx.CreateBucket([]byte("reports"))
		if bucketErr != nil {
			return bucketErr
		}
		return b.Put([]byte{0, 0, 0, 0, 0, 0, 0, 0}, []byte("invalid json"))
	}); writeErr != nil {
		_ = db.Close()
		t.Fatal(writeErr)
	}
	if closeErr := db.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	s, err := NewSpool(path, "reports", 2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	calls := 0
	if n, err := s.Drain(func(string, []byte) error { calls++; return nil }); n != 0 || err == nil || calls != 0 {
		t.Fatalf("corrupt head: delivered=%d calls=%d err=%v", n, calls, err)
	}
	enqueueSpoolBody(t, s, "valid")
	got := s.QueueStatuses(time.Now())["spool"]
	if got.Depth != 2 || got.InFlight != 0 || got.DroppedTotal != 0 || got.Reason != "spool_io" {
		t.Fatalf("unrelated write hid a corrupt head: %+v", got)
	}
	if enqueueSpoolBody(t, s, "newest") != 1 {
		t.Fatal("expected corrupt record eviction at cap")
	}
	if n, err := s.Drain(func(string, []byte) error { calls++; return nil }); n != 2 || err != nil || calls != 2 {
		t.Fatalf("recovery: delivered=%d calls=%d err=%v", n, calls, err)
	}
	got = s.QueueStatuses(time.Now())["spool"]
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 1 || got.Status != "ok" {
		t.Fatalf("corrupt head did not recover: %+v", got)
	}
}
