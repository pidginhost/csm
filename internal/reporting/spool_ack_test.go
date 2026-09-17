package reporting

import (
	"errors"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

func TestSpoolHealthAcknowledgedOverflowIsNotLoss(t *testing.T) {
	for _, retryFails := range []bool{false, true} {
		name := "waiting"
		if retryFails {
			name = "failed_retry"
		}
		t.Run(name, func(t *testing.T) {
			s := newSpool(t, 1)
			path := s.db.Path()
			enqueueSpoolBody(t, s, "acknowledged")
			calls := 0
			n, err := s.Drain(func(target string, body []byte) error {
				calls++
				if target != "collector" || string(body) != "acknowledged" {
					t.Fatalf("unexpected first delivery: target=%s body=%s", target, body)
				}
				if closeErr := s.db.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
				return nil
			})
			if n != 0 || calls != 1 || !errors.Is(err, bolterrors.ErrDatabaseNotOpen) {
				t.Fatalf("acknowledgment/delete failure: delivered=%d calls=%d err=%v", n, calls, err)
			}
			status := s.QueueStatuses(time.Now())["spool"]
			if status.Depth != 1 || status.InFlight != 0 || status.DroppedTotal != 0 || status.Reason != "spool_io" {
				t.Fatalf("failed deletion did not retain acknowledged work: %+v", status)
			}
			db, openErr := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
			if openErr != nil {
				t.Fatal(openErr)
			}
			s.db = db
			if retryFails {
				outage := errors.New("collector unavailable on retry")
				n, err = s.Drain(func(_ string, body []byte) error {
					calls++
					if string(body) != "acknowledged" {
						t.Fatalf("retried wrong record: %s", body)
					}
					if dropped := enqueueSpoolBody(t, s, "replacement"); dropped != 1 {
						t.Fatalf("active eviction = %d, want 1", dropped)
					}
					return outage
				})
				if n != 0 || calls != 2 || !errors.Is(err, outage) {
					t.Fatalf("failed retry: delivered=%d calls=%d err=%v", n, calls, err)
				}
			} else if dropped := enqueueSpoolBody(t, s, "replacement"); dropped != 1 {
				t.Fatalf("waiting eviction = %d, want 1", dropped)
			}
			status = s.QueueStatuses(time.Now())["spool"]
			if status.Depth != 1 || status.InFlight != 0 || status.DroppedTotal != 0 || s.Len() != 1 {
				t.Fatalf("acknowledged report counted as lost: %+v", status)
			}
			replacements := 0
			n, err = s.Drain(func(target string, body []byte) error {
				replacements++
				if target != "collector" || string(body) != "replacement" {
					t.Fatalf("unexpected replacement: target=%s body=%s", target, body)
				}
				return nil
			})
			if n != 1 || replacements != 1 || err != nil {
				t.Fatalf("replacement drain: delivered=%d calls=%d err=%v", n, replacements, err)
			}
			status = s.QueueStatuses(time.Now())["spool"]
			if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 0 || status.Status != "ok" {
				t.Fatalf("recovery did not settle work and preserve receipt: %+v", status)
			}
		})
	}
}
