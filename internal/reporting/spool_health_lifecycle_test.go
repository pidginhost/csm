package reporting

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
	bolterrors "go.etcd.io/bbolt/errors"
)

func TestSpoolHealthRetainsReportAfterSenderPanic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSpool(t, 8)
		enqueueSpoolBody(t, s, "retained")
		time.Sleep(61 * time.Second)
		var caught any
		func() {
			defer func() { caught = recover() }()
			_, _ = s.Drain(func(string, []byte) error { panic("sender failed") })
		}()
		got := s.QueueStatuses(time.Now())["spool"]
		if caught != "sender failed" || got.Depth != 1 || got.InFlight != 0 || got.DroppedTotal != 0 || got.LagSeconds != 61 || got.Reason != "delivery_failed" {
			t.Fatalf("retained panic: panic=%v status=%+v", caught, got)
		}
		n, err := s.Drain(func(_ string, body []byte) error {
			if string(body) != "retained" {
				t.Errorf("retained body = %q", body)
			}
			return nil
		})
		if got = s.QueueStatuses(time.Now())["spool"]; err != nil || n != 1 || got.Status != "ok" || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 {
			t.Fatalf("panic recovery: delivered=%d err=%v status=%+v", n, err, got)
		}
	})
}

func TestSpoolHealthFailedAcknowledgmentKeepsDurableCopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reports.db")
	s, err := NewSpool(path, "reports", 8)
	if err != nil {
		t.Fatal(err)
	}
	enqueueSpoolBody(t, s, "delivered-but-unacknowledged")
	calls := 0
	n, err := s.Drain(func(string, []byte) error {
		calls++
		return s.Close()
	})
	got := s.QueueStatuses(time.Now())["spool"]
	if n != 0 || calls != 1 || !errors.Is(err, bolterrors.ErrDatabaseNotOpen) || got.Depth != 1 || got.InFlight != 0 || got.DroppedTotal != 0 || got.Reason != "spool_io" {
		t.Fatalf("failed acknowledgment: n=%d calls=%d err=%v status=%+v", n, calls, err, got)
	}
	s, err = NewSpool(path, "reports", 8)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	n, err = s.Drain(func(_ string, body []byte) error {
		if string(body) != "delivered-but-unacknowledged" {
			t.Errorf("durable retry = %q", body)
		}
		return nil
	})
	if n != 1 || err != nil {
		t.Fatalf("durable retry: n=%d err=%v", n, err)
	}
}

func TestSpoolHealthDoesNotWaitForDatabaseWriter(t *testing.T) {
	s := newSpool(t, 8)
	enqueueSpoolBody(t, s, "stored")
	tx, err := s.db.Begin(true)
	if err != nil {
		t.Fatal(err)
	}
	releaseWrite := sync.OnceFunc(func() {
		if err := tx.Rollback(); err != nil {
			t.Error(err)
		}
	})
	writeDone := make(chan error, 1)
	go func() {
		_, err := s.Enqueue("collector", []byte("blocked"))
		writeDone <- err
	}()
	stopPoll, pollDone := make(chan struct{}), make(chan struct{})
	observed := make(chan queuehealth.Status, 1)
	go func() {
		defer close(pollDone)
		for {
			status := s.QueueStatuses(time.Now().Add(121 * time.Second))["spool"]
			if status.InFlight == 1 {
				observed <- status
				return
			}
			select {
			case <-stopPoll:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	defer func() {
		close(stopPoll)
		releaseWrite()
		if err := <-writeDone; err != nil {
			t.Error(err)
		}
		<-pollDone
	}()
	select {
	case got := <-observed:
		if got.Depth != 1 || got.Capacity != 8 || got.DroppedTotal != 0 || got.ProcessingSeconds < 121 || got.Status != "degraded" {
			t.Fatalf("blocked write evidence: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("health could not observe an admission blocked on the database writer")
	}
	releaseWrite()
}

func TestSpoolHealthConcurrentAdmissionsSettleExactlyOnce(t *testing.T) {
	s := newSpool(t, 8)
	enqueueSpoolBody(t, s, "active")
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	releaseSend := sync.OnceFunc(func() { close(release) })
	var delivered int
	var drainErr error
	seen := make(map[string]int)
	go func() {
		defer close(done)
		delivered, drainErr = s.Drain(func(_ string, body []byte) error {
			seen[string(body)]++
			if string(body) == "active" {
				close(started)
				<-release
			}
			return nil
		})
	}()
	defer func() { releaseSend(); <-done }()
	<-started
	var writers sync.WaitGroup
	for i := range 256 {
		writers.Go(func() {
			if _, err := s.Enqueue("collector", []byte(fmt.Sprintf("report-%d", i))); err != nil {
				t.Error(err)
			}
		})
	}
	writers.Wait()
	got := s.QueueStatuses(time.Now())["spool"]
	if got.Depth != 8 || got.InFlight != 1 || got.DroppedTotal != 248 {
		t.Fatalf("concurrent admissions lost active ownership: %+v", got)
	}
	releaseSend()
	<-done
	got = s.QueueStatuses(time.Now())["spool"]
	if delivered != 9 || drainErr != nil || len(seen) != 9 || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 248 {
		t.Fatalf("concurrent settlement: n=%d err=%v seen=%v status=%+v", delivered, drainErr, seen, got)
	}
	for body, count := range seen {
		if count != 1 {
			t.Errorf("body %q sent %d times", body, count)
		}
	}
}
