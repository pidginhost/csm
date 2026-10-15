package reporting

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func newSpool(t *testing.T, max int) *Spool {
	t.Helper()
	s, err := NewSpool(filepath.Join(t.TempDir(), "spool.db"), "reports", max)
	if err != nil {
		t.Fatalf("open spool: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSpoolEnqueueDrainFIFO(t *testing.T) {
	s := newSpool(t, 100)
	for _, b := range []string{"a", "b", "c"} {
		if _, err := s.Enqueue("central", []byte(b)); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	var got []string
	delivered, err := s.Drain(func(_ string, body []byte) error {
		got = append(got, string(body))
		return nil
	})
	if err != nil || delivered != 3 {
		t.Fatalf("drain delivered=%d err=%v", delivered, err)
	}
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("FIFO order wrong: %v", got)
	}
	if s.Len() != 0 {
		t.Fatalf("len = %d, want 0 after drain", s.Len())
	}
}

func TestSpoolDrainStopsAndRetainsOnError(t *testing.T) {
	s := newSpool(t, 100)
	for _, b := range []string{"a", "b", "c"} {
		_, _ = s.Enqueue("central", []byte(b))
	}
	calls := 0
	delivered, err := s.Drain(func(_ string, body []byte) error {
		calls++
		if string(body) == "b" {
			return errors.New("collector down")
		}
		return nil
	})
	if err == nil {
		t.Fatal("expected drain error")
	}
	if delivered != 1 { // only "a" delivered before "b" failed
		t.Fatalf("delivered = %d, want 1", delivered)
	}
	// "b" and "c" remain for retry.
	if s.Len() != 2 {
		t.Fatalf("len = %d, want 2 retained", s.Len())
	}
	// A later successful drain finishes the rest in order.
	var got []string
	if _, err := s.Drain(func(_ string, body []byte) error { got = append(got, string(body)); return nil }); err != nil {
		t.Fatalf("retry drain: %v", err)
	}
	if len(got) != 2 || got[0] != "b" || got[1] != "c" {
		t.Fatalf("retry order wrong: %v", got)
	}
}

// One collector's outage must not hold back reports for other collectors, and
// each collector still receives its reports in order.
func TestSpoolDrainSkipsOnlyTheFailingTarget(t *testing.T) {
	s := newSpool(t, 100)
	for _, it := range []struct{ target, body string }{
		{"a", "a1"}, {"b", "b1"}, {"a", "a2"}, {"b", "b2"},
	} {
		if _, err := s.Enqueue(it.target, []byte(it.body)); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	down := errors.New("collector a down")
	var sent []string
	delivered, err := s.Drain(func(target string, body []byte) error {
		sent = append(sent, string(body))
		if target == "a" {
			return down
		}
		return nil
	})
	if !errors.Is(err, down) || delivered != 2 {
		t.Fatalf("drain delivered=%d err=%v, want 2 and the outage", delivered, err)
	}
	// a2 is not attempted once a failed in this pass, so a keeps its order.
	if got := strings.Join(sent, ","); got != "a1,b1,b2" {
		t.Fatalf("sent %s, want a1,b1,b2", got)
	}
	if s.Len() != 2 {
		t.Fatalf("len = %d, want a1 and a2 retained", s.Len())
	}
	// b's deliveries must not hide that a is stalled.
	if st := s.QueueStatuses(time.Now())["spool"]; st.Status != "degraded" || st.Reason != "delivery_failed" {
		t.Fatalf("status after a mixed pass = %+v, want degraded delivery_failed", st)
	}
	var got []string
	if _, err := s.Drain(func(_ string, body []byte) error { got = append(got, string(body)); return nil }); err != nil {
		t.Fatalf("retry drain: %v", err)
	}
	if strings.Join(got, ",") != "a1,a2" {
		t.Fatalf("retry order %v, want a1,a2", got)
	}
}

// A report the collector refuses as invalid is refused on every retry. It is
// dropped and counted instead of blocking every report queued behind it.
func TestSpoolDrainDropsRefusedReport(t *testing.T) {
	s := newSpool(t, 100)
	for _, b := range []string{"bad1", "bad2", "good"} {
		if _, err := s.Enqueue("central", []byte(b)); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	var sent []string
	delivered, err := s.Drain(func(_ string, body []byte) error {
		sent = append(sent, string(body))
		if strings.HasPrefix(string(body), "bad") {
			return fmt.Errorf("%w: status 422", ErrReportRefused)
		}
		return nil
	})
	if delivered != 1 || !errors.Is(err, ErrReportRefused) {
		t.Fatalf("drain delivered=%d err=%v, want 1 and the refusals", delivered, err)
	}
	// Refusals are summarized per target, so a burst stays one log line.
	if msg := err.Error(); strings.Count(msg, "target central") != 1 || !strings.Contains(msg, "2 reports refused") {
		t.Fatalf("refusals not summarized per target: %q", msg)
	}
	if strings.Join(sent, ",") != "bad1,bad2,good" || s.Len() != 0 {
		t.Fatalf("sent %v len %d, want all attempted and nothing retained", sent, s.Len())
	}
	got := s.QueueStatuses(time.Now())["spool"]
	if got.DroppedTotal != 2 || got.RecentDrops != 2 || got.Depth != 0 || got.InFlight != 0 || got.Reason == "delivery_failed" {
		t.Fatalf("refused reports not counted as two drops: %+v", got)
	}
}

// A refused report that was evicted while its send was in flight is counted
// as dropped exactly once.
func TestSpoolDrainRefusedWhileEvictedCountsOnce(t *testing.T) {
	s := newSpool(t, 1)
	if _, err := s.Enqueue("central", []byte("bad")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	_, err := s.Drain(func(_ string, body []byte) error {
		if string(body) == "bad" {
			if _, err := s.Enqueue("central", []byte("new")); err != nil {
				t.Fatalf("enqueue during send: %v", err)
			}
			return fmt.Errorf("%w: status 422", ErrReportRefused)
		}
		return nil
	})
	if !errors.Is(err, ErrReportRefused) {
		t.Fatalf("drain err = %v, want the refusal", err)
	}
	if got := s.QueueStatuses(time.Now())["spool"]; got.DroppedTotal != 1 || got.InFlight != 0 {
		t.Fatalf("refused evicted report counted %d times: %+v", got.DroppedTotal, got)
	}
}

// A report the collector already acknowledged is not lost when a later retry,
// left behind by a failed removal, is refused.
func TestSpoolDrainRefusedRetryOfAcknowledgedReportIsNotLoss(t *testing.T) {
	s := newSpool(t, 10)
	path := s.db.Path()
	if _, err := s.Enqueue("central", []byte("ack")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if _, err := s.Drain(func(string, []byte) error {
		// Acknowledged, but the removal that follows fails.
		_ = s.db.Close()
		return nil
	}); err == nil {
		t.Fatal("drain with a failed removal returned nil")
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	s.db = db
	if _, err := s.Drain(func(string, []byte) error {
		return fmt.Errorf("%w: status 422", ErrReportRefused)
	}); !errors.Is(err, ErrReportRefused) {
		t.Fatalf("retry err = %v, want the refusal", err)
	}
	if got := s.QueueStatuses(time.Now())["spool"]; got.DroppedTotal != 0 || got.Depth != 0 {
		t.Fatalf("acknowledged report counted as lost: %+v", got)
	}
}

// If the spool cannot remove a refused report, it stays queued and is not yet
// counted as lost; the spool failure stops the pass.
func TestSpoolDrainRefusedButNotRemovedIsKept(t *testing.T) {
	s := newSpool(t, 10)
	if _, err := s.Enqueue("central", []byte("bad")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	_, err := s.Drain(func(string, []byte) error {
		// Closing the database makes the removal after the refusal fail.
		_ = s.db.Close()
		return fmt.Errorf("%w: status 422", ErrReportRefused)
	})
	if err == nil || strings.Contains(err.Error(), "dropped") {
		t.Fatalf("drain err = %v, want the removal failure without claiming a drop", err)
	}
	got := s.QueueStatuses(time.Now())["spool"]
	if got.DroppedTotal != 0 || got.Depth != 1 || got.Reason != "spool_io" {
		t.Fatalf("unremoved refused report miscounted: %+v", got)
	}
}

func TestSpoolDrainSerializesConcurrentCallers(t *testing.T) {
	s := newSpool(t, 100)
	if _, err := s.Enqueue("central", []byte("a")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	firstSend := make(chan struct{})
	releaseSend := make(chan struct{})
	duplicateSend := make(chan struct{})
	var calls atomic.Int32
	send := func(_ string, _ []byte) error {
		if calls.Add(1) == 1 {
			close(firstSend)
		} else {
			close(duplicateSend)
		}
		<-releaseSend
		return nil
	}

	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			_, _ = s.Drain(send)
		}()
	}

	select {
	case <-firstSend:
	case <-time.After(time.Second):
		t.Fatal("first drain did not start sending")
	}
	select {
	case <-duplicateSend:
		close(releaseSend)
		wg.Wait()
		t.Fatal("concurrent drains sent the same queued report twice")
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseSend)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("send calls = %d, want 1", got)
	}
	if s.Len() != 0 {
		t.Fatalf("len = %d, want 0", s.Len())
	}
}

func TestSpoolBoundedDropsOldest(t *testing.T) {
	s := newSpool(t, 3)
	totalDropped := 0
	for i := 0; i < 10; i++ {
		d, err := s.Enqueue("central", []byte{byte('0' + i)})
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		totalDropped += d
	}
	if s.Len() != 3 {
		t.Fatalf("len = %d, want cap 3", s.Len())
	}
	if totalDropped != 7 {
		t.Fatalf("dropped = %d, want 7", totalDropped)
	}
	// The three newest remain (7,8,9).
	var got []string
	_, _ = s.Drain(func(_ string, body []byte) error { got = append(got, string(body)); return nil })
	if len(got) != 3 || got[0] != "7" || got[2] != "9" {
		t.Fatalf("kept wrong items: %v", got)
	}
}

func TestSpoolPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spool.db")
	s1, err := NewSpool(path, "reports", 100)
	if err != nil {
		t.Fatalf("open1: %v", err)
	}
	if _, e := s1.Enqueue("central", []byte("persisted")); e != nil {
		t.Fatalf("enqueue: %v", e)
	}
	_ = s1.Close()

	s2, err := NewSpool(path, "reports", 100)
	if err != nil {
		t.Fatalf("open2: %v", err)
	}
	defer func() { _ = s2.Close() }()
	if s2.Len() != 1 {
		t.Fatalf("len after reopen = %d, want 1", s2.Len())
	}
	var got string
	_, _ = s2.Drain(func(_ string, body []byte) error { got = string(body); return nil })
	if got != "persisted" {
		t.Fatalf("got %q after reopen", got)
	}
}
