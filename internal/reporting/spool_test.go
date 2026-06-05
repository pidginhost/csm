package reporting

import (
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
