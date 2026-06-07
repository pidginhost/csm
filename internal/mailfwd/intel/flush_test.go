package intel

import (
	"errors"
	"reflect"
	"testing"
)

func TestFrozenBackscatterIDs(t *testing.T) {
	// In eximBpSample only the first message is BOTH frozen AND null-sender.
	// The other two <> messages are not frozen; the real-sender message is neither.
	got := FrozenBackscatterIDs(eximBpSample)
	want := []string{"1rABcd-000ABC-2A"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FrozenBackscatterIDs = %v, want %v", got, want)
	}
}

func TestParseQueueCountsFlushableBackscatter(t *testing.T) {
	c := ParseQueue(eximBpSample)
	if c.FlushableBackscatter != 1 {
		t.Fatalf("flushable backscatter = %d, want 1 (only the frozen <> message)", c.FlushableBackscatter)
	}
}

func TestEximQueueFlusherRemovesOnlyFrozenBackscatter(t *testing.T) {
	var removed []string
	f := &EximQueueFlusher{
		list:   func() ([]byte, error) { return []byte(eximBpSample), nil },
		remove: func(ids []string) error { removed = append(removed, ids...); return nil },
	}

	res, err := f.FlushBackscatter()
	if err != nil {
		t.Fatalf("FlushBackscatter error: %v", err)
	}
	if res.Removed != 1 {
		t.Errorf("removed = %d, want 1", res.Removed)
	}
	if !reflect.DeepEqual(removed, []string{"1rABcd-000ABC-2A"}) {
		t.Errorf("removed IDs = %v, want only the frozen null-sender message", removed)
	}
}

func TestEximQueueFlusherNoCandidatesDoesNotCallRemove(t *testing.T) {
	noFrozen := `  4d  1.2K 1rXYz0-000DEF-99 sender@shop.example
          user1@gmail.com
  2h   800 1rQQq1-000GHI-3B <>
          target@external.example
`
	removeCalled := false
	f := &EximQueueFlusher{
		list:   func() ([]byte, error) { return []byte(noFrozen), nil },
		remove: func(ids []string) error { removeCalled = true; return nil },
	}

	res, err := f.FlushBackscatter()
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if res.Removed != 0 {
		t.Errorf("removed = %d, want 0", res.Removed)
	}
	if removeCalled {
		t.Error("remove must not be called when there are no candidates")
	}
}

func TestEximQueueFlusherListErrorIsReturned(t *testing.T) {
	f := &EximQueueFlusher{
		list:   func() ([]byte, error) { return nil, errors.New("exim unavailable") },
		remove: func(ids []string) error { t.Fatal("remove must not run after a list failure"); return nil },
	}
	if _, err := f.FlushBackscatter(); err == nil {
		t.Fatal("expected error when listing the queue fails")
	}
}

func TestEximQueueFlusherRemoveErrorIsReturned(t *testing.T) {
	f := &EximQueueFlusher{
		list:   func() ([]byte, error) { return []byte(eximBpSample), nil },
		remove: func(ids []string) error { return errors.New("exim -Mrm failed") },
	}
	if _, err := f.FlushBackscatter(); err == nil {
		t.Fatal("expected error when removal fails")
	}
}
