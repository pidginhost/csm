package intel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

func TestFrozenBackscatterIDsRejectsRealSenderAndMalformedHeaders(t *testing.T) {
	in := ` 25m  2.5K 1rREAL-000ABC-2A sender@example.com *** frozen ***
          real-recipient@example.com
 25m  2.5K 1rLIVE-000ABC-2A <>
          *** frozen *** is recipient text, not a header marker
 25m  2.5K 1rEXTR-000ABC-2A <> *** frozen *** injected
          malformed@example.com
 25m  2.5K 1rGOOD-000ABC-2A <> *** frozen ***
          victim@example.com
`

	got := FrozenBackscatterIDs(in)
	want := []string{"1rGOOD-000ABC-2A"}
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

func TestRunEximRemoveBatchesIDs(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "args.log")
	eximPath := filepath.Join(dir, "exim")
	script := "#!/bin/sh\nprintf '%s\\n' \"$#\" >> \"$EXIM_ARG_LOG\"\n"
	if err := os.WriteFile(eximPath, []byte(script), 0700); err != nil {
		t.Fatalf("write fake exim: %v", err)
	}
	t.Setenv("EXIM_ARG_LOG", logPath)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	var ids []string
	for i := 0; i < eximRemoveBatch*2+1; i++ {
		ids = append(ids, fmt.Sprintf("1r%04d-000ABC-2A", i))
	}

	if err := runEximRemove(ids); err != nil {
		t.Fatalf("runEximRemove: %v", err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read fake exim log: %v", err)
	}
	got := strings.Fields(string(data))
	want := []string{"101", "101", "2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("batch argument counts = %v, want %v", got, want)
	}
}
