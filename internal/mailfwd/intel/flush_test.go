package intel

import (
	"context"
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

func TestFrozenBackscatterIDsAcceptsNewEximMessageIDFormat(t *testing.T) {
	got := FrozenBackscatterIDs(eximBpSampleNewID)
	want := []string{"1wVRAI-0000000CAT0-41m1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FrozenBackscatterIDs = %v, want %v", got, want)
	}
}

func TestFrozenBackscatterIDsAcceptsLocalUserSenderMarker(t *testing.T) {
	in := `  2h   900 1wVRAI-0000000CAT0-41m1 (nobody) <> *** frozen ***
          bounce@example.net
`
	got := FrozenBackscatterIDs(in)
	want := []string{"1wVRAI-0000000CAT0-41m1"}
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
	// The second list call is the post-removal re-read, so it must show the
	// message gone; returning the original queue would describe a removal
	// that did not happen.
	calls := 0
	f := &EximQueueFlusher{
		list: func() ([]byte, error) {
			calls++
			if calls == 1 {
				return []byte(eximBpSample), nil
			}
			return []byte(queueWithout(t, eximBpSample, "1rABcd-000ABC-2A")), nil
		},
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

func TestRunEximRemoveContinuesAfterBatchErrors(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "args.log")
	eximPath := filepath.Join(dir, "exim")
	script := "#!/bin/sh\nprintf '%s\\n' \"$#\" >> \"$EXIM_ARG_LOG\"\nexit 1\n"
	if err := os.WriteFile(eximPath, []byte(script), 0700); err != nil {
		t.Fatalf("write fake exim: %v", err)
	}
	t.Setenv("EXIM_ARG_LOG", logPath)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	var ids []string
	for i := 0; i < eximRemoveBatch+1; i++ {
		ids = append(ids, fmt.Sprintf("1r%04d-000ABC-2A", i))
	}

	err := runEximRemove(ids)
	if err == nil {
		t.Fatal("batch errors must be returned for queue verification")
	}
	if !strings.Contains(err.Error(), "2 removal batch(es)") {
		t.Fatalf("error = %q, want bounded failed-batch count", err)
	}
	data, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatalf("read fake exim log: %v", readErr)
	}
	got := strings.Fields(string(data))
	want := []string{"101", "2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("batch argument counts = %v, want %v; every batch must be attempted", got, want)
	}
}

func TestEximQueueCommandsRunThroughTransientServices(t *testing.T) {
	oldLookPath, oldRun := eximLookPath, eximRun
	t.Cleanup(func() { eximLookPath, eximRun = oldLookPath, oldRun })
	eximLookPath = func(file string) (string, error) {
		if file == "systemd-run" {
			return "/usr/bin/systemd-run", nil
		}
		return "/usr/sbin/exim", nil
	}
	var calls []string
	eximRun = func(_ context.Context, name string, args ...string) ([]byte, error) {
		call := strings.Join(append([]string{name}, args...), " ")
		calls = append(calls, call)
		if strings.HasSuffix(call, "/bin/true") {
			return nil, nil
		}
		if strings.HasSuffix(call, "/usr/sbin/exim -bp") {
			return []byte("7m 1K 1rABcd-000ABC-2A <> *** frozen ***\n"), nil
		}
		return nil, nil
	}

	if _, err := runEximBp(); err != nil {
		t.Fatalf("runEximBp: %v", err)
	}
	if err := runEximRemove([]string{"1rABcd-000ABC-2A"}); err != nil {
		t.Fatalf("runEximRemove: %v", err)
	}
	logText := strings.Join(calls, "\n")
	for _, want := range []string{"exim -bp", "exim -Mrm 1rABcd-000ABC-2A"} {
		if !strings.Contains(logText, want) {
			t.Errorf("systemd-run calls missing %q:\n%s", want, logText)
		}
	}
}
