package intel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// queueWithout returns eximBpSample with the header line for id (and its
// recipient continuation line) removed, simulating a queue re-read after
// the message was actually deleted.
func queueWithout(t *testing.T, sample, id string) string {
	t.Helper()
	var kept []string
	lines := strings.Split(sample, "\n")
	for i := 0; i < len(lines); i++ {
		if strings.Contains(lines[i], id) {
			// Skip the header line and its indented recipient lines.
			for i+1 < len(lines) && strings.HasPrefix(lines[i+1], " ") &&
				strings.TrimSpace(lines[i+1]) != "" {
				i++
			}
			continue
		}
		kept = append(kept, lines[i])
	}
	out := strings.Join(kept, "\n")
	if strings.Contains(out, id) {
		t.Fatalf("queueWithout failed to drop %s", id)
	}
	return out
}

// Production case: exim removed both frozen backscatter messages and still
// exited non-zero. The queue is the authority, not the exit status -- if
// the messages are gone the flush succeeded, and reporting a failure sends
// the operator chasing a problem that does not exist.
func TestEximQueueFlusherTrustsQueueOverExitCode(t *testing.T) {
	const (
		firstID  = "1rABcd-000ABC-2A"
		secondID = "1rEFgh-000DEF-3B"
	)
	queue := eximBpSample + `  1h   900 1rEFgh-000DEF-3B <> *** frozen ***
          second@example.net
`
	calls := 0
	f := &EximQueueFlusher{
		list: func() ([]byte, error) {
			calls++
			if calls == 1 {
				return []byte(queue), nil
			}
			after := queueWithout(t, queue, firstID)
			return []byte(queueWithout(t, after, secondID)), nil
		},
		remove: func([]string) error { return errors.New("exit status 1") },
	}

	res, err := f.FlushBackscatter()

	if err != nil {
		t.Fatalf("messages left the queue, so the flush succeeded; got error %v", err)
	}
	if res.Removed != 2 {
		t.Fatalf("Removed = %d, want 2", res.Removed)
	}
	if res.Targeted != 2 {
		t.Fatalf("Targeted = %d, want 2", res.Targeted)
	}
}

func TestEximQueueFlusherStillQueuedAfterUnfreezeIsNotRemoved(t *testing.T) {
	const id = "1rABcd-000ABC-2A"
	calls := 0
	f := &EximQueueFlusher{
		list: func() ([]byte, error) {
			calls++
			if calls == 1 {
				return []byte(eximBpSample), nil
			}
			return []byte(strings.Replace(eximBpSample, "<> *** frozen ***", "<>", 1)), nil
		},
		remove: func([]string) error { return nil },
	}

	res, err := f.FlushBackscatter()

	if err == nil {
		t.Fatal("a targeted message that remains queued must not count as removed")
	}
	if res.Removed != 0 {
		t.Fatalf("Removed = %d, want 0", res.Removed)
	}
	if !strings.Contains(err.Error(), id) {
		t.Fatalf("error %q does not identify the surviving message", err)
	}
}

func TestEximQueueFlusherPostRemovalListFailureReportsAttempt(t *testing.T) {
	calls := 0
	f := &EximQueueFlusher{
		list: func() ([]byte, error) {
			calls++
			if calls == 1 {
				return []byte(eximBpSample), nil
			}
			return nil, errors.New("queue re-read failed")
		},
		remove: func([]string) error { return nil },
	}

	res, err := f.FlushBackscatter()

	if err == nil {
		t.Fatal("failed queue verification must surface an error")
	}
	if res.Targeted != 1 {
		t.Fatalf("Targeted = %d, want 1 so the destructive attempt can be audited", res.Targeted)
	}
	if res.Removed != 0 {
		t.Fatalf("Removed = %d, want 0 when removal cannot be confirmed", res.Removed)
	}
}

func TestEximQueueFlusherPreservesRemoveAndVerificationErrors(t *testing.T) {
	calls := 0
	f := &EximQueueFlusher{
		list: func() ([]byte, error) {
			calls++
			if calls == 1 {
				return []byte(eximBpSample), nil
			}
			return nil, errors.New("queue re-read failed")
		},
		remove: func([]string) error { return errors.New("removal command failed") },
	}

	_, err := f.FlushBackscatter()

	if err == nil {
		t.Fatal("remove and verification failures must surface an error")
	}
	for _, want := range []string{"removal command failed", "queue re-read failed"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not include %q", err, want)
		}
	}
}

// The mirror case: the exit status was non-zero AND the message is still
// queued. That is a real failure and must not be reported as success.
func TestEximQueueFlusherReportsMessagesThatSurvived(t *testing.T) {
	f := &EximQueueFlusher{
		list:   func() ([]byte, error) { return []byte(eximBpSample), nil },
		remove: func([]string) error { return errors.New("exit status 1") },
	}

	res, err := f.FlushBackscatter()

	if err == nil {
		t.Fatal("a message that survived removal must surface an error")
	}
	if res.Removed != 0 {
		t.Fatalf("Removed = %d, want 0 when nothing left the queue", res.Removed)
	}
}

// A clean exit that silently removed nothing is also a failure. Without a
// post-check this reported success for a no-op.
func TestEximQueueFlusherCleanExitThatRemovedNothingFails(t *testing.T) {
	f := &EximQueueFlusher{
		list:   func() ([]byte, error) { return []byte(eximBpSample), nil },
		remove: func([]string) error { return nil },
	}

	res, err := f.FlushBackscatter()

	if err == nil {
		t.Fatal("clean exit that removed nothing must not report success")
	}
	if res.Removed != 0 {
		t.Fatalf("Removed = %d, want 0", res.Removed)
	}
}

func TestEximQueueFlusherBoundsSurvivorError(t *testing.T) {
	var queue strings.Builder
	for i := 0; i < survivorsListed+2; i++ {
		fmt.Fprintf(&queue, "  1h   900 1r%04d-000ABC-2A <> *** frozen ***\n", i)
		queue.WriteString("          bounce@example.net\n")
	}
	f := &EximQueueFlusher{
		list:   func() ([]byte, error) { return []byte(queue.String()), nil },
		remove: func([]string) error { return nil },
	}

	_, err := f.FlushBackscatter()

	if err == nil {
		t.Fatal("surviving messages must surface an error")
	}
	if !strings.Contains(err.Error(), "7 of 7") {
		t.Fatalf("error %q does not include the full survivor count", err)
	}
	if strings.Contains(err.Error(), "1r0005-000ABC-2A") {
		t.Fatalf("error names more than %d survivor IDs: %q", survivorsListed, err)
	}
	if len(err.Error()) > 256 {
		t.Fatalf("survivor error is not bounded: len=%d error=%q", len(err.Error()), err)
	}
}

func TestEximCommandErrorsDoNotExposeCommandOutput(t *testing.T) {
	dir := t.TempDir()
	eximPath := filepath.Join(dir, "exim")
	const secret = "private-recipient@example.net"
	script := "#!/bin/sh\nprintf 'queue data for " + secret + "\\n'\nprintf 'diagnostic for " + secret + "\\n' >&2\nexit 1\n"
	if err := os.WriteFile(eximPath, []byte(script), 0700); err != nil {
		t.Fatalf("write fake exim: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, listErr := runEximBp()
	removeErr := runEximRemove([]string{"1rABcd-000ABC-2A"})
	for name, err := range map[string]error{"list": listErr, "remove": removeErr} {
		if err == nil {
			t.Fatalf("%s command unexpectedly succeeded", name)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("%s error exposed command output: %q", name, err)
		}
	}
}
