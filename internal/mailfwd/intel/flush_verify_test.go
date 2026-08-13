package intel

import (
	"errors"
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
	const id = "1rABcd-000ABC-2A"
	calls := 0
	f := &EximQueueFlusher{
		list: func() ([]byte, error) {
			calls++
			if calls == 1 {
				return []byte(eximBpSample), nil
			}
			return []byte(queueWithout(t, eximBpSample, id)), nil
		},
		remove: func([]string) error { return errors.New("exit status 1") },
	}

	res, err := f.FlushBackscatter()

	if err != nil {
		t.Fatalf("messages left the queue, so the flush succeeded; got error %v", err)
	}
	if res.Removed != 1 {
		t.Fatalf("Removed = %d, want 1", res.Removed)
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
