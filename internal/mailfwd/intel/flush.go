package intel

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// FlushResult reports how many messages a flush removed.
type FlushResult struct {
	Removed int `json:"removed"`
}

// QueueFlusher removes safe-to-delete backscatter from the mail queue.
type QueueFlusher interface {
	FlushBackscatter() (FlushResult, error)
}

// FrozenBackscatterIDs returns the message IDs of messages that are BOTH frozen
// AND null-sender (<>) in `exim -bp` output. This is the only set the flush
// touches: a frozen null-sender message is undeliverable bounce backscatter,
// so removing it cannot lose a real sender's mail or interrupt a live retry.
func FrozenBackscatterIDs(out string) []string {
	var ids []string
	for _, line := range strings.Split(out, "\n") {
		if id, _, _, bounce, frozen, ok := parseQueueHeader(line); ok && bounce && frozen {
			ids = append(ids, id)
		}
	}
	return ids
}

// eximRemoveBatch bounds how many message IDs are passed to one `exim -Mrm`
// invocation so a huge queue cannot overflow the command line.
const eximRemoveBatch = 100

// EximQueueFlusher lists the queue, selects frozen null-sender messages, and
// removes them with `exim -Mrm`.
type EximQueueFlusher struct {
	list   func() ([]byte, error)
	remove func(ids []string) error
}

// NewEximQueueFlusher returns a flusher backed by the live exim binary.
func NewEximQueueFlusher() *EximQueueFlusher {
	return &EximQueueFlusher{list: runEximBp, remove: runEximRemove}
}

// FlushBackscatter removes every frozen null-sender message currently queued.
// A failure to list or remove is returned: the operator triggered this action
// explicitly and must know if it did not fully apply.
func (f *EximQueueFlusher) FlushBackscatter() (FlushResult, error) {
	out, err := f.list()
	if err != nil {
		return FlushResult{}, err
	}
	ids := FrozenBackscatterIDs(string(out))
	if len(ids) == 0 {
		return FlushResult{}, nil
	}
	if err := f.remove(ids); err != nil {
		return FlushResult{}, err
	}
	return FlushResult{Removed: len(ids)}, nil
}

func runEximRemove(ids []string) error {
	for start := 0; start < len(ids); start += eximRemoveBatch {
		end := start + eximRemoveBatch
		if end > len(ids) {
			end = len(ids)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		args := append([]string{"-Mrm"}, ids[start:end]...)
		// #nosec G204 -- ids are exim message IDs parsed by parseQueueHeader's
		// fixed legacy/new-format regex; no attacker-controlled text reaches argv.
		err := exec.CommandContext(ctx, "exim", args...).Run()
		cancel()
		if err != nil {
			return err
		}
	}
	return nil
}
