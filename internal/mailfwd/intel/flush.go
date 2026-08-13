package intel

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// FlushResult reports the observable outcome of a queue flush.
type FlushResult struct {
	Removed int `json:"removed"`
	// Targeted is the number of message IDs submitted for removal. It is kept
	// off the wire because the public response historically exposes only the
	// post-action count, but callers need it to audit an unconfirmed outcome.
	Targeted int `json:"-"`
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

// survivorsListed bounds how many surviving message IDs are named in the
// error text so a large stuck queue cannot produce an unreadable message.
const survivorsListed = 5

// FlushBackscatter removes every frozen null-sender message currently queued.
//
// The queue, not the exit status, decides the outcome. exim -Mrm has been
// observed removing every message it was handed and still exiting non-zero,
// which reported a failure for work that had already completed and skipped
// the caller's audit record. Re-reading the queue afterwards establishes
// what actually left, so a lying exit code can neither invent a failure nor
// hide a removal that silently did nothing.
//
// Removed is the number of targeted IDs absent from the post-action queue and
// stays meaningful alongside a non-nil error. A concurrent delivery can also
// make an ID disappear, so audit callers must describe it as no longer queued,
// not necessarily deleted by this command.
func (f *EximQueueFlusher) FlushBackscatter() (FlushResult, error) {
	out, err := f.list()
	if err != nil {
		return FlushResult{}, err
	}
	ids := FrozenBackscatterIDs(string(out))
	if len(ids) == 0 {
		return FlushResult{}, nil
	}
	result := FlushResult{Targeted: len(ids)}
	removeErr := f.remove(ids)

	after, listErr := f.list()
	if listErr != nil {
		confirmErr := fmt.Errorf("removal could not be confirmed: %w", listErr)
		if removeErr != nil {
			return result, errors.Join(fmt.Errorf("removal command failed: %w", removeErr), confirmErr)
		}
		return result, confirmErr
	}

	targeted := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		targeted[id] = struct{}{}
	}
	stillQueued := make(map[string]struct{}, len(ids))
	for _, line := range strings.Split(string(after), "\n") {
		id, _, _, _, _, ok := parseQueueHeader(line)
		if _, isTargeted := targeted[id]; ok && isTargeted {
			stillQueued[id] = struct{}{}
		}
	}
	var survived []string
	for _, id := range ids {
		if _, ok := stillQueued[id]; ok {
			survived = append(survived, id)
		}
	}
	result.Removed = len(ids) - len(survived)
	if len(survived) == 0 {
		return result, nil
	}

	named := survived
	if len(named) > survivorsListed {
		named = named[:survivorsListed]
	}
	msg := fmt.Sprintf("%d of %d frozen backscatter messages still queued after removal (%s)",
		len(survived), len(ids), strings.Join(named, " "))
	if removeErr != nil {
		return result, fmt.Errorf("%s: %w", msg, removeErr)
	}
	return result, errors.New(msg)
}

func runEximRemove(ids []string) error {
	var firstErr error
	failedBatches := 0
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
			// Exim can remove every ID and still return non-zero. Continue so an
			// unreliable status from one batch cannot prevent later attempts;
			// the queue re-read decides which messages remain. Retaining only the
			// first error keeps the eventual operator message bounded.
			failedBatches++
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if firstErr != nil {
		return fmt.Errorf("%d removal batch(es) reported an error; first: %w", failedBatches, firstErr)
	}
	return nil
}
