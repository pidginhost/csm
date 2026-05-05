//go:build linux && journal

package maillog

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-systemd/v22/sdjournal"
)

// JournalReader streams MESSAGE fields from systemd-journald for the
// given unit names. Only available on Linux builds with the `journal`
// tag; default builds get the stub from journal_reader_stub.go.
type JournalReader struct {
	units []string
}

// NewJournalReader constructs a JournalReader matching the given systemd
// unit names (e.g., "postfix", "dovecot", or full "*.service" names).
func NewJournalReader(units []string) *JournalReader {
	return &JournalReader{units: units}
}

func JournalSupported() bool { return true }

func (r *JournalReader) Run(ctx context.Context) (<-chan Line, error) {
	out := make(chan Line, 64)

	j, err := sdjournal.NewJournal()
	if err != nil {
		close(out)
		return nil, fmt.Errorf("opening journal: %w", err)
	}
	for i, unit := range r.units {
		match := fmt.Sprintf("_SYSTEMD_UNIT=%s", journalUnitName(unit))
		if err := j.AddMatch(match); err != nil {
			j.Close()
			close(out)
			return nil, fmt.Errorf("AddMatch %s: %w", match, err)
		}
		if i == len(r.units)-1 {
			continue
		}
		if err := j.AddDisjunction(); err != nil {
			j.Close()
			close(out)
			return nil, fmt.Errorf("AddDisjunction: %w", err)
		}
	}
	if err := j.SeekTail(); err != nil {
		j.Close()
		close(out)
		return nil, fmt.Errorf("seek tail: %w", err)
	}

	go r.loop(ctx, j, out)
	return out, nil
}

func journalUnitName(unit string) string {
	unit = strings.TrimSpace(unit)
	if strings.Contains(unit, ".") {
		return unit
	}
	return unit + ".service"
}

func (r *JournalReader) loop(ctx context.Context, j *sdjournal.Journal, out chan<- Line) {
	defer close(out)
	defer j.Close()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := j.Next()
		if err != nil {
			fmt.Println("journal Next:", err)
			time.Sleep(time.Second)
			continue
		}
		if n == 0 {
			// No new entry; wait up to 2s for one.
			_ = j.Wait(2 * time.Second)
			continue
		}
		entry, err := j.GetEntry()
		if err != nil {
			continue
		}
		unit := entry.Fields["_SYSTEMD_UNIT"]
		msg := entry.Fields["MESSAGE"]
		select {
		case out <- Line{Source: "journal", Unit: unit, Message: msg}:
		case <-ctx.Done():
			return
		}
	}
}
