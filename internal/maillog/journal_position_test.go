//go:build linux && journal

package maillog

import (
	"context"
	"testing"
	"time"

	"github.com/coreos/go-systemd/v22/sdjournal"
)

type positionJournal struct {
	read   bool
	cancel context.CancelFunc
}

func (j *positionJournal) Next() (uint64, error) {
	if j.read {
		return 0, nil
	}
	j.read = true
	return 1, nil
}

func (j *positionJournal) GetEntry() (*sdjournal.JournalEntry, error) {
	return &sdjournal.JournalEntry{
		Fields:            map[string]string{"_SYSTEMD_UNIT": "dovecot.service", "MESSAGE": "auth failed"},
		Cursor:            "s=0123;i=4567;b=89ab;m=cdef;t=1;x=2",
		RealtimeTimestamp: 1_790_000_000_123_456,
	}, nil
}

func (j *positionJournal) Wait(time.Duration) int {
	j.cancel()
	return 0
}

func (j *positionJournal) Close() error { return nil }

// A journal line names the journal as its stream, the encoded entry cursor
// and the time journald recorded the entry.
func TestJournalLinePosition(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue := NewQueue()
	out := queue.channel()
	NewJournalReader([]string{"dovecot"}, queue).loop(ctx, &positionJournal{cancel: cancel}, out)
	line, ok := <-out
	if !ok {
		t.Fatal("no journal line")
	}
	line.Process(func(Line) bool { return true })
	want := Position{Stream: "journal", Cursor: journalCursor("s=0123;i=4567;b=89ab;m=cdef;t=1;x=2"), ObservedAt: time.UnixMicro(1_790_000_000_123_456)}
	if line.Position != want {
		t.Fatalf("position %+v, want %+v", line.Position, want)
	}
}

// Older journal records without a cursor still dispatch without provenance.
func TestJournalLinePositionWithoutCursor(t *testing.T) {
	entry := &sdjournal.JournalEntry{RealtimeTimestamp: 1_790_000_000_123_456}
	if got := journalPosition(entry); got != (Position{}) {
		t.Fatalf("cursorless entry acquired position %+v", got)
	}
}
