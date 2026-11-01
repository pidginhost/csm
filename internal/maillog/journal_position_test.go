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
	fields map[string]string
}

func (j *positionJournal) Next() (uint64, error) {
	if j.read {
		return 0, nil
	}
	j.read = true
	return 1, nil
}

func (j *positionJournal) GetEntry() (*sdjournal.JournalEntry, error) {
	fields := j.fields
	if fields == nil {
		fields = map[string]string{"_SYSTEMD_UNIT": "dovecot.service", "MESSAGE": "auth failed"}
	}
	return &sdjournal.JournalEntry{
		Fields:            fields,
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

// The reader hands the parsers the entry's program tag and time, not the
// bare MESSAGE field.
func TestJournalReaderRendersSyslogLine(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue := NewQueue()
	out := queue.channel()
	fields := map[string]string{"_SYSTEMD_UNIT": "postfix.service", "SYSLOG_IDENTIFIER": "postfix/smtpd", "_PID": "99", "MESSAGE": "warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: x"}
	NewJournalReader([]string{"postfix"}, queue).loop(ctx, &positionJournal{cancel: cancel, fields: fields}, out)
	line, ok := <-out
	if !ok {
		t.Fatal("no journal line")
	}
	line.Process(func(Line) bool { return true })
	want := time.UnixMicro(1_790_000_000_123_456).Format(time.RFC3339Nano) + " postfix/smtpd[99]: warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: x"
	if line.Message != want || line.Unit != "postfix.service" {
		t.Fatalf("line = %+v, want message %q", line, want)
	}
}

// Older journal records without a cursor still dispatch without provenance.
func TestJournalLinePositionWithoutCursor(t *testing.T) {
	entry := &sdjournal.JournalEntry{RealtimeTimestamp: 1_790_000_000_123_456}
	if got := journalPosition(entry); got != (Position{}) {
		t.Fatalf("cursorless entry acquired position %+v", got)
	}
}

func TestJournalLinePositionRejectsUnencodableTime(t *testing.T) {
	entry := &sdjournal.JournalEntry{Cursor: "cursor", RealtimeTimestamp: 253402300800_000000}
	if got := journalPosition(entry); got != (Position{}) {
		t.Fatalf("unencodable time acquired position %+v", got)
	}
}

// Configured names become exact _SYSTEMD_UNIT values, so the Debian Postfix
// instance needs its own entry.
func TestJournalUnitName(t *testing.T) {
	for name, want := range map[string]string{
		"postfix":           "postfix.service",
		"postfix@-":         "postfix@-.service",
		"postfix@-.service": "postfix@-.service",
		" dovecot ":         "dovecot.service",
	} {
		if got := journalUnitName(name); got != want {
			t.Errorf("journalUnitName(%q) = %q, want %q", name, got, want)
		}
	}
}
