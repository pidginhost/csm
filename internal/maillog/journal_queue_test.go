//go:build linux && journal

package maillog

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/coreos/go-systemd/v22/sdjournal"
)

type queueJournal struct {
	position int
	closed   bool
	cancel   context.CancelFunc
}

func (j *queueJournal) Next() (uint64, error) {
	j.position++
	if j.position <= 4 {
		return 1, nil
	}
	return 0, nil
}

func (j *queueJournal) GetEntry() (*sdjournal.JournalEntry, error) {
	if j.position <= 3 {
		return nil, errors.New("journal record unreadable")
	}
	return &sdjournal.JournalEntry{Fields: map[string]string{"_SYSTEMD_UNIT": "postfix.service", "MESSAGE": "delivered"}}, nil
}

func (j *queueJournal) Wait(time.Duration) int {
	j.cancel()
	return 0
}

func (j *queueJournal) Close() error {
	j.closed = true
	return nil
}

func TestJournalQueueCountsUnreadableEntriesAndDelivery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue := NewQueue()
	journal := &queueJournal{cancel: cancel}
	out := queue.channel()
	NewJournalReader([]string{"postfix"}, queue).loop(ctx, journal, out)
	got := queue.QueueStatuses(time.Now())["delivery"]
	if !journal.closed || got.Depth != 1 || got.InFlight != 0 || got.DroppedTotal != 3 || got.RecentDrops != 3 || got.Status != "degraded" {
		t.Fatalf("unreadable entries or queued journal work missing: closed=%v status=%+v", journal.closed, got)
	}
	line, ok := <-out
	if !ok || !line.Process(func(line Line) bool {
		return line.Source == "journal" && line.Unit == "postfix.service" && line.Message == "delivered"
	}) {
		t.Fatalf("journal successor did not survive read failures: open=%v line=%+v", ok, line)
	}
	if extra, ok := <-out; ok {
		t.Fatalf("unexpected extra journal line: %+v", extra)
	}
	got = queue.QueueStatuses(time.Now())["delivery"]
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 {
		t.Fatalf("completed journal work remains pending: %+v", got)
	}
}
