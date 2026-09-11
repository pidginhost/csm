//go:build linux && journal

package maillog

import (
	"context"
	"time"
)

// The journal reader is the only producer of these transitions, so they live
// under its build constraint: a build without it carries no journal source.

func (s *journalSourceQueue) begin() {
	s.mu.Lock()
	s.seen, s.active = true, true
	s.at = time.Now()
	s.mu.Unlock()
}

func (s *journalSourceQueue) progress() {
	s.mu.Lock()
	s.at = time.Now()
	s.mu.Unlock()
}

func (s *journalSourceQueue) selectEntry() {
	s.mu.Lock()
	s.selected = true
	s.at = time.Now()
	s.mu.Unlock()
}

func (s *journalSourceQueue) releaseEntry() {
	s.mu.Lock()
	s.selected = false
	s.at = time.Now()
	s.mu.Unlock()
}

func (q *Queue) finishJournal(normal, closed bool) {
	s := &q.journal
	s.mu.Lock()
	if s.selected {
		// This cursor already selected an entry, but delivery never acquired
		// it. Keep the existing delivery row's upstream record-loss contract.
		q.lose()
	}
	s.selected, s.active = false, false
	s.failed = s.failed || !normal || !closed
	// New records can arrive before the cursor closes. Without an exact
	// unread count, shutdown cannot certify zero abandoned records.
	s.uncertain = true
	s.mu.Unlock()
}

func (q *Queue) sendJournal(ctx context.Context, out chan<- Line, line Line) bool {
	line.ticket = q.health.Begin(time.Now())
	q.journal.releaseEntry()
	return q.sendTracked(ctx, out, line)
}

// A working file source retires the journal's current error without erasing
// the history the row keeps.
func (s *fileSourceQueue) replaced() {
	s.mu.Lock()
	s.failures, s.sampleFailed = 0, false
	s.mu.Unlock()
}
