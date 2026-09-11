package maillog

import (
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

// The journal cursor cannot measure its unread backlog. Track actual reader
// progress and the one selected entry without taking the journal's I/O locks.
type journalSourceQueue struct {
	mu                     sync.Mutex
	seen, active, selected bool
	failed, uncertain      bool
	at                     time.Time
}

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

func (s *journalSourceQueue) outcome(failed, uncertain bool) {
	s.mu.Lock()
	s.failed = failed
	s.uncertain = s.uncertain || uncertain
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

func (s *journalSourceQueue) snapshot(now time.Time) (queuehealth.Status, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The cursor exposes no unread count and no waiting age, so the row
	// measures the current operation and says so instead of reporting a
	// backlog of zero.
	row := queuehealth.Status{Status: "ok", DepthUnavailable: true, CapacityUnavailable: true, DroppedLowerBound: s.uncertain, LagBasis: "unavailable"}
	if s.selected {
		row.InFlight = 1
	}
	if s.active {
		row.ProcessingSeconds = max(0, now.Sub(s.at).Seconds())
	}
	switch {
	case s.failed:
		row.Status, row.Reason = "degraded", "source_io"
	case row.ProcessingSeconds >= time.Minute.Seconds():
		row.Status, row.Reason = "degraded", "processing_lag"
	}
	return row, s.seen
}
