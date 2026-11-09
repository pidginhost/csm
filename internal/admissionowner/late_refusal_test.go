package admissionowner

import (
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/admission"
)

// Retention discards complete hours. A later ledger refusal must not
// resurrect a discarded hour as a partial summary, even after a write
// acknowledgement frees room for it.
func TestComparisonLateRefusalCannotRestoreDiscardedHour(t *testing.T) {
	for _, acknowledge := range []bool{false, true} {
		t.Run(map[bool]string{false: "room after trimming", true: "room after acknowledgement"}[acknowledge], func(t *testing.T) {
			var c comparison
			h := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
			key := compareKey{entry: admission.EntryScan, check: "pam_bruteforce", kind: admission.KindBlockIP, decision: decisionQueued}
			c.addAt(key, h)
			key.kind = admission.KindChallenge
			c.addAt(key, h)
			for i := 1; i < maxUnwrittenRows; i++ {
				c.addAt(key, h.Add(time.Duration(i)*time.Hour))
			}
			now := h.Add(maxUnwrittenRows * time.Hour)
			rows, through := c.take(now, false)
			if len(rows) != maxUnwrittenRows-1 || c.droppedRows() != 2 || !rows[0].Timestamp.Equal(h.Add(2*time.Hour)) {
				t.Fatalf("retention: %d rows, %d dropped, want oldest hour discarded whole", len(rows), c.droppedRows())
			}
			wantRows := len(rows)
			if acknowledge {
				c.written(through)
				wantRows = 0
			}
			key.decision, key.reason = decisionRefused, admission.ReasonStale
			for _, at := range []time.Time{h.Add(20 * time.Minute), h.Add(-time.Minute)} {
				c.addLedgerRefusalAt(key, at)
			}
			rows, _ = c.take(now, false)
			if len(rows) != wantRows || c.droppedRows() != 4 {
				t.Fatalf("late refusals restored discarded hours: %d rows, %d dropped; want %d rows, 4 dropped", len(rows), c.droppedRows(), wantRows)
			}
			// A retained hour still accepts late refusals, including after
			// its earlier rows were acknowledged.
			c.addLedgerRefusalAt(key, h.Add(time.Hour+20*time.Minute))
			rows, _ = c.take(now, false)
			if len(rows) != wantRows+1 || c.droppedRows() != 4 {
				t.Fatalf("late refusal in a retained hour was lost: %d rows, %d dropped", len(rows), c.droppedRows())
			}
		})
	}
}

// The ledger can report on another goroutine while the owner is blocked
// writing an older batch. That write must neither hold the comparison
// lock nor acknowledge the late refusal it never received.
func TestOwnerLaterRefusalDuringComparisonWrite(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	ledgerAt := f.host.now()
	h := ledgerAt.UTC().Truncate(time.Hour)
	comparisonClock(t, f.host.now)
	started, release := make(chan struct{}), make(chan struct{})
	var firstWrite, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	sink := &actionSink{}
	opts := respondOptions(f)
	opts.WriteAudit = func(rows []actionlog.Record) error {
		firstWrite.Do(func() {
			close(started)
			<-release
		})
		return sink.write(rows)
	}
	o := f.start(opts)
	t.Cleanup(unblock)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	queued := candidate(t, o, id)
	key := compareKey{entry: queued.Entry, check: queued.Check, kind: queued.Key.Kind, decision: decisionQueued}
	o.compare.addAt(key, ledgerAt)
	key.decision = decisionObserve
	o.compare.addAt(key, h.Add(time.Hour+10*time.Minute))
	ownerNow := h.Add(3*time.Hour + 5*time.Minute)
	if err := o.do(func() error { o.now = ownerNow; return nil }); err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() {
		written <- o.do(func() error { o.writeComparison(false); return nil })
	}()
	<-started
	ended := make(chan error, 1)
	go func() {
		ended <- o.ledger.RefuseDisabled(func(admission.Candidate) bool { return false })
	}()
	if err := <-ended; err != nil {
		t.Fatal(err)
	}
	if c, err := o.ledger.Candidate(id); err != nil || c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled {
		t.Fatalf("disabled candidate = %+v, err %v", c, err)
	}
	// A funnel can also move the open hour while the writer waits.
	o.compare.addAt(key, h.Add(4*time.Hour+10*time.Minute))
	unblock()
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if err := o.do(func() error {
		if !o.now.Equal(ownerNow) {
			t.Errorf("callback changed owner time to %v", o.now)
		}
		o.writeComparison(true)
		o.writeComparison(true)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.recs) != 4 {
		t.Fatalf("wrote %+v, want the original batch, one late refusal and the later arrival", sink.recs)
	}
	want := []struct {
		result string
		end    time.Time
	}{
		{decisionQueued, h.Add(time.Hour)},
		{decisionObserve, h.Add(2 * time.Hour)},
		{decisionRefused, h.Add(time.Hour)},
		{decisionObserve, h.Add(5 * time.Hour)},
	}
	for i, row := range sink.recs {
		if string(row.Result) != want[i].result || !row.Timestamp.Equal(want[i].end) || row.Count != 1 {
			t.Errorf("row %d = %+v, want %s at %v counted once", i, row, want[i].result, want[i].end)
		}
	}
	if row := sink.recs[2]; row.Error != "disabled" || row.Cause != "" {
		t.Errorf("late refusal = %+v, want disabled with no attribution cause", row)
	}
}
