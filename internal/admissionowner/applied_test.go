package admissionowner

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/store"
)

// appliedSink records every batch of applied rows the owner hands over and
// fails as told.
type appliedSink struct {
	mu      sync.Mutex
	batches [][]admission.AuditRow
	err     error
}

func (s *appliedSink) consume(rows []admission.AuditRow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batches = append(s.batches, append([]admission.AuditRow(nil), rows...))
	return s.err
}

func (s *appliedSink) set(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *appliedSink) seen() [][]admission.AuditRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]admission.AuditRow(nil), s.batches...)
}

// ended takes a candidate of kind at addr through one attempt that ends d.
func ended(t *testing.T, o *Owner, p *admission.Producer, host *fakeHost, addr string, kind admission.Kind, d admission.Disposition) {
	t.Helper()
	id, now := queuedKind(t, o, p, host, admission.SeverityHigh, addr, kind)
	if err := o.do(func() error {
		_, a, _, err := o.ledger.Reserve(id, admission.LaneGeneral, now.Add(time.Hour))
		if err != nil {
			return err
		}
		if _, _, _, err = o.ledger.Execute(a.Attempt.ID); err != nil {
			return err
		}
		_, _, err = o.ledger.Finish(a.Attempt.ID, d)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// Spec 5.5 and design P14: a verified block's consumers see its applied
// row after the action log write and before the acknowledgement, and only
// that row: reservations, executions, failures, unknown outcomes and other
// kinds never reach them. A failed consumer acknowledges nothing, so the
// same row comes again with the same identity.
func TestOwnerHandsAppliedBlocksToTheirConsumer(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink, consumer := &auditSink{}, &appliedSink{}
	opts := f.options()
	opts.WriteAudit, opts.Applied = sink.write, consumer.consume
	o := f.start(opts)
	ended(t, o, p, f.host, "192.0.2.11", admission.KindBlockIP, admission.DispositionFailed)
	ended(t, o, p, f.host, "192.0.2.12", admission.KindBlockIP, admission.DispositionUnknown)
	ended(t, o, p, f.host, "192.0.2.13", admission.KindChallenge, admission.DispositionApplied)
	if err := o.do(o.deliverAudit); err != nil {
		t.Fatal(err)
	}
	if got := consumer.seen(); len(got) != 0 {
		t.Fatalf("consumers saw rows of no applied block: %+v", got)
	}
	applied(t, o, p, f.host)
	ended(t, o, p, f.host, "192.0.2.14", admission.KindBlockIP, admission.DispositionFailed)
	rows := pendingAudit(t, o)
	var want admission.AuditRow
	for _, r := range rows {
		if r.Kind == admission.KindBlockIP && r.State == admission.StateVerified {
			want = r
		}
	}
	if want.Disposition != admission.DispositionApplied {
		t.Fatalf("fixture has no applied block row: %+v", rows)
	}

	sink.set(errors.New("disk full"))
	if err := o.do(o.deliverAudit); err == nil {
		t.Fatal("a failed write reported delivery")
	}
	if got := consumer.seen(); len(got) != 0 {
		t.Fatalf("consumers saw rows the action log did not record: %+v", got)
	}

	sink.set(nil)
	cause := errors.New("fixture consumer failure")
	consumer.set(cause)
	if err := o.do(o.deliverAudit); !errors.Is(err, cause) {
		t.Fatalf("delivery error = %v, want the consumer failure", err)
	}
	if status := o.Status(); status.Owner == nil || !strings.Contains(status.Owner.AuditError, cause.Error()) {
		t.Fatalf("consumer failure is not visible: %+v", status.Owner)
	}
	if got := pendingAudit(t, o); len(got) != len(rows) {
		t.Fatalf("a failed consumer acknowledged rows: %d of %d left", len(got), len(rows))
	}

	consumer.set(nil)
	if err := o.do(o.deliverAudit); err != nil {
		t.Fatal(err)
	}
	if got := o.Status().Owner.AuditError; got != "" {
		t.Fatalf("recovered delivery still reports %q", got)
	}
	if got := pendingAudit(t, o); len(got) != 0 {
		t.Fatalf("delivered rows still pending: %+v", got)
	}
	batches := consumer.seen()
	if len(batches) != 2 {
		t.Fatalf("consumer batches = %+v, want the failed one repeated", batches)
	}
	for i, batch := range batches {
		if len(batch) != 1 || batch[0].ID() != want.ID() || !batch[0].At.Equal(want.At) || batch[0].Target != want.Target || !batch[0].ExpiresAt.Equal(want.ExpiresAt) {
			t.Fatalf("batch %d = %+v, want only the applied block %+v", i, batch, want)
		}
	}

	if err := o.do(o.deliverAudit); err != nil || len(consumer.seen()) != 2 {
		t.Fatalf("an acknowledged row reached its consumer again: %d batches, %v", len(consumer.seen()), err)
	}
}

// Without a consumer, applied rows are delivered and acknowledged as
// before.
func TestOwnerWithoutAnAppliedConsumerAcknowledges(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &auditSink{}
	opts := f.options()
	opts.WriteAudit = sink.write
	o := f.start(opts)
	applied(t, o, p, f.host)
	if err := o.do(o.deliverAudit); err != nil {
		t.Fatal(err)
	}
	if got := pendingAudit(t, o); len(got) != 0 {
		t.Fatalf("rows still pending: %+v", got)
	}
}

func TestOwnerReplaysAppliedBlocksAfterLostAckAndRestart(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink, consumer := &auditSink{}, &appliedSink{}
	opts := f.options()
	opts.WriteAudit = sink.write
	opts.Applied = func(rows []admission.AuditRow) error {
		if err := consumer.consume(rows); err != nil {
			return err
		}
		// Delivery succeeded, but the acknowledgement cannot reach disk.
		return f.db.Close()
	}
	o := f.start(opts)
	applied(t, o, p, f.host)
	want := pendingAudit(t, o)
	if err := o.do(o.deliverAudit); err == nil {
		t.Fatal("the closed store accepted an acknowledgement")
	}
	if got := consumer.seen(); len(got) != 1 || len(got[0]) != 1 {
		t.Fatalf("consumer did not finish before acknowledgement: %+v", got)
	}
	o.Stop()
	db, err := store.Open(f.statePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	opts.DB, opts.Applied = db, consumer.consume
	restarted := f.start(opts)
	if got := pendingAudit(t, restarted); !reflect.DeepEqual(got, want) {
		t.Fatalf("restart lost unacknowledged rows: %+v, want %+v", got, want)
	}
	if err = restarted.do(restarted.deliverAudit); err != nil {
		t.Fatal(err)
	}
	batches := consumer.seen()
	if len(batches) != 2 || !reflect.DeepEqual(batches[0], batches[1]) {
		t.Fatalf("restart did not replay the same applied row: %+v", batches)
	}
	if got := pendingAudit(t, restarted); len(got) != 0 {
		t.Fatalf("successful replay left pending rows: %+v", got)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.batches) != 2 || !reflect.DeepEqual(sink.batches[0], sink.batches[1]) {
		t.Fatalf("restart did not rewrite the unacknowledged action-log batch: %+v", sink.batches)
	}
}

func TestOwnerReportsAppliedConsumerBacklog(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	cause := errors.New("recording applied threat batch: disk full")
	consumer := &appliedSink{err: cause}
	opts := f.options()
	opts.Applied = consumer.consume
	o := f.start(opts)
	setOwnerHook(t, o, &auditBatch, 1)
	for _, ip := range []string{"192.0.2.15", "192.0.2.16", "192.0.2.17"} {
		ended(t, o, p, f.host, ip, admission.KindBlockIP, admission.DispositionApplied)
	}
	if got := len(pendingAudit(t, o)); got != 9 {
		t.Fatalf("fixture has %d rows, want three complete attempts", got)
	}
	if err := o.do(o.deliverAudit); !errors.Is(err, cause) {
		t.Fatalf("delivery = %v", err)
	}
	pending := pendingAudit(t, o)
	if len(pending) != 7 || pending[0].Disposition != admission.DispositionApplied {
		t.Fatalf("head did not hold two later attempts: %+v", pending)
	}
	if err := o.do(o.deliverAudit); !errors.Is(err, cause) || !reflect.DeepEqual(pending, pendingAudit(t, o)) {
		t.Fatalf("retry lost or acknowledged the blocked batch: %v", err)
	}
	if got := o.Status().Owner.AuditError; got != cause.Error() {
		t.Fatalf("blocked delivery cause = %q", got)
	}
	later := time.Now().Add(10 * time.Minute)
	if q := o.QueueStatuses(later)["audit"]; q.Status != "degraded" || q.Depth == 0 {
		t.Fatalf("blocked delivery queue = %+v", q)
	}
	consumer.set(nil)
	if err := o.do(o.deliverAudit); err != nil {
		t.Fatal(err)
	}
	if len(pendingAudit(t, o)) != 0 || o.Status().Owner.AuditError != "" {
		t.Fatal("recovery left pending rows or a stale error")
	}
	if q := o.QueueStatuses(later)["audit"]; q.Status == "degraded" || q.Depth != 0 {
		t.Fatalf("recovered delivery queue = %+v", q)
	}
}

// Audit delivery runs every second; status reads the whole ledger and runs
// on its own slower timer. A delivery publishes only a change of its error,
// copying the cached status, so steady deliveries read no ledger status.
func TestOwnerDeliveryPublishesOnlyAChangedError(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &auditSink{}
	opts := f.options()
	opts.WriteAudit = sink.write
	o := f.start(opts)
	applied(t, o, p, f.host)
	before := o.Status()
	for range 3 {
		if err := o.do(o.deliverAudit); err != nil {
			t.Fatal(err)
		}
	}
	if o.Status() != before {
		t.Fatal("a steady delivery republished the status")
	}
	cause := errors.New("fixture delivery failure")
	sink.set(cause)
	ended(t, o, p, f.host, "192.0.2.15", admission.KindBlockIP, admission.DispositionApplied)
	_ = o.do(o.deliverAudit)
	failed := o.Status()
	if failed == before || failed.Owner.AuditError != cause.Error() || failed.Ledger != before.Ledger {
		t.Fatalf("a new delivery error was published as %+v; want the cached ledger view with the error", failed.Owner)
	}
	_ = o.do(o.deliverAudit)
	if o.Status() != failed {
		t.Fatal("the same delivery error republished the status")
	}
	sink.set(nil)
	if err := o.do(o.deliverAudit); err != nil {
		t.Fatal(err)
	}
	recovered := o.Status()
	if recovered == failed || recovered.Owner.AuditError != "" {
		t.Fatalf("recovery was published as %+v", recovered.Owner)
	}
	if err := o.do(o.deliverAudit); err != nil || o.Status() != recovered {
		t.Fatalf("a steady delivery after recovery republished the status: %v", err)
	}
}

// A consumer failure after the action log write keeps the rows pending.
// Retries hand them to the consumer again without writing them to the action
// log again, so a long consumer outage cannot rotate the operator's history
// out; a row that arrives meanwhile is written once.
func TestOwnerWritesAPendingRowOnceWhileItsConsumerFails(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink, consumer := &auditSink{}, &appliedSink{err: errors.New("fixture consumer failure")}
	opts := f.options()
	opts.WriteAudit, opts.Applied = sink.write, consumer.consume
	o := f.start(opts)
	applied(t, o, p, f.host)
	first := len(pendingAudit(t, o))
	for range 3 {
		if err := o.do(o.deliverAudit); err == nil {
			t.Fatal("a failed consumer reported delivery")
		}
	}
	ended(t, o, p, f.host, "192.0.2.18", admission.KindBlockIP, admission.DispositionFailed)
	total := len(pendingAudit(t, o))
	if err := o.do(o.deliverAudit); err == nil {
		t.Fatal("a failed consumer reported delivery")
	}
	consumer.set(nil)
	if err := o.do(o.deliverAudit); err != nil {
		t.Fatal(err)
	}
	if got := pendingAudit(t, o); len(got) != 0 {
		t.Fatalf("delivered rows still pending: %+v", got)
	}
	if err := o.do(func() error {
		if len(o.auditWritten) != 0 {
			return fmt.Errorf("acknowledged rows stay in the written set: %d", len(o.auditWritten))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	seen, written := map[string]int{}, 0
	for _, b := range sink.batches {
		for _, r := range b {
			seen[fmt.Sprintf("%+v", r)]++
			written++
		}
	}
	if written != total || len(seen) != total || first >= total {
		t.Fatalf("action log got %d records (%d distinct) for %d rows (%d in the first batch); want each once", written, len(seen), total, first)
	}
	if got := len(consumer.seen()); got != 5 {
		t.Fatalf("consumer saw %d batches, want every retry", got)
	}
}

// New attempts can sort before written rows and displace all or part of a
// failed batch. Acknowledging the newcomers must not forget those writes.
func TestOwnerKeepsWrittenRowsAcrossReorderedBatches(t *testing.T) {
	for _, batchSize := range []int{3, 4} {
		t.Run(fmt.Sprint(batchSize), func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			cause := errors.New("fixture consumer failure")
			sink, consumer := &auditSink{}, &appliedSink{err: cause}
			opts := f.options()
			opts.WriteAudit, opts.Applied = sink.write, consumer.consume
			o := f.start(opts)
			setOwnerHook(t, o, &auditBatch, batchSize)
			first, now := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.19")
			second, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.20")
			a, err := admission.NewAttempt(first, 1)
			if err != nil {
				t.Fatal(err)
			}
			b, err := admission.NewAttempt(second, 1)
			if err != nil {
				t.Fatal(err)
			}
			if a.ID < b.ID {
				first, second = second, first
			}
			finish := func(id admission.CandidateID, disposition admission.Disposition) {
				t.Helper()
				if err := o.do(func() error {
					_, attempt, _, err := o.ledger.Reserve(id, admission.LaneGeneral, now.Add(time.Hour))
					if err != nil {
						return err
					}
					if _, _, _, err = o.ledger.Execute(attempt.Attempt.ID); err != nil {
						return err
					}
					_, _, err = o.ledger.Finish(attempt.Attempt.ID, disposition)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			finish(first, admission.DispositionApplied)
			if err := o.do(o.deliverAudit); !errors.Is(err, cause) {
				t.Fatalf("first delivery = %v, want consumer failure", err)
			}
			finish(second, admission.DispositionFailed)
			rows := pendingAudit(t, o)
			if len(rows) != 6 || rows[0].Attempt.Candidate != second {
				t.Fatalf("new rows did not precede the written batch: %+v", rows)
			}
			if err := o.do(o.deliverAudit); !errors.Is(err, cause) {
				t.Fatalf("reordered delivery = %v, want consumer failure", err)
			}
			consumer.set(nil)
			if err := o.do(o.deliverAudit); err != nil {
				t.Fatal(err)
			}
			if got := pendingAudit(t, o); len(got) != 0 {
				t.Fatalf("recovery left pending rows: %+v", got)
			}
			sink.mu.Lock()
			defer sink.mu.Unlock()
			for _, row := range rows {
				writes := 0
				for _, batch := range sink.batches {
					for _, record := range batch {
						if record.ActionID == string(row.Attempt.ID) && record.ActionVersion == uint64(row.Transition) && record.Timestamp.Equal(row.At) {
							writes++
						}
					}
				}
				if writes != 1 {
					t.Errorf("row %+v written %d times, want once", row.ID(), writes)
				}
			}
		})
	}
}
