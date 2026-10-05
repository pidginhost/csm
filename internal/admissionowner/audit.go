package admissionowner

import (
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/queuehealth"
)

const (
	// auditBatchesPerRun bounds the writes one delivery makes, so a
	// backlog cannot hold the owner goroutine.
	auditBatchesPerRun = 16
	// deliveryLag is how long pending work may go without progress before
	// its queue reports a stall.
	deliveryLag = time.Minute
)

// auditBatch bounds the rows one durable write carries; deliveryNow dates
// delivery progress. Tests shrink the one and move the other.
var (
	auditBatch  = 64
	deliveryNow = time.Now
)

// deliverAudit writes pending audit rows to the action log, a batch at a
// time with one durable write each, and acknowledges each row by its ID
// and time only after its write (spec 5.5, O49, ruling R1). A failed or
// unacknowledged write acknowledges nothing: the rows are written again,
// with the same identity, and readers drop the copy.
func (o *Owner) deliverAudit() error {
	for range auditBatchesPerRun {
		rows, err := o.ledger.PendingAudit(auditBatch)
		if err != nil {
			return err
		}
		o.audit.Observe(deliveryNow(), len(rows), o.auditAcked)
		if len(rows) == 0 {
			return nil
		}
		records := make([]actionlog.Record, len(rows))
		acks := make([]admission.AuditAck, len(rows))
		for i, r := range rows {
			records[i], acks[i] = auditRecord(r), r.Ack()
		}
		if err = o.opts.WriteAudit(records); err != nil {
			return err
		}
		if err = o.ledger.AckAudit(acks); err != nil {
			return err
		}
		o.auditAcked += uint64(len(rows))
	}
	return nil
}

// auditRecord is the action log record of one admitted transition: the
// attempt and transition name it, and the row's time tells a re-minted
// attempt's rows apart.
func auditRecord(r admission.AuditRow) actionlog.Record {
	result := r.State.String()
	if r.Disposition != 0 {
		result = r.Disposition.String()
	}
	return actionlog.Record{
		Timestamp: r.At, Op: "respond.block_ip", Action: r.Kind.String(), Actor: actionlog.Daemon,
		FindingID: r.FindingID, ActionID: string(r.Attempt.ID), ActionVersion: uint64(r.Transition),
		Target: r.Target.Key(), Reason: r.Lane.String() + " lane, expires " + r.ExpiresAt.UTC().Format(time.RFC3339),
		Result: actionlog.Result(result),
	}
}

// QueueStatuses reports the owner's deliveries through queue health, which
// does not depend on the ledger being writable.
func (o *Owner) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	return map[string]queuehealth.Status{"audit": o.audit.Snapshot(now)}
}
