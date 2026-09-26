package store

import (
	"errors"
	"math"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

func loadIngressState(tx *bolt.Tx) (admission.IngressState, error) {
	raw := tx.Bucket([]byte(admissionQueueStateBucket)).Get(ingressStateKey)
	if raw == nil {
		return admission.IngressState{}, admission.ErrCorruptRecord
	}
	return admission.UnmarshalIngressState(raw)
}

func putIngressState(tx *bolt.Tx, s admission.IngressState) error {
	data, err := s.MarshalBinary()
	if err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionQueueStateBucket)).Put(ingressStateKey, data)
}

// BeginIngress starts a new ingress generation. A generation still open
// ended without a clean close: whatever its ingress held was lost, and it
// is counted as interrupted.
func (l *AdmissionLedger) BeginIngress() (admission.IngressState, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out admission.IngressState
	err := l.update("ingress", func(tx *bolt.Tx) error {
		s, err := loadIngressState(tx)
		if err != nil {
			return err
		}
		if s.Open {
			s.Interrupted++
		}
		s.Generation++
		s.Open, s.Persisted = true, 0
		out = s
		return putIngressState(tx, s)
	})
	if err != nil {
		return admission.IngressState{}, err
	}
	return out, nil
}

// EndIngress closes the current generation cleanly.
func (l *AdmissionLedger) EndIngress() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.update("ingress", func(tx *bolt.Tx) error {
		s, err := loadIngressState(tx)
		if err != nil || !s.Open {
			return err
		}
		s.Open = false
		return putIngressState(tx, s)
	})
}

// EnqueueGroup persists a group of ingress arrivals in one transaction. Each
// arrival publishes its evidence, links its later reports and queues or
// coalesces its request. An arrival whose evidence differs from the stored
// record only in its finding is a later report: it is linked and queued
// against the original. A refused arrival is counted and returned in its
// result; any other error aborts the whole group.
func (l *AdmissionLedger) EnqueueGroup(arrivals []admission.Arrival, checkpoint *admission.IngressCheckpoint) ([]admission.ArrivalResult, int, error) {
	if len(arrivals) > admission.MaxArrivalGroup {
		return nil, 0, refusal(admission.ReasonInvalid, "arrival group is too large")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now, err := l.clock()
	if err != nil {
		return nil, 0, err
	}
	var out []admission.ArrivalResult
	var revision int
	err = l.update("group", func(tx *bolt.Tx) error {
		ingress, txErr := loadIngressState(tx)
		if txErr != nil {
			return txErr
		}
		if !ingress.Open {
			return refusal(admission.ReasonEngineUnavailable, "no ingress generation is open")
		}
		if checkpoint != nil {
			if txErr = checkpoint.Validate(ingress.Checkpoint, ingress.Generation); txErr != nil {
				return txErr
			}
			ingress.Checkpoint = checkpoint
		}
		q, txErr := l.openQueue(tx, now)
		if txErr != nil {
			return txErr
		}
		// Empty groups must meet the same shared damage as arrivals. Drain
		// uses one to distinguish a broken queue from a damaged arrival.
		if _, txErr = q.queueView(); txErr != nil {
			return txErr
		}
		if txErr = q.sweep(); txErr != nil {
			return txErr
		}
		out = make([]admission.ArrivalResult, len(arrivals))
		for i, a := range arrivals {
			id, created, arriveErr := l.arriveTx(q, a)
			out[i].Candidate, out[i].Created, out[i].Err = id, created, arriveErr
			switch reason, refused := admission.ReasonOf(arriveErr); {
			case refused:
				if txErr = q.count(admission.EventRefused, reason, arrivalTier(a, now)); txErr != nil {
					return txErr
				}
			case errors.Is(arriveErr, admission.ErrCandidateTerminal), errors.Is(arriveErr, admission.ErrTransitionConflict):
				// The request names a candidate that has ended or is in
				// flight: the engine's episode choice, not a queue refusal.
			case arriveErr != nil:
				return arriveErr
			}
		}
		ingress.Persisted += uint64(len(arrivals))
		if txErr = putIngressState(tx, ingress); txErr != nil {
			return txErr
		}
		revision = tx.ID()
		return q.flush()
	})
	if err != nil {
		return nil, 0, err
	}
	return out, revision, nil
}

// arrivalTier is the tier the arrival's own evidence supports, for
// counting a refusal; zero when that evidence cannot be assessed.
func arrivalTier(a admission.Arrival, now time.Time) admission.Tier {
	assessed, err := admission.Assess(a.Evidence.Target(), []admission.Evidence{a.Evidence}, now)
	if err != nil {
		return admission.Tier{}
	}
	return assessed.Tier
}

func (l *AdmissionLedger) arriveTx(q *queueTx, a admission.Arrival) (admission.CandidateID, bool, error) {
	e := a.Evidence
	if !a.ReportsOnly && a.Request.Primary != e.ID() {
		return "", false, refusal(admission.ReasonInvalid, "arrival request does not name its evidence")
	}
	if _, err := publishTx(q.tx, l.reg, e); errors.Is(err, admission.ErrEvidenceConflict) {
		stored, loadErr := loadEvidence(q.tx, l.reg, e.ID())
		if loadErr != nil {
			return "", false, loadErr
		}
		if !stored.SameExceptFinding(e) {
			return "", false, err
		}
		// A report-only tail has already acknowledged the primary finding.
		if !a.ReportsOnly {
			if err = linkTx(q.tx, l.reg, e.ID(), e.FindingID()); err != nil {
				return "", false, err
			}
		}
		// Report invariants refer to the immutable original finding, not
		// the remint we just linked as a later report.
		e = stored
	} else if err != nil {
		return "", false, err
	}
	for _, finding := range a.Reports {
		if err := linkTx(q.tx, l.reg, e.ID(), finding); err != nil {
			return "", false, err
		}
	}
	if a.Dropped != 0 {
		links, err := loadReports(q.tx, e)
		if err != nil {
			return "", false, err
		}
		links.Dropped += min(a.Dropped, math.MaxUint32-links.Dropped)
		data, err := links.MarshalBinary()
		if err != nil {
			return "", false, err
		}
		if err = q.tx.Bucket([]byte(admissionReportsBucket)).Put([]byte(e.ID()), data); err != nil {
			return "", false, err
		}
	}
	if a.ReportsOnly {
		return "", false, nil
	}
	ids, err := rootSet(a.Request)
	if err != nil {
		return "", false, err
	}
	key := admission.CandidateKey{Kind: a.Request.Kind, Target: a.Request.Target, Episode: a.Request.Episode, Generation: a.Request.Generation}
	id, err := key.ID()
	if err != nil {
		return "", false, err
	}
	_, created, err := l.enqueueTx(q, a.Request, key, id, ids)
	return id, created, err
}

// QueueSnapshot is the durable queue as the ingress sees it: every live
// position, the partition cursors, the admission time and the inventory.
// It needs a current reading, since the ingress assesses against its time.
func (l *AdmissionLedger) QueueSnapshot() (*admission.QueueSnapshot, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now, err := l.clock()
	if err != nil {
		return nil, err
	}
	inv := l.Inventory()
	snap := &admission.QueueSnapshot{Now: now, Inventory: inv}
	err = l.db.bolt.View(func(tx *bolt.Tx) error {
		q, txErr := openQueueWith(tx, l.reg, inv, now)
		if txErr != nil {
			return txErr
		}
		live, txErr := q.live()
		if txErr != nil {
			return txErr
		}
		for _, lc := range live {
			snap.Items = append(snap.Items, queueItem(lc.id, lc.c, lc.entry))
		}
		snap.Cursors = q.state.Cursors
		snap.Revision = tx.ID()
		ingress, txErr := loadIngressState(tx)
		if txErr != nil {
			return txErr
		}
		snap.Generation, snap.Checkpoint = ingress.Generation, ingress.Checkpoint
		return nil
	})
	if err != nil {
		return nil, err
	}
	return snap, nil
}
