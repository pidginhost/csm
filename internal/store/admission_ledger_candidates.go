package store

import (
	"errors"
	"slices"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// errCandidateMissing is the refusal for a candidate the ledger does not
// hold. It is one value, so callers can tell it from other refusals.
var errCandidateMissing error = &admission.Error{Reason: admission.ReasonInvalid, Detail: "candidate is not queued"}

func loadCandidate(tx *bolt.Tx, id admission.CandidateID) (admission.Candidate, error) {
	if _, err := admission.ParseCandidateID(string(id)); err != nil {
		return admission.Candidate{}, err
	}
	raw := tx.Bucket([]byte(admissionCandidatesBucket)).Get([]byte(id))
	if raw == nil {
		return admission.Candidate{}, errCandidateMissing
	}
	c, err := admission.UnmarshalCandidate(raw)
	if err != nil {
		return admission.Candidate{}, err
	}
	if got, _ := c.ID(); got != id {
		return admission.Candidate{}, admission.ErrCorruptRecord
	}
	return c, nil
}

func putCandidate(tx *bolt.Tx, c admission.Candidate) error {
	id, err := c.ID()
	if err != nil {
		return err
	}
	data, err := c.MarshalBinary()
	if err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionCandidatesBucket)).Put([]byte(id), data)
}

// rootSet returns the request's roots sorted and unique, bounded by MaxRoots.
func rootSet(req admission.CandidateRequest) ([]admission.EvidenceID, error) {
	if len(req.Support) >= admission.MaxRoots {
		return nil, refusal(admission.ReasonInvalid, "candidate has too many roots")
	}
	ids := append([]admission.EvidenceID{req.Primary}, req.Support...)
	for _, id := range ids {
		if _, err := admission.ParseEvidenceID(string(id)); err != nil {
			return nil, err
		}
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	return ids, nil
}

// mergeRoots adds new roots to the existing ones while room remains; the
// candidate keeps its original roots and never grows past MaxRoots.
func mergeRoots(have, add []admission.EvidenceID) []admission.EvidenceID {
	out := slices.Clone(have)
	for _, id := range add {
		if len(out) >= admission.MaxRoots {
			break
		}
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

// scopeOwner assigns an account only when every root names the same current
// account generation. Any host or mixed-account root keeps the host scope.
func scopeOwner(inv *admission.Inventory, roots []admission.Evidence) (admission.Owner, error) {
	owner, several, unknown := admission.HostOwner(), false, false
	for _, e := range roots {
		o := e.Owner()
		if o.IsHost() {
			unknown = true
			continue
		}
		if !inv.Current(o) {
			return admission.HostOwner(), refusal(admission.ReasonStaleIdentity, "root evidence names an account that is no longer current")
		}
		if !owner.IsHost() && owner != o {
			several = true
		}
		owner = o
	}
	if several || unknown {
		return admission.HostOwner(), nil
	}
	return owner, nil
}

// Enqueue queues a candidate built from published evidence. A request for a
// queued candidate coalesces its new roots without extending queue age,
// freshness or history. A reserved or executing candidate only acknowledges
// roots it already holds: its attempt's evidence is frozen until the attempt
// ends. A terminal candidate is never revived. Enqueue takes the request's
// episode as given and keeps no episode row: production queues only
// through EnqueueGroup, where the ledger assigns episodes.
func (l *AdmissionLedger) Enqueue(req admission.CandidateRequest) (admission.Candidate, bool, error) {
	ids, err := rootSet(req)
	if err != nil {
		return admission.Candidate{}, false, err
	}
	key := admission.CandidateKey{Kind: req.Kind, Target: req.Target, Episode: req.Episode, Generation: req.Generation}
	id, err := key.ID()
	if err != nil {
		return admission.Candidate{}, false, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now, err := l.clock()
	if err != nil {
		return admission.Candidate{}, false, err
	}
	var out admission.Candidate
	var created bool
	if err := l.update("enqueue", func(tx *bolt.Tx) error {
		q, txErr := l.openQueue(tx, now)
		if txErr != nil {
			return txErr
		}
		if out, created, txErr = l.enqueueTx(q, req, key, id, ids); txErr != nil {
			return txErr
		}
		return q.flush()
	}); err != nil {
		return admission.Candidate{}, false, err
	}
	return out, created, nil
}

// enqueueTx queues or coalesces one request within q's transaction. The
// caller flushes q once its transaction's work is done.
func (l *AdmissionLedger) enqueueTx(q *queueTx, req admission.CandidateRequest, key admission.CandidateKey, id admission.CandidateID, ids []admission.EvidenceID) (admission.Candidate, bool, error) {
	tx, now := q.tx, q.now
	cur, err := loadCandidate(tx, id)
	switch {
	case err == nil:
		return l.coalesceTx(q, cur, ids)
	case !errors.Is(err, errCandidateMissing):
		return admission.Candidate{}, false, err
	}
	// Candidates whose deadlines passed give up their positions before a
	// new one is placed.
	if err = q.sweep(); err != nil {
		return admission.Candidate{}, false, err
	}
	roots, err := loadRoots(tx, l.reg, ids)
	if err != nil {
		return admission.Candidate{}, false, err
	}
	assessment, err := admission.Assess(key.Target, roots, now)
	if err != nil {
		return admission.Candidate{}, false, err
	}
	owner, err := scopeOwner(l.Inventory(), roots)
	if err != nil {
		return admission.Candidate{}, false, err
	}
	primary := roots[slices.Index(ids, req.Primary)]
	c := admission.Candidate{
		Key:         key,
		Scope:       admission.Scope{Owner: owner, Effect: key.Kind.Effect()},
		Entry:       primary.Entry(),
		Check:       primary.Check(),
		FindingID:   primary.FindingID(),
		Roots:       ids,
		FirstQueued: now,
		AgeOut:      minTime(now.Add(admission.QueueAgeLimit), assessment.EvidenceExpiry),
		State:       admission.StateQueued,
		Transitions: 1,
	}
	if err = q.insert(id, c, entryFor(assessment)); err != nil {
		return admission.Candidate{}, false, err
	}
	for _, root := range ids {
		if err = q.name(root); err != nil {
			return admission.Candidate{}, false, err
		}
	}
	return c, true, putCandidate(tx, c)
}

// coalesceTx revalidates a repeated request against current policy and
// inventory, then adds its new roots to a queued candidate, rescopes it and
// records its new assessment. The request alone and the merged set must
// both assess for the target; queue age and age-out never move. An
// in-flight candidate's roots are frozen, so it only acknowledges roots it
// already holds.
func (l *AdmissionLedger) coalesceTx(q *queueTx, cur admission.Candidate, ids []admission.EvidenceID) (admission.Candidate, bool, error) {
	tx, now := q.tx, q.now
	if cur.State.Terminal() {
		return admission.Candidate{}, false, admission.ErrCandidateTerminal
	}
	if cur.Attempts > 0 {
		if _, err := currentAttempt(tx, cur); err != nil {
			return admission.Candidate{}, false, err
		}
	}
	if cur.State != admission.StateQueued {
		for _, id := range ids {
			if !slices.Contains(cur.Roots, id) {
				return admission.Candidate{}, false, admission.ErrTransitionConflict
			}
		}
	}
	// Validate the bounded request even when no extra roots will fit.
	supplied, err := loadRoots(tx, l.reg, ids)
	if err != nil {
		return admission.Candidate{}, false, err
	}
	if _, err = admission.Assess(cur.Key.Target, supplied, now); err != nil {
		return admission.Candidate{}, false, err
	}
	if _, err = scopeOwner(l.Inventory(), supplied); err != nil {
		return admission.Candidate{}, false, err
	}
	merged := mergeRoots(cur.Roots, ids)
	roots, err := loadRoots(tx, l.reg, merged)
	if err != nil {
		return admission.Candidate{}, false, err
	}
	if _, err = admission.Assess(cur.Key.Target, roots, now); err != nil {
		return admission.Candidate{}, false, err
	}
	owner, err := scopeOwner(l.Inventory(), roots)
	if err != nil {
		return admission.Candidate{}, false, err
	}
	if cur.State != admission.StateQueued {
		return cur, false, nil
	}
	if !now.Before(cur.AgeOut) {
		return admission.Candidate{}, false, refusal(admission.ReasonStale, "candidate aged out of the queue")
	}
	if slices.Equal(merged, cur.Roots) && owner == cur.Scope.Owner {
		return cur, false, nil
	}
	id, _ := cur.ID()
	entry, err := loadQueueEntry(tx, id)
	if err != nil {
		return admission.Candidate{}, false, err
	}
	if err = q.remapHistoryRoots(cur, merged); err != nil {
		return admission.Candidate{}, false, err
	}
	for _, root := range merged {
		if !slices.Contains(cur.Roots, root) {
			if err = q.name(root); err != nil {
				return admission.Candidate{}, false, err
			}
		}
	}
	cur.Roots, cur.Scope.Owner = merged, owner
	cur.Transitions++
	if err = putCandidate(tx, cur); err != nil {
		return admission.Candidate{}, false, err
	}
	// Mark the old assessment due inside this transaction. The sweep must
	// see merged support before any candidate chooses a displacement victim.
	if entry.Assessed() {
		entry.NextChange = now
	}
	if err = putQueueEntry(tx, id, entry); err != nil {
		return admission.Candidate{}, false, err
	}
	q.noteDeadlines(cur, entry)
	if err = q.sweep(); err != nil {
		return admission.Candidate{}, false, err
	}
	stored, err := loadCandidate(tx, id)
	return stored, false, err
}

func loadRoots(tx *bolt.Tx, reg *admission.Registry, ids []admission.EvidenceID) ([]admission.Evidence, error) {
	roots := make([]admission.Evidence, 0, len(ids))
	for _, id := range ids {
		e, err := loadEvidence(tx, reg, id)
		if err != nil {
			return nil, err
		}
		roots = append(roots, e)
	}
	return roots, nil
}

// Candidate loads a candidate record.
func (l *AdmissionLedger) Candidate(id admission.CandidateID) (admission.Candidate, error) {
	var c admission.Candidate
	err := l.db.bolt.View(func(tx *bolt.Tx) error {
		var err error
		c, err = loadCandidate(tx, id)
		return err
	})
	return c, err
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
