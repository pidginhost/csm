package store

import (
	"crypto/rand"
	"io"
	"slices"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// admissionSchemaEpisodeElapsed is the schema of a ledger whose episode
// rows may carry an elapsed end. Every host writes episode rows, live or
// not, so unlike schemas 11 and 12 it records nothing of the live start
// or the effect records: at 13 those prove themselves.
const admissionSchemaEpisodeElapsed = 13

// admissionSchemaEpisodeRetained permits a verified episode whose
// candidate references are gone but whose boundary still answers, and a
// block line that names its latest verified generation.
const admissionSchemaEpisodeRetained = 15

// retainedShape reports whether e needs schema 15 to be read.
func retainedShape(e admission.Episode) bool {
	return !e.HasCandidates() || slices.ContainsFunc(e.Lines, func(l admission.EpisodeLine) bool { return l.VerifiedGeneration > 0 })
}

// episodeStateKey holds the episode sequence in the queue state bucket.
var episodeStateKey = []byte("episodes")

// episodeNonce is where a new episode sequence reads its nonce.
var episodeNonce io.Reader = rand.Reader

func loadEpisodeSequence(tx *bolt.Tx) (admission.EpisodeSequence, error) {
	raw := tx.Bucket([]byte(admissionQueueStateBucket)).Get(episodeStateKey)
	if raw == nil {
		return admission.EpisodeSequence{}, admission.ErrCorruptRecord
	}
	return admission.UnmarshalEpisodeSequence(raw)
}

func putEpisodeSequence(tx *bolt.Tx, s admission.EpisodeSequence) error {
	data, err := s.MarshalBinary()
	if err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionQueueStateBucket)).Put(episodeStateKey, data)
}

// startEpisodeSequence gives a new or upgraded ledger its own sequence.
func startEpisodeSequence(tx *bolt.Tx) error {
	s, err := admission.NewEpisodeSequence(episodeNonce)
	if err != nil {
		return err
	}
	return putEpisodeSequence(tx, s)
}

// upgradeLedgerToSchemaSix adds the episode bucket and sequence to a schema
// 5 ledger inside the opening transaction. Candidates queued before keep
// the episodes they were given; no episode row is invented for them.
func upgradeLedgerToSchemaSix(tx *bolt.Tx) error {
	if _, err := tx.CreateBucket([]byte(admissionEpisodesBucket)); err != nil {
		return err
	}
	return startEpisodeSequence(tx)
}

func loadEpisode(tx *bolt.Tx, key string) (admission.Episode, bool, error) {
	raw := tx.Bucket([]byte(admissionEpisodesBucket)).Get([]byte(key))
	if raw == nil {
		return admission.Episode{}, false, nil
	}
	e, err := admission.UnmarshalEpisode(raw)
	return e, true, err
}

func putEpisode(tx *bolt.Tx, key string, e admission.Episode) error {
	data, err := e.MarshalBinary()
	if err != nil {
		// Placement chose the row; one it cannot store is damage, never a
		// refused arrival that would keep a candidate without its row.
		return corruptRecord(err)
	}
	if retainedShape(e) {
		if err = raiseSchema(tx, admissionSchemaEpisodeRetained); err != nil {
			return err
		}
	}
	if e.EndElapsed > 0 {
		if err = raiseSchema(tx, admissionSchemaEpisodeElapsed); err != nil {
			return err
		}
	}
	return tx.Bucket([]byte(admissionEpisodesBucket)).Put([]byte(key), data)
}

// episodeClock is admission time and the ceiling's elapsed time at this
// transaction's reading.
func (q *queueTx) episodeClock() (admission.EpisodeClock, error) {
	s, err := loadCeilingState(q.tx)
	return admission.EpisodeClock{Now: q.now, Elapsed: s.Elapsed}, err
}

// putEpisode anchors legacy rows even when a write changes only their
// lines. The raw encoder remains available for old-format fixtures.
func (q *queueTx) putEpisode(key string, e admission.Episode) error {
	clock, err := q.episodeClock()
	if err != nil {
		return err
	}
	e, err = e.AnchorElapsed(clock)
	if err != nil {
		// A per-arrival refusal could commit candidate writes already
		// made by placement without the matching episode boundary.
		return corruptRecord(err)
	}
	return putEpisode(q.tx, key, e)
}

// proveEpisodes checks every episode row at open: it decodes under its
// target's canonical key, and each line names a stored candidate of that
// target, kind, episode and generation. The sequence must decode too.
// ParseTargetKey refuses a key that is not canonical.
func proveEpisodes(tx *bolt.Tx) error {
	if _, err := loadEpisodeSequence(tx); err != nil {
		return err
	}
	var hasVerifiedReference bool
	if err := tx.Bucket([]byte(admissionEpisodesBucket)).ForEach(func(k, v []byte) error {
		target, err := admission.ParseTargetKey(string(k), admission.Caps{IPv6: true})
		if err != nil {
			return admission.ErrCorruptRecord
		}
		e, err := admission.UnmarshalEpisode(v)
		if err != nil {
			return err
		}
		if retainedShape(e) {
			schema := tx.Bucket([]byte(admissionMetaBucket)).Get(admissionSchemaKey)
			if len(schema) != 1 || schema[0] < admissionSchemaEpisodeRetained {
				return admission.ErrCorruptRecord
			}
		}
		for _, line := range e.Lines {
			hasVerifiedReference = hasVerifiedReference || line.VerifiedGeneration != 0
			if _, _, err := loadVerifiedBlock(tx, e.ID, line, target); err != nil {
				return err
			}
			if line.Candidate == "" {
				continue
			}
			c, err := loadCandidate(tx, line.Candidate)
			if err != nil {
				return corruptRecord(err)
			}
			if c.Key != (admission.CandidateKey{Kind: line.Kind, Target: target, Episode: e.ID, Generation: line.Generation}) {
				return admission.ErrCorruptRecord
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if !hasVerifiedReference {
		return nil
	}
	// Forgotten returns can leave gaps between the current line and its
	// latest verified block. Check retained history without assuming an
	// unbroken generation chain or trusting the reference being proved.
	return tx.Bucket([]byte(admissionCandidatesBucket)).ForEach(func(k, _ []byte) error {
		c, err := loadCandidate(tx, admission.CandidateID(k))
		if err != nil {
			return corruptRecord(err)
		}
		if c.State != admission.StateVerified || (c.Key.Kind != admission.KindBlockIP && c.Key.Kind != admission.KindBlockSubnet) {
			return nil
		}
		e, found, err := loadEpisode(tx, c.Key.Target.Key())
		if err != nil || !found || e.ID != c.Key.Episode {
			return err
		}
		if line, ok := e.Line(c.Key.Kind); ok && line.VerifiedGeneration != 0 && c.Key.Generation > line.VerifiedGeneration {
			return admission.ErrCorruptRecord
		}
		return nil
	})
}

// PreviewsAnswer sets whether an observe preview answers its episode's
// line as a verified effect does. Previews answer while admission only
// previews, so a comparison follows the episode. A forecasting owner turns
// them off: an address previewed before its session is forecast again on
// its next observation (section 8, row 3). Challenge lines always follow
// their previews, which no forecast models.
func (l *AdmissionLedger) PreviewsAnswer(on bool) { l.previewsEnd.Store(!on) }

// takeEpisode names a new episode from the ledger's sequence.
func (q *queueTx) takeEpisode() (admission.EpisodeID, error) {
	s, err := loadEpisodeSequence(q.tx)
	if err != nil {
		return admission.EpisodeID{}, err
	}
	id, err := s.Take()
	if err != nil {
		return admission.EpisodeID{}, err
	}
	return id, putEpisodeSequence(q.tx, s)
}

// placeTx assigns an arrival its episode and generation from the target's
// episode row and queues or coalesces it. The row changes only
// when the arrival is queued or coalesced, or when it is refused because
// its kind's line already had an attempt: that observation still extends
// the episode. The engine, never the caller, chooses the episode.
func (l *AdmissionLedger) placeTx(q *queueTx, req admission.CandidateRequest, e admission.Evidence, ids []admission.EvidenceID) (admission.CandidateID, bool, error) {
	// Assessment tolerates clock skew, but storing it as a frontier would
	// make genuine observations stale or cross a boundary before its time.
	if e.ObservedAt().After(q.now) {
		return "", false, refusal(admission.ReasonInvalid, "episode observation is dated in the future")
	}
	rowKey := req.Target.Key()
	cur, found, err := loadEpisode(q.tx, rowKey)
	if err != nil {
		return "", false, err
	}
	var at *admission.Episode
	var states []admission.LineState
	// gone is when the ledger learned the arriving kind's verified block
	// left early; zero unless this arrival may re-admit it.
	var gone time.Time
	if found {
		if q.started && !cur.Verified.IsZero() && req.Kind == admission.KindBlockIP {
			if line, ok := cur.Line(req.Kind); ok && line.VerifiedGeneration == 0 {
				if line.VerifiedGeneration, err = retainedVerifiedGeneration(q.tx, cur.ID, line, req.Target); err != nil {
					return "", false, err
				}
				cur = cur.WithLine(line)
			}
		}
		at = &cur
		for _, line := range cur.Lines {
			// Without previews answering, a remembered answer of a block
			// line counts only for a verified block, which closes the episode.
			ignore := l.previewsEnd.Load() && line.Kind != admission.KindChallenge
			if line.Candidate == "" {
				state := admission.LineEnded
				if line.Answered && (!ignore || !cur.Verified.IsZero()) {
					state = admission.LineAnswered
				}
				// A forgotten return still owes the verified block's gate.
				var left time.Time
				if state, left, err = q.readmit(cur, line, req, e, state, state == admission.LineAnswered); err != nil {
					return "", false, err
				}
				if !left.IsZero() {
					gone = left
				}
				states = append(states, state)
				continue
			}
			c, loadErr := loadCandidate(q.tx, line.Candidate)
			if loadErr != nil {
				return "", false, corruptRecord(loadErr)
			}
			if c.Key != (admission.CandidateKey{Kind: line.Kind, Target: req.Target, Episode: cur.ID, Generation: line.Generation}) {
				return "", false, admission.ErrCorruptRecord
			}
			retired := false
			if c.State == admission.StateUnknown {
				a, attemptErr := currentAttempt(q.tx, c)
				if attemptErr != nil {
					return "", false, attemptErr
				}
				retired = a.Retired
			}
			state := admission.LineStateOf(c, retired)
			if ignore && c.State == admission.StateObserved {
				state = admission.LineEnded
			}
			var left time.Time
			if state, left, err = q.readmit(cur, line, req, e, state, c.State == admission.StateVerified); err != nil {
				return "", false, err
			}
			if !left.IsZero() {
				gone = left
			}
			states = append(states, state)
		}
	}
	clock, err := q.episodeClock()
	if err != nil {
		return "", false, err
	}
	clock.Degraded = l.degraded
	choice, err := admission.Place(at, states, req.Kind, e.ObservedAt(), clock, q.takeEpisode)
	if err != nil {
		return "", false, err
	}
	for _, root := range ids {
		proof, proofErr := loadEvidence(q.tx, l.reg, root)
		if proofErr != nil {
			return "", false, proofErr
		}
		if proof.ObservedAt().Before(choice.Episode.Previous) || (!choice.Episode.PriorLast.IsZero() && !proof.ObservedAt().After(choice.Episode.PriorLast)) {
			return "", false, refusal(admission.ReasonStale, "support belongs to an earlier episode")
		}
		if !gone.IsZero() && choice.Episode.ID == cur.ID && !proof.ObservedAt().After(gone) {
			return "", false, refusal(admission.ReasonStale, "support predates the block's removal")
		}
	}
	key := admission.CandidateKey{Kind: req.Kind, Target: req.Target, Episode: choice.Episode.ID, Generation: choice.Generation}
	id, err := key.ID()
	if err != nil {
		return "", false, err
	}
	if choice.Answered {
		if err = q.putEpisode(rowKey, choice.Episode); err != nil {
			return "", false, err
		}
		return id, false, refusal(admission.ReasonExistingEffect, "the episode's response already has an attempt")
	}
	req.Episode, req.Generation = key.Episode, key.Generation
	_, created, err := l.enqueueTx(q, req, key, id, ids)
	if err != nil {
		return id, false, err
	}
	next := admission.EpisodeLine{Kind: req.Kind, Generation: key.Generation, Candidate: id, Observed: e.ObservedAt()}
	if line, ok := choice.Episode.Line(req.Kind); ok {
		if line.Observed.After(next.Observed) {
			next.Observed = line.Observed
		}
		// A later generation keeps the episode's latest verified block.
		next.VerifiedGeneration = line.VerifiedGeneration
	}
	row := choice.Episode.WithLine(next)
	return id, created, q.putEpisode(rowKey, row)
}

// retainedVerifiedGeneration anchors an older line on its next write.
// Only an unbroken chain proves which verified block was latest; a gap
// leaves the line answered, as it did before generations were recorded.
func retainedVerifiedGeneration(tx *bolt.Tx, episode admission.EpisodeID, line admission.EpisodeLine, target admission.Target) (uint32, error) {
	key := admission.CandidateKey{Kind: line.Kind, Target: target, Episode: episode, Generation: line.Generation}
	for ; key.Generation > 0; key.Generation-- {
		id, err := key.ID()
		if err != nil {
			return 0, err
		}
		c, err := loadCandidate(tx, id)
		if err == errCandidateMissing {
			return 0, nil
		}
		if err != nil {
			return 0, err
		}
		if c.State == admission.StateVerified {
			return key.Generation, nil
		}
	}
	return 0, nil
}

// VerifiedEnd is the original verified end, in admission time, of the
// episode candidate c belongs to when that episode is its target's
// current row and a verified block closed it: what a same-episode
// re-admission may last until. current distinguishes an
// unverified current row from a lost or replaced row, which cannot grant
// an older queued return a new lifetime.
func (l *AdmissionLedger) VerifiedEnd(c admission.Candidate) (end time.Time, current bool, err error) {
	err = l.db.bolt.View(func(tx *bolt.Tx) error {
		e, found, loadErr := loadEpisode(tx, c.Key.Target.Key())
		if loadErr == nil && found && e.ID == c.Key.Episode {
			end, current = e.Verified, true
		}
		return loadErr
	})
	return end, current, err
}

// readmit applies the evidence gate to the line of the arriving kind. A
// verified block that left before its episode's original end no longer
// answers a later attack of its kind: the attack is a charged re-admission
// of the same episode, never past that end and only
// on evidence observed after the latest removal, which gone
// returns. verified says the line answers through a verified block, its
// own or a forgotten return's. Queued and ended returns keep the gate; a
// line without proof keeps answering. Only a live ledger has effect
// records, so nothing changes on a host that previews or forecasts.
func (q *queueTx) readmit(cur admission.Episode, line admission.EpisodeLine, req admission.CandidateRequest, e admission.Evidence, state admission.LineState, verified bool) (admission.LineState, time.Time, error) {
	if !q.started || cur.Verified.IsZero() || line.Kind != req.Kind || req.Kind != admission.KindBlockIP ||
		(state != admission.LineQueued && state != admission.LineEnded && !verified) {
		return state, time.Time{}, nil
	}
	left, err := q.verifiedGone(cur, line, req.Target)
	if err != nil {
		return state, time.Time{}, err
	}
	if !q.now.Before(cur.Verified) || left.IsZero() || !e.ObservedAt().After(left) {
		return admission.LineAnswered, time.Time{}, nil
	}
	if verified {
		state = admission.LineEnded
	}
	return state, left, nil
}

// verifiedGone is when the ledger learned the latest verified block of
// line's kind in episode cur left the kernel before its expiry, from that
// block's effect record; zero while it holds, or when no retained record
// says. History keeps that block until both episode ends pass.
func (q *queueTx) verifiedGone(cur admission.Episode, line admission.EpisodeLine, target admission.Target) (time.Time, error) {
	c, found, err := loadVerifiedBlock(q.tx, cur.ID, line, target)
	if err != nil || !found {
		return time.Time{}, err
	}
	a, err := currentAttempt(q.tx, c)
	if err != nil {
		return time.Time{}, err
	}
	rec, _, found, err := loadEffect(q.tx, a)
	if err != nil || !found {
		return time.Time{}, err
	}
	return rec.Gone, nil
}

// A verified reference may outlive its history after both episode ends
// pass, but retained history must prove the reference's claimed outcome.
func loadVerifiedBlock(tx *bolt.Tx, episode admission.EpisodeID, line admission.EpisodeLine, target admission.Target) (admission.Candidate, bool, error) {
	if line.VerifiedGeneration == 0 {
		return admission.Candidate{}, false, nil
	}
	id, err := admission.CandidateKey{Kind: line.Kind, Target: target, Episode: episode, Generation: line.VerifiedGeneration}.ID()
	if err != nil {
		return admission.Candidate{}, false, err
	}
	c, err := loadCandidate(tx, id)
	if err == errCandidateMissing {
		return admission.Candidate{}, false, nil
	}
	if err != nil {
		return admission.Candidate{}, false, err
	}
	if c.State != admission.StateVerified {
		return admission.Candidate{}, false, admission.ErrCorruptRecord
	}
	return c, true, nil
}

// forgetLine clears a deleted candidate reference but retains the kind's
// generation and answer. A verified boundary survives the last reference;
// a retained predecessor's retirement collects it after both clocks pass.
func (q *queueTx) forgetLine(id admission.CandidateID, c admission.Candidate) error {
	key := c.Key.Target.Key()
	e, found, err := loadEpisode(q.tx, key)
	if err != nil || !found {
		return err
	}
	// Forgetting an unattempted return must not discard the earlier
	// verified boundary. Its verified predecessor already pays to keep
	// this row until expiry; that predecessor's retirement also collects
	// an unreferenced row once both ends have passed.
	answered := c.State == admission.StateVerified || c.State == admission.StateObserved ||
		(c.Key.Kind == admission.KindBlockIP && !e.Verified.IsZero())
	rest, had := e.WithoutCandidate(id, answered)
	if !rest.HasCandidates() {
		clock, clockErr := q.episodeClock()
		if clockErr != nil {
			return clockErr
		}
		// Only an answered address block line can hold the row (its codec
		// refuses any other unreferenced shape); anything else goes as before.
		line, ok := rest.Line(admission.KindBlockIP)
		if rest.Verified.IsZero() || !ok || !line.Answered || (!clock.Now.Before(rest.Verified) && clock.Elapsed >= rest.EndElapsed) {
			return q.tx.Bucket([]byte(admissionEpisodesBucket)).Delete([]byte(key))
		}
	}
	if !had {
		return nil
	}
	return q.putEpisode(key, rest)
}

// closeEpisode ends the episode of a verified block when its kernel element
// expires: its original expiry, less the lead of the engine's
// lease clock over admission time when it ran, on both admission
// and the ceiling's elapsed time, read on clock: the reading the block ran
// at. Other kinds, and
// a candidate of another episode than its target's row, change nothing. An
// episode queues no new generation of a kind while one is in flight, so
// the verified block is its kind's latest.
func (q *queueTx) closeEpisode(c admission.Candidate, lead time.Duration, clock admission.EpisodeClock) error {
	if c.Key.Kind != admission.KindBlockIP && c.Key.Kind != admission.KindBlockSubnet {
		return nil
	}
	key := c.Key.Target.Key()
	e, found, err := loadEpisode(q.tx, key)
	if err != nil || !found || e.ID != c.Key.Episode {
		return err
	}
	if e, err = e.Close(c.ExpiresAt.Add(-max(lead, 0)), clock); err != nil {
		return err
	}
	// The verified block is its kind's latest generation; the gate reads
	// it even after later generations are retired. Only a live ledger
	// gates re-admissions, so only it records one.
	if line, ok := e.Line(c.Key.Kind); ok && q.started && line.Generation == c.Key.Generation {
		line.VerifiedGeneration = c.Key.Generation
		e = e.WithLine(line)
	}
	return putEpisode(q.tx, key, e)
}
