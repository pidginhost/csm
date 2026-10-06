package store

import (
	"crypto/rand"
	"io"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

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
// the episodes they were given; no episode row is invented for them. This
// upgrade completes the chain and records the schema.
func upgradeLedgerToSchemaSix(tx *bolt.Tx) error {
	if _, err := tx.CreateBucket([]byte(admissionEpisodesBucket)); err != nil {
		return err
	}
	if err := startEpisodeSequence(tx); err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{admissionSchemaVersion})
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
		return err
	}
	return tx.Bucket([]byte(admissionEpisodesBucket)).Put([]byte(key), data)
}

// proveEpisodes checks every episode row at open: it decodes under its
// target's canonical key, and each line names a stored candidate of that
// target, kind, episode and generation. The sequence must decode too.
// ParseTargetKey refuses a key that is not canonical.
func proveEpisodes(tx *bolt.Tx) error {
	if _, err := loadEpisodeSequence(tx); err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionEpisodesBucket)).ForEach(func(k, v []byte) error {
		target, err := admission.ParseTargetKey(string(k), admission.Caps{IPv6: true})
		if err != nil {
			return admission.ErrCorruptRecord
		}
		e, err := admission.UnmarshalEpisode(v)
		if err != nil {
			return err
		}
		for _, line := range e.Lines {
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
	})
}

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
// episode row and queues or coalesces it (spec 5.2). The row changes only
// when the arrival is queued or coalesced, or when it is refused because
// its kind's line already had an attempt: that observation still extends
// the episode. The engine, never the caller, chooses the episode.
func (l *AdmissionLedger) placeTx(q *queueTx, req admission.CandidateRequest, e admission.Evidence, ids []admission.EvidenceID) (admission.CandidateID, bool, error) {
	rowKey := req.Target.Key()
	cur, found, err := loadEpisode(q.tx, rowKey)
	if err != nil {
		return "", false, err
	}
	var at *admission.Episode
	var states []admission.LineState
	if found {
		at = &cur
		for _, line := range cur.Lines {
			if line.Candidate == "" {
				state := admission.LineEnded
				if line.Answered {
					state = admission.LineAnswered
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
			states = append(states, admission.LineStateOf(c))
		}
	}
	choice, err := admission.Place(at, states, req.Kind, e.ObservedAt(), l.degraded, q.takeEpisode)
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
	}
	key := admission.CandidateKey{Kind: req.Kind, Target: req.Target, Episode: choice.Episode.ID, Generation: choice.Generation}
	id, err := key.ID()
	if err != nil {
		return "", false, err
	}
	if choice.Answered {
		if err = putEpisode(q.tx, rowKey, choice.Episode); err != nil {
			return "", false, err
		}
		return id, false, refusal(admission.ReasonExistingEffect, "the episode's response already has an attempt")
	}
	req.Episode, req.Generation = key.Episode, key.Generation
	_, created, err := l.enqueueTx(q, req, key, id, ids)
	if err != nil {
		return id, false, err
	}
	observed := e.ObservedAt()
	if line, ok := choice.Episode.Line(req.Kind); ok && line.Observed.After(observed) {
		observed = line.Observed
	}
	row := choice.Episode.WithLine(admission.EpisodeLine{Kind: req.Kind, Generation: key.Generation, Candidate: id, Observed: observed})
	return id, created, putEpisode(q.tx, rowKey, row)
}
