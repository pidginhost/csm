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
