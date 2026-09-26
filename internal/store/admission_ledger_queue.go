package store

import (
	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

var (
	queueStateKey    = []byte("queue")
	queueCountersKey = []byte("counters")
)

func initializeQueueState(b *bolt.Bucket) error {
	state, err := admission.QueueState{}.MarshalBinary()
	if err != nil {
		return err
	}
	counters, err := admission.QueueCounters{}.MarshalBinary()
	if err != nil {
		return err
	}
	if err := b.Put(queueStateKey, state); err != nil {
		return err
	}
	return b.Put(queueCountersKey, counters)
}

// upgradeLedgerToSchemaTwo adds the queue buckets to a schema 1 ledger
// inside the opening transaction. Every live candidate gets an unassessed
// entry holding a general position; the first current reading assesses and
// places it. A damaged candidate refuses the upgrade, and the transaction
// leaves the schema 1 ledger exactly as it was.
func upgradeLedgerToSchemaTwo(tx *bolt.Tx) error {
	for _, name := range admissionQueueBuckets {
		if _, err := tx.CreateBucket([]byte(name)); err != nil {
			return err
		}
	}
	queue := tx.Bucket([]byte(admissionQueueBucket))
	live := 0
	err := tx.Bucket([]byte(admissionCandidatesBucket)).ForEach(func(k, v []byte) error {
		c, err := admission.UnmarshalCandidate(v)
		if err != nil {
			return err
		}
		if id, _ := c.ID(); string(id) != string(k) {
			return admission.ErrCorruptRecord
		}
		if c.State.Terminal() {
			return nil
		}
		live++
		// Eligibility is unknown until a current reading. Every imported
		// candidate must fit the general partition without borrowing reserve.
		if live > admission.PartitionGeneral.DurableCapacity() {
			return refusal(admission.ReasonQueueOverflow, "legacy queue exceeds unassessed capacity")
		}
		data, err := admission.QueueEntry{Partition: admission.PartitionGeneral}.MarshalBinary()
		if err != nil {
			return err
		}
		return queue.Put(k, data)
	})
	if err != nil {
		return err
	}
	if err := initializeQueueState(tx.Bucket([]byte(admissionQueueStateBucket))); err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{admissionSchemaVersion})
}

func loadQueueState(tx *bolt.Tx) (admission.QueueState, error) {
	raw := tx.Bucket([]byte(admissionQueueStateBucket)).Get(queueStateKey)
	if raw == nil {
		return admission.QueueState{}, admission.ErrCorruptRecord
	}
	return admission.UnmarshalQueueState(raw)
}

func loadQueueCounters(tx *bolt.Tx) (admission.QueueCounters, error) {
	raw := tx.Bucket([]byte(admissionQueueStateBucket)).Get(queueCountersKey)
	if raw == nil {
		return admission.QueueCounters{}, admission.ErrCorruptRecord
	}
	return admission.UnmarshalQueueCounters(raw)
}

// loadQueueEntry loads the entry of a live candidate. A live candidate
// without one, or an entry without its candidate, is a damaged ledger.
func loadQueueEntry(tx *bolt.Tx, id admission.CandidateID) (admission.QueueEntry, error) {
	raw := tx.Bucket([]byte(admissionQueueBucket)).Get([]byte(id))
	if raw == nil {
		return admission.QueueEntry{}, admission.ErrCorruptRecord
	}
	return admission.UnmarshalQueueEntry(raw)
}
