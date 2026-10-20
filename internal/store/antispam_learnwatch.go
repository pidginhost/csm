package store

import bolt "go.etcd.io/bbolt"

// ResetLearnWatch cancels unsent reports and starts new folder baselines
// after explicit disable. The learning ledger and contribution guards stay.
func (db *DB) ResetLearnWatch() error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		for _, name := range WatchBuckets {
			if err := tx.DeleteBucket([]byte(name)); err != nil {
				return err
			}
			if _, err := tx.CreateBucket([]byte(name)); err != nil {
				return err
			}
		}
		return nil
	})
}
