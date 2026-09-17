package store

import bolt "go.etcd.io/bbolt"

const contentLogicVersionKey = "content:logic_version"

// ContentLogicVersionChanged reports whether token differs from the last
// completed finding re-verification sweep. Reading and committing the marker
// are separate so a crash or shutdown during the sweep causes a retry.
func (db *DB) ContentLogicVersionChanged(token string) (bool, error) {
	var changed bool
	err := db.bolt.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("meta"))
		if meta == nil {
			changed = true
			return nil
		}
		changed = string(meta.Get([]byte(contentLogicVersionKey))) != token
		return nil
	})
	if err != nil {
		return false, err
	}
	return changed, nil
}

// SetContentLogicVersion records token after a finding re-verification sweep
// completes, preventing another run until one of its logic versions changes.
func (db *DB) SetContentLogicVersion(token string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucketIfNotExists([]byte("meta"))
		if err != nil {
			return err
		}
		return meta.Put([]byte(contentLogicVersionKey), []byte(token))
	})
}
