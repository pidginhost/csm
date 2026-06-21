package store

import bolt "go.etcd.io/bbolt"

// EnsureContentLogicVersion records the content-detection logic token and
// reports whether it changed since the last call. The daemon uses the change
// signal to trigger a stale-content-finding re-verification sweep. The marker
// lives in the "meta" bucket under content:logic_version.
func (db *DB) EnsureContentLogicVersion(token string) (bool, error) {
	var changed bool
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucketIfNotExists([]byte("meta"))
		if err != nil {
			return err
		}
		key := []byte("content:logic_version")
		if string(meta.Get(key)) == token {
			return nil
		}
		changed = true
		return meta.Put(key, []byte(token))
	})
	if err != nil {
		return false, err
	}
	return changed, nil
}
