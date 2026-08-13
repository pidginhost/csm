package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	bolt "go.etcd.io/bbolt"
)

const (
	timeKeyUTCMarker       = "time_keys:utc_v1"
	timeKeyHistoryTemp     = "time_keys:migrate:history"
	timeKeyAttacksTemp     = "time_keys:migrate:attacks"
	timeKeyAttacksIPTemp   = "time_keys:migrate:attacks_ip"
	timeKeyMigrationDone   = "1"
	historyBucketName      = "history"
	attackEventsBucketName = "attacks:events"
	attackEventsIPBucket   = "attacks:events:ip"
)

// migrateTimeKeysToUTC rewrites keys created by releases that formatted the
// wall clock from each timestamp's own location. Values retain the authoritative
// instant, so the rewrite can safely canonicalize mixed local/UTC stores. The
// buckets and marker are replaced in one transaction: a failed migration leaves
// the original indexes intact and is retried on the next Open.
func (db *DB) migrateTimeKeysToUTC() error {
	var done bool
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("meta"))
		done = meta != nil && string(meta.Get([]byte(timeKeyUTCMarker))) == timeKeyMigrationDone
		return nil
	}); err != nil {
		return err
	}
	if done {
		return nil
	}

	return db.bolt.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("meta"))
		if string(meta.Get([]byte(timeKeyUTCMarker))) == timeKeyMigrationDone {
			return nil
		}

		if err := migrateHistoryTimeKeys(tx); err != nil {
			return fmt.Errorf("history: %w", err)
		}
		if err := migrateAttackTimeKeys(tx); err != nil {
			return fmt.Errorf("attack events: %w", err)
		}
		return meta.Put([]byte(timeKeyUTCMarker), []byte(timeKeyMigrationDone))
	})
}

func migrateHistoryTimeKeys(tx *bolt.Tx) error {
	src := tx.Bucket([]byte(historyBucketName))
	if bucketIsEmpty(src) {
		return nil
	}
	tmp, err := freshMigrationBucket(tx, timeKeyHistoryTemp)
	if err != nil {
		return err
	}

	if src != nil {
		c := src.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var finding alert.Finding
			if decodeErr := json.Unmarshal(v, &finding); decodeErr != nil {
				if _, putErr := putPreservedValue(tmp, k, v); putErr != nil {
					return putErr
				}
				continue
			}
			if _, putErr := putMigratedTimeValue(tmp, finding.Timestamp, timeKeyCounter(k), v); putErr != nil {
				return putErr
			}
		}
	}

	return replaceBucketFromTemp(tx, historyBucketName, timeKeyHistoryTemp)
}

func migrateAttackTimeKeys(tx *bolt.Tx) error {
	primary := tx.Bucket([]byte(attackEventsBucketName))
	secondary := tx.Bucket([]byte(attackEventsIPBucket))
	if bucketIsEmpty(primary) && bucketIsEmpty(secondary) {
		return nil
	}
	tmpPrimary, err := freshMigrationBucket(tx, timeKeyAttacksTemp)
	if err != nil {
		return err
	}

	keyMap := make(map[string]string)
	if primary != nil {
		c := primary.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			oldKey := string(k)
			var event AttackEvent
			var newKey string
			var putErr error
			if decodeErr := json.Unmarshal(v, &event); decodeErr != nil {
				newKey, putErr = putPreservedValue(tmpPrimary, k, v)
			} else {
				newKey, putErr = putMigratedTimeValue(tmpPrimary, event.Timestamp, timeKeyCounter(k), v)
			}
			if putErr != nil {
				return putErr
			}
			keyMap[oldKey] = newKey
		}
	}
	if replaceErr := replaceBucketFromTemp(tx, attackEventsBucketName, timeKeyAttacksTemp); replaceErr != nil {
		return replaceErr
	}

	tmpSecondary, err := freshMigrationBucket(tx, timeKeyAttacksIPTemp)
	if err != nil {
		return err
	}
	if secondary != nil {
		c := secondary.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			sep := bytes.LastIndexByte(k, '/')
			if sep >= 0 {
				if newTimeKey, ok := keyMap[string(k[sep+1:])]; ok {
					newKey := string(k[:sep+1]) + newTimeKey
					if _, err := putPreservedValue(tmpSecondary, []byte(newKey), v); err != nil {
						return err
					}
					continue
				}
			}
			if _, err := putPreservedValue(tmpSecondary, k, v); err != nil {
				return err
			}
		}
	}
	return replaceBucketFromTemp(tx, attackEventsIPBucket, timeKeyAttacksIPTemp)
}

func bucketIsEmpty(b *bolt.Bucket) bool {
	if b == nil {
		return true
	}
	k, _ := b.Cursor().First()
	return k == nil
}

func freshMigrationBucket(tx *bolt.Tx, name string) (*bolt.Bucket, error) {
	if tx.Bucket([]byte(name)) != nil {
		if err := tx.DeleteBucket([]byte(name)); err != nil {
			return nil, err
		}
	}
	return tx.CreateBucket([]byte(name))
}

func replaceBucketFromTemp(tx *bolt.Tx, name, tempName string) error {
	if tx.Bucket([]byte(name)) != nil {
		if err := tx.DeleteBucket([]byte(name)); err != nil {
			return err
		}
	}
	dst, err := tx.CreateBucket([]byte(name))
	if err != nil {
		return err
	}
	tmp := tx.Bucket([]byte(tempName))
	if tmp != nil {
		if err := tmp.ForEach(func(k, v []byte) error {
			return dst.Put(k, v)
		}); err != nil {
			return err
		}
	}
	return tx.DeleteBucket([]byte(tempName))
}

func putMigratedTimeValue(b *bolt.Bucket, timestamp time.Time, start int, value []byte) (string, error) {
	for counter := start; ; counter++ {
		key := TimeKey(timestamp, counter)
		if b.Get([]byte(key)) == nil {
			return key, b.Put([]byte(key), value)
		}
	}
}

func putPreservedValue(b *bolt.Bucket, key, value []byte) (string, error) {
	candidate := string(key)
	for suffix := 0; b.Get([]byte(candidate)) != nil; suffix++ {
		candidate = fmt.Sprintf("%s~%04d", key, suffix)
	}
	return candidate, b.Put([]byte(candidate), value)
}

func timeKeyCounter(key []byte) int {
	sep := bytes.LastIndexByte(key, '-')
	if sep < 0 || sep == len(key)-1 {
		return 0
	}
	counter, err := strconv.Atoi(string(key[sep+1:]))
	if err != nil || counter < 0 {
		return 0
	}
	return counter
}
