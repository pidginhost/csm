package store

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	bolt "go.etcd.io/bbolt"
)

// challengePassBucket maps an address (16-byte form) to when it last passed
// a challenge, as big-endian unix nanos.
const challengePassBucket = "challenge_passes"

// PutChallengePass records that ip passed a challenge at at.
func (db *DB) PutChallengePass(ip string, at time.Time) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("challenge pass: invalid address %q", ip)
	}
	var val [8]byte
	binary.BigEndian.PutUint64(val[:], uint64(at.UnixNano())) // #nosec G115 -- unix nanos stored as a bit pattern and read back the same way
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(challengePassBucket))
		if err != nil {
			return err
		}
		return b.Put(parsed.To16(), val[:])
	})
}

// ChallengePasses returns the passes recorded after cutoff and deletes the
// older ones.
func (db *DB) ChallengePasses(cutoff time.Time) (map[string]time.Time, error) {
	out := make(map[string]time.Time)
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(challengePassBucket))
		if err != nil {
			return err
		}
		var stale [][]byte
		err = b.ForEach(func(k, v []byte) error {
			if len(k) != net.IPv6len || len(v) != 8 {
				stale = append(stale, append([]byte(nil), k...))
				return nil
			}
			at := time.Unix(0, int64(binary.BigEndian.Uint64(v))) // #nosec G115 -- reverses the bit pattern PutChallengePass wrote
			if !at.After(cutoff) {
				stale = append(stale, append([]byte(nil), k...))
				return nil
			}
			out[net.IP(k).String()] = at
			return nil
		})
		if err != nil {
			return err
		}
		for _, k := range stale {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}
