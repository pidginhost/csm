package store

import (
	"bytes"
	"encoding/binary"
	"net"
	"time"

	bolt "go.etcd.io/bbolt"
)

// botVerifyEntry layout:
//
//	byte 0      verified flag (1 byte)
//	bytes 1..8  expiry as unix nanos (8 bytes big-endian)
//
// Key format:
//
//	<bot-bytes> 0x00 <ip-bytes>
//
// IP is stored in its 16-byte form (IPv4 promoted via To16). The
// 0x00 separator allows the bot name to be any non-null string while
// keeping keys byte-sortable within a single bucket.
func botVerifyKey(ip net.IP, bot string) []byte {
	ipBytes := ip.To16()
	if ipBytes == nil {
		return nil
	}
	out := make([]byte, 0, len(bot)+1+16)
	out = append(out, []byte(bot)...)
	out = append(out, 0x00)
	out = append(out, ipBytes...)
	return out
}

// PutBotVerify stores a PTR+forward-A verification result with an
// explicit expiry. A verified=false entry means the IP failed rDNS
// and will emit http_ua_spoof on the next scan that sees it with the
// same bot UA.
func (db *DB) PutBotVerify(ip net.IP, bot string, verified bool, expiresAt time.Time) error {
	key := botVerifyKey(ip, bot)
	if key == nil {
		return nil
	}
	var val [9]byte
	if verified {
		val[0] = 1
	}
	binary.BigEndian.PutUint64(val[1:], uint64(expiresAt.UnixNano())) // #nosec G115 -- unix nano stored as bit pattern; sign is irrelevant for expiry comparison
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("botverify"))
		if err != nil {
			return err
		}
		if records := tx.Bucket([]byte(botVerifyUnverifiableBucket)); records != nil {
			if err := records.Delete(key); err != nil {
				return err
			}
		}
		return b.Put(key, val[:])
	})
}

// botVerifyUnverifiableBucket holds sources whose claimed bot identity had no
// PTR record. The value is only the expiry as unix nanos. It lives apart from
// the verdict bucket because a missing PTR proves nothing about identity, and
// a build that predates this bucket must never read it as a spoof verdict.
const botVerifyUnverifiableBucket = "botverify_unverifiable"

// PutBotVerifyUnverifiable records that ip had no PTR for bot until expiresAt,
// so repeat claims wait for the record to lapse before querying DNS again.
func (db *DB) PutBotVerifyUnverifiable(ip net.IP, bot string, expiresAt time.Time) error {
	key := botVerifyKey(ip, bot)
	if key == nil {
		return nil
	}
	var val [8]byte
	binary.BigEndian.PutUint64(val[:], uint64(expiresAt.UnixNano())) // #nosec G115 -- unix nano stored as bit pattern; sign is irrelevant for expiry comparison
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(botVerifyUnverifiableBucket))
		if err != nil {
			return err
		}
		return b.Put(key, val[:])
	})
}

// BotVerifyUnverifiable reports whether a no-PTR record still suppresses DNS
// and whether the source has ever been recorded. Lapsed records keep attempt
// history across restarts and in-memory eviction without extending suppression.
// A definitive verdict or cache reset removes that history. Reads never write.
func (db *DB) BotVerifyUnverifiable(ip net.IP, bot string) (live, recorded bool) {
	key := botVerifyKey(ip, bot)
	if key == nil {
		return false, false
	}
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(botVerifyUnverifiableBucket))
		if b == nil {
			return nil
		}
		val := b.Get(key)
		if len(val) != 8 {
			return nil
		}
		recorded = true
		live = !time.Now().After(unixNanoBits(val))
		return nil
	})
	return live, recorded
}

func unixNanoBits(val []byte) time.Time {
	return time.Unix(0, int64(binary.BigEndian.Uint64(val))) // #nosec G115 -- reinterpret stored bit pattern as signed nanos
}

// EnsureBotVerifyLogicVersion compares the stored cache logic version
// with version and, on mismatch (or when no marker exists yet), drops
// the botverify bucket and its missing-PTR records, then records the new
// version. The marker lives in the "meta" bucket under
// botverify:logic_version. Returns true when the bucket was dropped.
//
// Use this from daemon startup so that any change to the verifier
// logic (BotDomains suffix list, ClaimedBotFromUA mapping, etc.)
// automatically invalidates entries written under the old rules.
// Operators do not need to know about the cache.
func (db *DB) EnsureBotVerifyLogicVersion(version int) (bool, error) {
	var dropped bool
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		meta, mErr := tx.CreateBucketIfNotExists([]byte("meta"))
		if mErr != nil {
			return mErr
		}
		current := uint64(version) // #nosec G115 -- logic version is a small positive internal constant
		stored := ^uint64(0)
		if raw := meta.Get([]byte("botverify:logic_version")); len(raw) == 8 {
			stored = binary.BigEndian.Uint64(raw)
		}
		if stored == current {
			return nil
		}
		if _, dErr := resetBotVerifyBuckets(tx); dErr != nil {
			return dErr
		}
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], current)
		if pErr := meta.Put([]byte("botverify:logic_version"), buf[:]); pErr != nil {
			return pErr
		}
		dropped = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return dropped, nil
}

// ResetBotVerify drops every cached PTR+forward-A result and no-PTR record.
// Returns the number of entries cleared. Use after a verifier-logic upgrade that
// would invalidate prior negative cache entries (e.g., a domain suffix
// fix that turns prior false-spoof entries into positives). Safe to
// call when the bucket is missing or empty.
func (db *DB) ResetBotVerify() (int, error) {
	var cleared int
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		var err error
		cleared, err = resetBotVerifyBuckets(tx)
		return err
	})
	if err != nil {
		return 0, err
	}
	return cleared, nil
}

// resetBotVerifyBuckets empties the verdict cache and its no-PTR records
// together, so no retry suppression outlives the rules that produced it.
func resetBotVerifyBuckets(tx *bolt.Tx) (int, error) {
	cleared := 0
	for _, name := range []string{"botverify", botVerifyUnverifiableBucket} {
		if b := tx.Bucket([]byte(name)); b != nil {
			cleared += b.Stats().KeyN
			if err := tx.DeleteBucket([]byte(name)); err != nil {
				return 0, err
			}
		}
	}
	_, err := tx.CreateBucket([]byte("botverify"))
	return cleared, err
}

// GetBotVerify returns (verified, valid). valid=false means no
// non-expired entry exists; the caller should treat the IP as
// unverified and (optionally) enqueue an async verify job.
func (db *DB) GetBotVerify(ip net.IP, bot string) (verified, valid bool) {
	key := botVerifyKey(ip, bot)
	if key == nil {
		return false, false
	}
	var stored []byte
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("botverify"))
		if b == nil {
			return nil
		}
		val := b.Get(key)
		if len(val) != 9 {
			return nil
		}
		stored = append([]byte(nil), val...)
		exp := time.Unix(0, int64(binary.BigEndian.Uint64(val[1:]))) // #nosec G115 -- reinterpret stored bit pattern as signed nanos
		if time.Now().After(exp) {
			return nil
		}
		verified = val[0] == 1
		valid = true
		return nil
	})
	if valid || len(stored) != 9 {
		return verified, valid
	}
	_ = db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("botverify"))
		current := b.Get(key)
		if !bytes.Equal(current, stored) {
			return nil
		}
		exp := time.Unix(0, int64(binary.BigEndian.Uint64(current[1:]))) // #nosec G115 -- reinterpret stored bit pattern as signed nanos
		if time.Now().After(exp) {
			return b.Delete(key)
		}
		return nil
	})
	return verified, valid
}
