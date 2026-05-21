package store

import (
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
		return b.Put(key, val[:])
	})
}

// GetBotVerify returns (verified, valid). valid=false means no
// non-expired entry exists; the caller should treat the IP as
// unverified and (optionally) enqueue an async verify job.
func (db *DB) GetBotVerify(ip net.IP, bot string) (verified, valid bool) {
	key := botVerifyKey(ip, bot)
	if key == nil {
		return false, false
	}
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("botverify"))
		if b == nil {
			return nil
		}
		val := b.Get(key)
		if len(val) != 9 {
			return nil
		}
		exp := time.Unix(0, int64(binary.BigEndian.Uint64(val[1:]))) // #nosec G115 -- reinterpret stored bit pattern as signed nanos
		if time.Now().After(exp) {
			return nil
		}
		verified = val[0] == 1
		valid = true
		return nil
	})
	return verified, valid
}
