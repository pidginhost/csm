package store

import (
	"bytes"
	"encoding/binary"
	"hash/fnv"
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Example keys and values come from this build, older builds and the
// legacy writer. Maintenance parses them and must never panic: a key time it
// accepts orders exactly against a cutoff, and a session it reads is the
// record's own.
func FuzzDryRunExampleRecord(f *testing.F) {
	f.Add([]byte("2026-10-15T12:00:00.000000000Z:192.0.2.1:cand_00000000000000000000000000000001"), []byte(`{"session_id":"0123456789abcdef0123456789abcdef"}`))
	f.Add([]byte("2026-10-15T12:00:00.5Z:2001:db8::1"), []byte(`{"ip":"2001:db8::1","reason":"x","timeout_sec":1}`))
	f.Add([]byte("Z:"), []byte("not json"))
	f.Add([]byte("2026-13-40T99:00:00Z:192.0.2.1"), []byte(`{"session_id":7}`))
	f.Fuzz(func(t *testing.T, key, value []byte) {
		if at, ok := dryRunKeyAt(string(key)); ok {
			if dryRunKeyBefore(key, at) || !dryRunKeyBefore(key, at.Add(time.Nanosecond)) {
				t.Fatalf("key %q parsed as %v but does not order against it", key, at)
			}
		} else if dryRunKeyBefore(key, time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)) {
			t.Fatalf("an unparsed key %q was judged old", key)
		}
		_ = dryRunSession(value)
	})
}

// Mutate a real snapshot without invalidating the meta checksum first, so
// fuzzing reaches page references and element bounds as well as metadata.
func FuzzSnapshotVerification(f *testing.F) {
	path := filepath.Join(f.TempDir(), "snapshot.db")
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		f.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		b, createErr := tx.CreateBucket([]byte("data"))
		if createErr != nil {
			return createErr
		}
		return b.Put([]byte("key"), []byte("value"))
	})
	if closeErr := db.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		f.Fatal(err)
	}
	seed, err := os.ReadFile(path)
	if err != nil {
		f.Fatal(err)
	}
	if err := checkSnapshot(bytes.NewReader(seed), int64(len(seed))); err != nil {
		f.Fatal(err)
	}
	f.Add(uint32(0), []byte{})
	f.Add(uint32(32), []byte{255, 255, 255, 255, 255, 255, 255, 255})
	f.Add(uint32(3*os.Getpagesize()+10), []byte{255, 255})
	f.Fuzz(func(t *testing.T, offset uint32, replacement []byte) {
		data := bytes.Clone(seed)
		copy(data[int(offset)%len(data):], replacement)
		for _, at := range []int{0, os.Getpagesize()} {
			h := fnv.New64a()
			_, _ = h.Write(data[at+16 : at+72])
			binary.NativeEndian.PutUint64(data[at+72:], h.Sum64())
		}
		err := checkSnapshot(bytes.NewReader(data), int64(len(data)))
		if len(replacement) == 0 && err != nil {
			t.Fatalf("unchanged snapshot refused: %v", err)
		}
	})
}
