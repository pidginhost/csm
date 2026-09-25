package admission

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"
)

// ErrCorruptRecord reports a stored admission record that fails its
// checksum, strict decoding, canonical form or invariants. A corrupt record
// refuses mutation; it is never repaired by guessing.
var ErrCorruptRecord = errors.New("admission record is corrupt")

// sealRecord encodes v as JSON followed by the first 8 bytes of its SHA-256,
// the framing Generations and Evidence use.
func sealRecord(v any) ([]byte, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	return append(body, sum[:8]...), nil
}

// openRecord verifies the checksum, decodes strictly and requires the
// canonical encoding, so a stored record has exactly one byte form.
func openRecord(data []byte, v any) error {
	if len(data) < 8 {
		return ErrCorruptRecord
	}
	body, sum := data[:len(data)-8], data[len(data)-8:]
	if want := sha256.Sum256(body); !bytes.Equal(sum, want[:8]) {
		return ErrCorruptRecord
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return ErrCorruptRecord
	}
	canonical, err := json.Marshal(v)
	if err != nil || !bytes.Equal(canonical, body) {
		return ErrCorruptRecord
	}
	return nil
}

// unixNano returns t as nanoseconds, or false when t cannot round-trip
// through them.
func unixNano(t time.Time) (int64, bool) {
	if t.IsZero() {
		return 0, false
	}
	n := t.UnixNano()
	return n, n != 0 && time.Unix(0, n).Equal(t)
}

func fromNano(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}
