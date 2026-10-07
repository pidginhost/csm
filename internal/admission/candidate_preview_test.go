package admission

import (
	"bytes"
	"math"
	"reflect"
	"testing"
	"time"
)

// The optional selected lifetime survives encoding and keeps the same
// storage bound. Existing rows with no lifetime remain byte-for-byte equal.
func TestCandidatePreviewLifetimeCodec(t *testing.T) {
	for _, ttl := range []time.Duration{0, 7 * 24 * time.Hour, time.Duration(math.MaxInt64)} {
		c := queuedCandidate(t)
		c.PreviewTTL = ttl
		data, err := c.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		back, err := UnmarshalCandidate(data)
		if err != nil || !reflect.DeepEqual(back, c) {
			t.Fatalf("lifetime %v round trip = %+v, %v", ttl, back, err)
		}
		bound, err := c.MaxBytes()
		if err != nil || bound > MaxCandidateBytes || len(data) > bound {
			t.Fatalf("lifetime %v: actual %d, bound %d, %v", ttl, len(data), bound, err)
		}
		if ttl == 0 && bytes.Contains(data, []byte(`"preview_ttl"`)) {
			t.Fatal("an existing row gained an optional lifetime field")
		}
	}
	c := queuedCandidate(t)
	c.PreviewTTL = -time.Second
	rec, err := queuedCandidate(t).record()
	if err != nil {
		t.Fatal(err)
	}
	rec.PreviewTTL = int64(c.PreviewTTL)
	assertCandidateRefused(t, c, rec)
}
