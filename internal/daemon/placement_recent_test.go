package daemon

import (
	"testing"
	"time"
)

func TestRecentAnalysesExpiresAndEvicts(t *testing.T) {
	const ttl = time.Minute
	t0 := time.Unix(1_700_000_000, 0)
	key := func(ino uint64) analysisKey {
		return analysisKey{Dev: 1, Ino: ino, Size: 10, MtimeNs: 5, Class: "c"}
	}

	r := newRecentAnalyses(2, ttl)
	r.Record(key(1), t0)
	if !r.Seen(key(1), t0.Add(ttl-time.Nanosecond)) {
		t.Fatal("key not seen inside the ttl")
	}
	if other := (analysisKey{Dev: 1, Ino: 1, Size: 10, MtimeNs: 5, Class: "d"}); r.Seen(other, t0) {
		t.Fatal("same inode under another class was seen")
	}
	if r.Seen(key(1), t0.Add(ttl)) {
		t.Fatal("key still seen exactly at the ttl")
	}
	// An expired entry is dropped, so an earlier clock cannot revive it.
	if r.Seen(key(1), t0) {
		t.Fatal("expired key revived")
	}

	r = newRecentAnalyses(2, ttl)
	r.Record(key(1), t0)
	r.Record(key(2), t0)
	r.Record(key(1), t0) // a repeat analysis makes 1 the most recent
	r.Record(key(3), t0)
	if r.Seen(key(2), t0) {
		t.Fatal("least recently recorded key survived past capacity")
	}
	if !r.Seen(key(1), t0) || !r.Seen(key(3), t0) {
		t.Fatal("recent keys evicted")
	}
}
