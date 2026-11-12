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
	r.Record(key(1), r.Begin(), t0)
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
	r.Record(key(1), r.Begin(), t0)
	r.Record(key(2), r.Begin(), t0)
	r.Record(key(1), r.Begin(), t0) // a repeat analysis makes 1 the most recent
	r.Record(key(3), r.Begin(), t0)
	if r.Seen(key(2), t0) {
		t.Fatal("least recently recorded key survived past capacity")
	}
	if !r.Seen(key(1), t0) || !r.Seen(key(3), t0) {
		t.Fatal("recent keys evicted")
	}
}

// A write through any name, or an inode freed and reused, changes the file
// without changing what the key can see. Every close-write forgets the
// inode, and a kernel overflow that hides writes forgets everything.
func TestRecentAnalysesInvalidateAndPurge(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	key := func(dev, ino uint64, class string) analysisKey {
		return analysisKey{Dev: dev, Ino: ino, Size: 10, MtimeNs: 5, Class: class}
	}
	r := newRecentAnalyses(3, time.Minute)
	r.Record(key(1, 1, "a"), r.Begin(), t0)
	r.Record(key(1, 1, "b"), r.Begin(), t0)
	r.Record(key(2, 1, "a"), r.Begin(), t0) // same inode number on another device

	r.Invalidate(1, 1)
	if r.Seen(key(1, 1, "a"), t0) || r.Seen(key(1, 1, "b"), t0) {
		t.Fatal("invalidated inode still seen")
	}
	if !r.Seen(key(2, 1, "a"), t0) {
		t.Fatal("other device's inode invalidated")
	}

	// Evicted entries leave no stale index behind.
	for ino := uint64(10); ino < 14; ino++ {
		r.Record(key(1, ino, "a"), r.Begin(), t0)
	}
	r.Invalidate(1, 10)
	r.Record(key(1, 10, "a"), r.Begin(), t0)
	if !r.Seen(key(1, 10, "a"), t0) {
		t.Fatal("re-recorded key not seen")
	}

	r.Purge()
	for ino := uint64(10); ino < 14; ino++ {
		if r.Seen(key(1, ino, "a"), t0) {
			t.Fatalf("inode %d survived a purge", ino)
		}
	}
	r.Record(key(1, 1, "a"), r.Begin(), t0)
	if !r.Seen(key(1, 1, "a"), t0) {
		t.Fatal("cache unusable after a purge")
	}
}

// An analysis records its key only after it finishes. A write invalidated
// while it ran must not be covered by that late record.
func TestRecentAnalysesDropsRecordAfterInvalidation(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	key := func(ino uint64) analysisKey { return analysisKey{Dev: 1, Ino: ino, Size: 10, MtimeNs: 5, Class: "a"} }

	r := newRecentAnalyses(2, time.Minute)
	begun := r.Begin()
	r.Invalidate(1, 1)
	r.Record(key(1), begun, t0)
	if r.Seen(key(1), t0) {
		t.Fatal("record survived an invalidation during its analysis")
	}
	begun = r.Begin()
	r.Invalidate(1, 2)
	r.Record(key(1), begun, t0)
	if !r.Seen(key(1), t0) {
		t.Fatal("another inode's invalidation dropped the record")
	}

	begun = r.Begin()
	r.Purge()
	r.Record(key(1), begun, t0)
	if r.Seen(key(1), t0) {
		t.Fatal("record survived a purge during its analysis")
	}

	// Past capacity the invalidation history is folded away; records begun
	// before that cannot be checked and are dropped.
	begun = r.Begin()
	for ino := uint64(10); ino < 14; ino++ {
		r.Invalidate(1, ino)
	}
	r.Record(key(1), begun, t0)
	if r.Seen(key(1), t0) {
		t.Fatal("record kept after its invalidation history was dropped")
	}
	r.Record(key(1), r.Begin(), t0)
	if !r.Seen(key(1), t0) {
		t.Fatal("fresh record dropped")
	}
}
