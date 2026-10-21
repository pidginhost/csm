package store

import (
	"slices"
	"testing"
)

func TestMailStatsBucketsExist(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	for _, name := range []string{"mail:stats", "mail:rejects", "mail:gaps"} {
		if !db.HasBucket(name) {
			t.Errorf("missing bucket %q", name)
		}
	}
}

func TestPutMailStatsPrunes(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// Many stale keys pruned in the transaction that also writes: a bbolt
	// cursor that deletes and steps with Next would skip some of them.
	stale := map[int64][]byte{}
	for k := int64(1); k < 100; k++ {
		stale[k] = []byte("old")
	}
	if err = db.PutMailStats(stale, map[string][]byte{"spam": []byte(`["a"]`), "malware": []byte(`["m"]`)}, 0); err != nil {
		t.Fatal(err)
	}
	if err = db.AddMailStatsGap(100, 140); err != nil {
		t.Fatal(err)
	}
	if err = db.AddMailStatsGap(120, 160); err != nil {
		t.Fatal(err)
	}
	if err = db.PutMailStats(map[int64][]byte{100: []byte("a"), 200: []byte("b")}, map[string][]byte{"spam": []byte(`["b"]`)}, 150); err != nil {
		t.Fatal(err)
	}

	buckets, rejects, err := db.MailStats()
	if err != nil {
		t.Fatal(err)
	}
	if len(buckets) != 1 || string(buckets[200]) != "b" {
		t.Fatalf("buckets %v", buckets)
	}
	// A ring value replaces the class's ring; a class not written keeps its ring.
	if len(rejects) != 2 || string(rejects["spam"]) != `["b"]` || string(rejects["malware"]) != `["m"]` {
		t.Fatalf("rejects %q", rejects)
	}
	// A gap goes once it ends before the cutoff, not while it reaches past it.
	gaps, err := db.MailStatsGaps(0)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(gaps, [][2]int64{{120, 160}}) {
		t.Fatalf("gaps %v", gaps)
	}
}

func TestMailStatsGapsSince(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	for _, g := range [][2]int64{{300, 330}, {100, 120}, {200, 260}} {
		if err = db.AddMailStatsGap(g[0], g[1]); err != nil {
			t.Fatal(err)
		}
	}
	for since, want := range map[int64][][2]int64{
		0:   {{100, 120}, {200, 260}, {300, 330}},
		120: {{200, 260}, {300, 330}},
		250: {{200, 260}, {300, 330}},
		330: nil,
	} {
		got, gapsErr := db.MailStatsGaps(since)
		if gapsErr != nil {
			t.Fatal(gapsErr)
		}
		if !slices.Equal(got, want) {
			t.Errorf("since %d: %v, want %v", since, got, want)
		}
	}

	empty, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = empty.Close() }()
	buckets, rejects, err := empty.MailStats()
	if err != nil || len(buckets) != 0 || len(rejects) != 0 {
		t.Fatalf("empty store: %v %v %v", buckets, rejects, err)
	}
}
