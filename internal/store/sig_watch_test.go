package store

import (
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestSignatureFilesRoundTrip(t *testing.T) {
	db := openTestDB(t)
	mtime := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	want := map[string]SignatureFileState{
		"/opt/csm/rules/malware.yml": {Mtime: mtime, Size: 143, SHA256: "ab12"},
	}
	if err := db.PutSignatureFiles(want); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetSignatureFiles()
	if err != nil {
		t.Fatal(err)
	}
	state, ok := got["/opt/csm/rules/malware.yml"]
	if len(got) != 1 || !ok {
		t.Fatalf("got %v, want one entry for malware.yml", got)
	}
	if !state.Mtime.Equal(mtime) || state.Size != 143 || state.SHA256 != "ab12" {
		t.Fatalf("state = %+v, want mtime %v size 143 sha ab12", state, mtime)
	}
}

// Stores written before content hashes were tracked hold a bare path to
// mtime map. Reading one must keep the mtimes, so the first tick after an
// upgrade still compares against what was last seen.
func TestSignatureFilesReadsLegacyMtimeMap(t *testing.T) {
	db := openTestDB(t)
	legacy := `{"/opt/csm/rules/malware.yml":"2026-09-01T12:00:00Z"}`
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("sig_watch")).Put([]byte(sigWatchKey), []byte(legacy))
	}); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetSignatureFiles()
	if err != nil {
		t.Fatal(err)
	}
	state := got["/opt/csm/rules/malware.yml"]
	if !state.Mtime.Equal(time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("legacy mtime lost: %+v", state)
	}
	if state.SHA256 != "" || state.Size != -1 {
		t.Fatalf("legacy entry = %+v, want unknown size (-1) and no hash", state)
	}
}

// A queued rescan is stored with the rule state that caused it, so a restart
// before the sweep finishes cannot lose it. Only the sweep that read a
// generation may clear it.
func TestSignatureRescanPendingUntilCleared(t *testing.T) {
	db := openTestDB(t)
	pending := func() uint64 {
		t.Helper()
		gen, err := db.SignatureRescanPending()
		if err != nil {
			t.Fatal(err)
		}
		return gen
	}
	arm := func(state map[string]SignatureFileState) uint64 {
		t.Helper()
		gen, err := db.PutSignatureFilesWithRescan(state)
		if err != nil {
			t.Fatal(err)
		}
		return gen
	}
	clear := func(gen uint64) bool {
		t.Helper()
		cleared, err := db.ClearSignatureRescan(gen)
		if err != nil {
			t.Fatal(err)
		}
		return cleared
	}

	if gen := pending(); gen != 0 {
		t.Fatalf("fresh store pending = %d, want 0", gen)
	}
	state := map[string]SignatureFileState{"/opt/csm/rules/malware.yml": {Size: 1, SHA256: "aa"}}
	first := arm(state)
	if first == 0 {
		t.Fatal("arming returned no generation")
	}
	got, err := db.GetSignatureFiles()
	if err != nil || got["/opt/csm/rules/malware.yml"].SHA256 != "aa" {
		t.Fatalf("rule state not written with the rescan: %v, %v", got, err)
	}
	second := arm(state)
	if second <= first {
		t.Fatalf("re-arm = %d, want a generation after %d", second, first)
	}
	if clear(first) {
		t.Fatal("stale clear removed the newer rescan")
	}
	if gen := pending(); gen != second {
		t.Fatalf("pending = %d after stale clear, want %d", gen, second)
	}
	if !clear(second) {
		t.Fatal("current generation not cleared")
	}
	if gen := pending(); gen != 0 {
		t.Fatalf("pending = %d after clear, want 0", gen)
	}
	if third := arm(state); third <= second {
		t.Fatalf("arm after clear = %d; generations must not repeat", third)
	}
}

func TestSignatureRescanRepairsCorruptRecord(t *testing.T) {
	for _, raw := range []string{
		"{", "null", "{}", `{"generation":0,"pending":true}`,
		`{"generation":1}`, `{"generation":"bad","pending":true}`,
	} {
		t.Run(raw, func(t *testing.T) {
			db := openTestDB(t)
			old, err := db.PutSignatureFilesWithRescan(nil)
			if err != nil {
				t.Fatal(err)
			}
			if writeErr := db.bolt.Update(func(tx *bolt.Tx) error {
				return tx.Bucket([]byte("sig_watch")).Put([]byte(sigRescanKey), []byte(raw))
			}); writeErr != nil {
				t.Fatal(writeErr)
			}
			if pending, readErr := db.SignatureRescanPending(); readErr == nil || pending != 0 {
				t.Errorf("corrupt record accepted: generation %d, error %v", pending, readErr)
			}
			state := map[string]SignatureFileState{"/opt/csm/rules/malware.yml": {Size: 2, SHA256: "bb"}}
			gen, err := db.PutSignatureFilesWithRescan(state)
			if err != nil || gen <= old {
				t.Fatalf("cannot queue after corruption: generation %d, error %v", gen, err)
			}
			got, err := db.GetSignatureFiles()
			if err != nil || got["/opt/csm/rules/malware.yml"].SHA256 != "bb" {
				t.Fatalf("repaired queue lost its rule state: %v, %v", got, err)
			}
			if cleared, err := db.ClearSignatureRescan(old); err != nil || cleared {
				t.Fatalf("stale sweep cleared repaired queue: %v, %v", cleared, err)
			}
			if cleared, err := db.ClearSignatureRescan(gen); err != nil || !cleared {
				t.Fatalf("repaired queue cannot be cleared: %v, %v", cleared, err)
			}
		})
	}
}

func TestSignatureRescanLegacyGenerationSurvivesCorruption(t *testing.T) {
	db := openTestDB(t)
	// Compaction can reset transaction IDs below a saved generation. Older
	// queues have no bucket sequence, so claiming one must preserve its token.
	const legacyGeneration = 5000
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("sig_watch"))
		return b.Put([]byte(sigRescanKey), []byte(`{"generation":5000,"pending":true}`))
	}); err != nil {
		t.Fatal(err)
	}
	gen, err := db.SignatureRescanPending()
	if err != nil || gen != legacyGeneration {
		t.Fatalf("legacy queue not readable: %d, %v", gen, err)
	}
	if writeErr := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("sig_watch")).Put([]byte(sigRescanKey), []byte("{"))
	}); writeErr != nil {
		t.Fatal(writeErr)
	}
	next, err := db.PutSignatureFilesWithRescan(nil)
	if err != nil || next <= gen {
		t.Fatalf("repaired queue reused a legacy sweep's generation: %d after %d, %v", next, gen, err)
	}
	if cleared, err := db.ClearSignatureRescan(gen); err != nil || cleared {
		t.Fatalf("legacy sweep cleared repaired queue: %v, %v", cleared, err)
	}
}
