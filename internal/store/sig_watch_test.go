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
