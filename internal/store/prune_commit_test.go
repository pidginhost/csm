package store

import (
	"errors"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// The prune helpers counted deletions inside the transaction and returned
// that count even when the transaction failed to commit, so callers logged
// and metered rows that were still in the database. A failed commit removes
// nothing and must report nothing.
func TestPruneHelpersReportZeroWhenCommitFails(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	past := time.Now().Add(-48 * time.Hour)
	if err := db.putThreatEntry(PermanentBlockEntry{IP: "203.0.113.70", Reason: "expired", BlockedAt: past, Source: "auto", ExpiresAt: past}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetReputation("203.0.113.71", ReputationEntry{Score: 90, CheckedAt: past}); err != nil {
		t.Fatal(err)
	}

	prev := boltUpdate
	boltUpdate = func(b *bolt.DB, fn func(*bolt.Tx) error) error {
		// Run the body, then fail the commit: bbolt rolls the tx back.
		_ = b.Update(func(tx *bolt.Tx) error {
			_ = fn(tx)
			return errors.New("simulated commit failure")
		})
		return errors.New("simulated commit failure")
	}
	threats := db.PruneExpiredThreats()
	reputation := db.CleanExpiredReputation(24 * time.Hour)
	boltUpdate = prev

	if threats != 0 || reputation != 0 {
		t.Fatalf("failed commits reported removals: threats=%d reputation=%d", threats, reputation)
	}
	if got := db.PruneExpiredThreats(); got != 1 {
		t.Fatalf("expired threat did not survive the failed commit: prune now removed %d", got)
	}
	if got := db.CleanExpiredReputation(24 * time.Hour); got != 1 {
		t.Fatalf("expired reputation did not survive the failed commit: clean now removed %d", got)
	}
}
