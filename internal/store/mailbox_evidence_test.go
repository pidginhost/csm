package store

import (
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func (db *DB) countMailboxEvidence(t *testing.T) int {
	t.Helper()
	n := 0
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		n = tx.Bucket([]byte(mailboxEvidenceBucket)).Stats().KeyN
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestMailboxEvidenceUpdateStoresAndDeletesEmpty(t *testing.T) {
	db := openTestDB(t)
	if !db.HasBucket(mailboxEvidenceBucket) {
		t.Fatalf("missing bucket %q", mailboxEvidenceBucket)
	}
	at := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	sig := MailboxSignal{Kind: "new_country", Key: "DE", First: at, Last: at, Count: 1, Detail: "webmail login from DE"}

	got, err := db.UpdateMailboxEvidence("A@Example.com", func(e *MailboxEvidence) {
		e.Signals = append(e.Signals, sig)
	})
	if err != nil || len(got.Signals) != 1 {
		t.Fatalf("UpdateMailboxEvidence = %+v, %v", got, err)
	}
	// Keys compare case-insensitively, like the mail server's logins.
	got, err = db.UpdateMailboxEvidence("a@example.com", func(e *MailboxEvidence) {
		if len(e.Signals) != 1 || !e.Signals[0].First.Equal(at) || e.Signals[0].Detail != sig.Detail {
			t.Fatalf("stored evidence = %+v", e)
		}
		e.Signals = nil
	})
	if err != nil || len(got.Signals) != 0 {
		t.Fatalf("clearing update = %+v, %v", got, err)
	}
	if n := db.countMailboxEvidence(t); n != 0 {
		t.Fatalf("empty ledger kept %d rows, want 0", n)
	}
}

func TestMailboxEvidenceDeleteAndPrune(t *testing.T) {
	db := openTestDB(t)
	at := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	reported := at
	for _, mailbox := range []string{"old@example.com", "kept@example.com", "gone@example.com"} {
		if _, err := db.UpdateMailboxEvidence(mailbox, func(e *MailboxEvidence) {
			e.Signals = []MailboxSignal{{Kind: "forged_sender", Key: mailbox, First: at, Last: at, Count: 1}}
			e.ReportedAt = &reported
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.DeleteMailboxEvidence("GONE@example.com"); err != nil {
		t.Fatal(err)
	}
	err := db.PruneMailboxEvidence(func(mailbox string, e *MailboxEvidence) {
		if mailbox == "old@example.com" {
			e.Signals, e.ReportedAt = nil, nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := db.countMailboxEvidence(t); n != 1 {
		t.Fatalf("rows after prune = %d, want only kept@example.com", n)
	}
	if _, err := db.UpdateMailboxEvidence("kept@example.com", func(e *MailboxEvidence) {
		if len(e.Signals) != 1 || e.ReportedAt == nil || !e.ReportedAt.Equal(reported) {
			t.Fatalf("kept evidence = %+v", e)
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMailboxEvidenceUnreadableRowIsAnError(t *testing.T) {
	db := openTestDB(t)
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(mailboxEvidenceBucket)).Put([]byte("a@example.com"), []byte("{"))
	}); err != nil {
		t.Fatal(err)
	}
	called := false
	_, err := db.UpdateMailboxEvidence("a@example.com", func(*MailboxEvidence) { called = true })
	if err == nil || called {
		t.Fatalf("damaged row: err = %v, fn called = %v; want an error before fn", err, called)
	}
}
