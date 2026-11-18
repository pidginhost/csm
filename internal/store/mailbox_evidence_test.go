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

	got, err := db.UpdateMailboxEvidence("A@Host.example", func(e *MailboxEvidence) {
		e.Signals = append(e.Signals, sig)
	})
	if err != nil || len(got.Signals) != 1 {
		t.Fatalf("UpdateMailboxEvidence = %+v, %v", got, err)
	}
	// Keys compare case-insensitively, like the mail server's logins.
	got, err = db.UpdateMailboxEvidence("a@host.example", func(e *MailboxEvidence) {
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
	for _, mailbox := range []string{"old@host.example", "kept@host.example", "gone@host.example"} {
		if _, err := db.UpdateMailboxEvidence(mailbox, func(e *MailboxEvidence) {
			e.Signals = []MailboxSignal{{Kind: "forged_sender", Key: mailbox, First: at, Last: at, Count: 1}}
			e.ReportedAt = &reported
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.UpdateMailboxEvidence("GONE@host.example", func(e *MailboxEvidence) { *e = MailboxEvidence{} }); err != nil {
		t.Fatal(err)
	}
	err := db.PruneMailboxEvidence(func(mailbox string, e *MailboxEvidence) {
		if mailbox == "old@host.example" {
			e.Signals, e.ReportedAt = nil, nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := db.countMailboxEvidence(t); n != 1 {
		t.Fatalf("rows after prune = %d, want only kept@host.example", n)
	}
	if _, err := db.UpdateMailboxEvidence("kept@host.example", func(e *MailboxEvidence) {
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
		return tx.Bucket([]byte(mailboxEvidenceBucket)).Put([]byte("a@host.example"), []byte("{"))
	}); err != nil {
		t.Fatal(err)
	}
	called := false
	_, err := db.UpdateMailboxEvidence("a@host.example", func(*MailboxEvidence) { called = true })
	if err == nil || called {
		t.Fatalf("damaged row: err = %v, fn called = %v; want an error before fn", err, called)
	}
}

func TestMailboxEvidencePruneIsolatesDamagedRow(t *testing.T) {
	db := openTestDB(t)
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(mailboxEvidenceBucket))
		if err := b.Put([]byte("a@host.example"), []byte("{")); err != nil {
			return err
		}
		return b.Put([]byte("z@host.example"), []byte("{}"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.PruneMailboxEvidence(func(string, *MailboxEvidence) {}); err == nil {
		t.Fatal("missing corruption error")
	}
	if got := db.countMailboxEvidence(t); got != 1 {
		t.Fatalf("rows=%d, want only the damaged row", got)
	}
	if _, err := db.UpdateMailboxEvidence("a@host.example", func(*MailboxEvidence) {}); err == nil {
		t.Fatal("prune lost damaged ledger")
	}
}
