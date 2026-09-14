package store

import (
	"bytes"
	"net"
	"runtime"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func openBotVerifyTestDB(t *testing.T, dir string) *DB {
	t.Helper()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestBotVerifyUnverifiableSurvivesReopenWithoutVerdict(t *testing.T) {
	dir := t.TempDir()
	db := openBotVerifyTestDB(t, dir)
	ip := net.ParseIP("192.0.2.20")
	if err := db.PutBotVerifyUnverifiable(ip, "facebookbot", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db = openBotVerifyTestDB(t, dir)
	if live, recorded := db.BotVerifyUnverifiable(ip, "facebookbot"); !live || !recorded {
		t.Fatal("no-PTR record did not survive a restart")
	}
	if live, recorded := db.BotVerifyUnverifiable(ip, "amazonbot"); live || recorded {
		t.Error("no-PTR record for one claimed identity applied to another")
	}
	// A missing PTR proves nothing about identity: the verdict cache must
	// still report no entry, so it can never read as a confirmed spoof.
	if _, valid := db.GetBotVerify(ip, "facebookbot"); valid {
		t.Error("no-PTR record surfaced as a verification verdict")
	}
}

func TestBotVerifyUnverifiableReadDoesNotExtendExpiry(t *testing.T) {
	db := openBotVerifyTestDB(t, t.TempDir())
	ip := net.ParseIP("2001:db8::20")
	if err := db.PutBotVerifyUnverifiable(ip, "claudebot", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	raw := func() []byte {
		var out []byte
		_ = db.bolt.View(func(tx *bolt.Tx) error {
			if b := tx.Bucket([]byte(botVerifyUnverifiableBucket)); b != nil {
				out = append([]byte(nil), b.Get(botVerifyKey(ip, "claudebot"))...)
			}
			return nil
		})
		return out
	}
	before := raw()
	for range 3 {
		if live, recorded := db.BotVerifyUnverifiable(ip, "claudebot"); !live || !recorded {
			t.Fatal("live no-PTR record not reported")
		}
	}
	if after := raw(); len(before) == 0 || !bytes.Equal(before, after) {
		t.Fatalf("reads changed the stored record: before %x, after %x", before, after)
	}
}

func TestBotVerifyUnverifiableExpiredRecordRetainsHistory(t *testing.T) {
	db := openBotVerifyTestDB(t, t.TempDir())
	ip := net.ParseIP("198.51.100.20")
	if err := db.PutBotVerifyUnverifiable(ip, "gptbot", time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	before := db.WriteTxID()
	for range 2 {
		if live, recorded := db.BotVerifyUnverifiable(ip, "gptbot"); live || !recorded {
			t.Fatalf("expired record = (%t, %t), want (false, true)", live, recorded)
		}
	}
	if after := db.WriteTxID(); after != before {
		t.Fatal("reading lapsed history wrote to the store")
	}
	var left int
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket([]byte(botVerifyUnverifiableBucket)); b != nil {
			left = b.Stats().KeyN
		}
		return nil
	})
	if left != 1 {
		t.Errorf("expired no-PTR record retained %d history entries, want 1", left)
	}
}

func TestResetBotVerifyClearsUnverifiableRecords(t *testing.T) {
	db := openBotVerifyTestDB(t, t.TempDir())
	exp := time.Now().Add(time.Hour)
	if err := db.PutBotVerify(net.ParseIP("192.0.2.21"), "amazonbot", true, exp); err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP("192.0.2.22")
	if err := db.PutBotVerifyUnverifiable(ip, "facebookbot", exp); err != nil {
		t.Fatal(err)
	}

	n, err := db.ResetBotVerify()
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("ResetBotVerify cleared %d entries, want 2", n)
	}
	if live, recorded := db.BotVerifyUnverifiable(ip, "facebookbot"); live || recorded {
		t.Error("reset left a no-PTR record suppressing verification")
	}
	if err := db.PutBotVerifyUnverifiable(ip, "facebookbot", exp); err != nil {
		t.Fatalf("write after reset: %v", err)
	}
	if live, recorded := db.BotVerifyUnverifiable(ip, "facebookbot"); !live || !recorded {
		t.Error("write after reset did not land")
	}
}

func TestEnsureBotVerifyLogicVersionClearsUnverifiableRecords(t *testing.T) {
	db := openBotVerifyTestDB(t, t.TempDir())
	if _, err := db.EnsureBotVerifyLogicVersion(1); err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP("203.0.113.22")
	if err := db.PutBotVerifyUnverifiable(ip, "facebookbot", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	if dropped, err := db.EnsureBotVerifyLogicVersion(1); err != nil || dropped {
		t.Fatalf("matching version: dropped=%v err=%v", dropped, err)
	}
	if live, recorded := db.BotVerifyUnverifiable(ip, "facebookbot"); !live || !recorded {
		t.Fatal("matching version cleared a no-PTR record")
	}
	// A verified_bots change can add suffixes or identities; start over.
	if dropped, err := db.EnsureBotVerifyLogicVersion(2); err != nil || !dropped {
		t.Fatalf("mismatched version: dropped=%v err=%v", dropped, err)
	}
	if live, recorded := db.BotVerifyUnverifiable(ip, "facebookbot"); live || recorded {
		t.Error("version change left a no-PTR record suppressing verification")
	}
}

func TestBotVerifyUnverifiableReadDuringReset(t *testing.T) {
	db := openBotVerifyTestDB(t, t.TempDir())
	ip := net.ParseIP("192.0.2.23")
	if err := db.PutBotVerifyUnverifiable(ip, "facebookbot", time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	// Hold the writer while the reader sees the old expired record. Committing
	// a reset must not let expiry cleanup dereference the deleted bucket.
	tx, err := db.bolt.Begin(true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := resetBotVerifyBuckets(tx); err != nil {
		t.Fatal(err)
	}
	before := db.bolt.Stats().TxN
	result := make(chan any, 1)
	go func() {
		defer func() { result <- recover() }()
		db.BotVerifyUnverifiable(ip, "facebookbot")
	}()
	deadline := time.Now().Add(5 * time.Second)
	for db.bolt.Stats().TxN == before {
		if time.Now().After(deadline) {
			t.Fatal("reader did not start")
		}
		runtime.Gosched()
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if panicValue := <-result; panicValue != nil {
		t.Fatalf("record read panicked during reset: %v", panicValue)
	}
	if live, recorded := db.BotVerifyUnverifiable(ip, "facebookbot"); live || recorded {
		t.Fatal("reset left retry suppression behind")
	}
}

func TestBotVerifyVerdictReplacesUnverifiableRecord(t *testing.T) {
	for _, verified := range []bool{false, true} {
		db := openBotVerifyTestDB(t, t.TempDir())
		ip := net.ParseIP("192.0.2.24")
		expiry := time.Now().Add(time.Hour)
		for _, bot := range []string{"facebookbot", "gptbot"} {
			if err := db.PutBotVerifyUnverifiable(ip, bot, expiry); err != nil {
				t.Fatal(err)
			}
		}
		if err := db.PutBotVerify(ip, "facebookbot", verified, expiry); err != nil {
			t.Fatal(err)
		}
		if got, valid := db.GetBotVerify(ip, "facebookbot"); !valid || got != verified {
			t.Fatalf("stored verdict = (%t, %t), want (%t, true)", got, valid, verified)
		}
		if err := db.bolt.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(botVerifyUnverifiableBucket))
			if b != nil && b.Get(botVerifyKey(ip, "facebookbot")) != nil {
				t.Error("definitive verdict left stale no-PTR history")
			}
			if b == nil || b.Get(botVerifyKey(ip, "gptbot")) == nil {
				t.Error("verdict cleared another bot identity's history")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
