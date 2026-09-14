package store

import (
	"bytes"
	"net"
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
	if !db.BotVerifyUnverifiable(ip, "facebookbot") {
		t.Fatal("no-PTR record did not survive a restart")
	}
	if db.BotVerifyUnverifiable(ip, "amazonbot") {
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
		if !db.BotVerifyUnverifiable(ip, "claudebot") {
			t.Fatal("live no-PTR record not reported")
		}
	}
	if after := raw(); len(before) == 0 || !bytes.Equal(before, after) {
		t.Fatalf("reads changed the stored record: before %x, after %x", before, after)
	}
}

func TestBotVerifyUnverifiableExpiredRecordIsRemoved(t *testing.T) {
	db := openBotVerifyTestDB(t, t.TempDir())
	ip := net.ParseIP("198.51.100.20")
	if err := db.PutBotVerifyUnverifiable(ip, "gptbot", time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if db.BotVerifyUnverifiable(ip, "gptbot") {
		t.Fatal("expired no-PTR record still suppresses verification")
	}
	var left int
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket([]byte(botVerifyUnverifiableBucket)); b != nil {
			left = b.Stats().KeyN
		}
		return nil
	})
	if left != 0 {
		t.Errorf("expired no-PTR record left %d entries behind", left)
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
	if db.BotVerifyUnverifiable(ip, "facebookbot") {
		t.Error("reset left a no-PTR record suppressing verification")
	}
	if err := db.PutBotVerifyUnverifiable(ip, "facebookbot", exp); err != nil {
		t.Fatalf("write after reset: %v", err)
	}
	if !db.BotVerifyUnverifiable(ip, "facebookbot") {
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
	if !db.BotVerifyUnverifiable(ip, "facebookbot") {
		t.Fatal("matching version cleared a no-PTR record")
	}
	// A verified_bots change can add suffixes or identities; start over.
	if dropped, err := db.EnsureBotVerifyLogicVersion(2); err != nil || !dropped {
		t.Fatalf("mismatched version: dropped=%v err=%v", dropped, err)
	}
	if db.BotVerifyUnverifiable(ip, "facebookbot") {
		t.Error("version change left a no-PTR record suppressing verification")
	}
}
