package store

import (
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
	observed := time.Unix(0, time.Now().UnixNano())
	if err := db.PutBotVerifyUnverifiable(ip, "facebookbot", observed); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db = openBotVerifyTestDB(t, dir)
	if got, ok := db.BotVerifyUnverifiable(ip, "facebookbot"); !ok || !got.Equal(observed) {
		t.Fatalf("no-PTR record after restart = (%v, %t), want (%v, true)", got, ok, observed)
	}
	if _, ok := db.BotVerifyUnverifiable(ip, "amazonbot"); ok {
		t.Error("no-PTR record for one claimed identity applied to another")
	}
	// A missing PTR proves nothing about identity: the verdict cache must
	// still report no entry, so it can never read as a confirmed spoof.
	if _, valid := db.GetBotVerify(ip, "facebookbot"); valid {
		t.Error("no-PTR record surfaced as a verification verdict")
	}
}

func TestBotVerifyUnverifiableReadNeverWrites(t *testing.T) {
	db := openBotVerifyTestDB(t, t.TempDir())
	ip := net.ParseIP("2001:db8::20")
	if err := db.PutBotVerifyUnverifiable(ip, "claudebot", time.Now().Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Retention belongs to the sweep. A read that wrote could extend a record
	// or race a concurrent reset of the bucket.
	before := db.WriteTxID()
	for range 3 {
		if _, ok := db.BotVerifyUnverifiable(ip, "claudebot"); !ok {
			t.Fatal("stored no-PTR record not reported")
		}
	}
	if after := db.WriteTxID(); after != before {
		t.Fatal("reading a no-PTR record wrote to the store")
	}
}

func TestSweepBotVerifyUnverifiableRemovesOnlyOlderRecords(t *testing.T) {
	db := openBotVerifyTestDB(t, t.TempDir())
	now := time.Now()
	old := net.ParseIP("192.0.2.25")
	edge := net.ParseIP("192.0.2.26")
	fresh := net.ParseIP("2001:db8::26")
	for _, rec := range []struct {
		ip       net.IP
		observed time.Time
	}{
		{old, now.Add(-25 * time.Hour)},
		{edge, now.Add(-24 * time.Hour)},
		{fresh, now.Add(-time.Minute)},
	} {
		if err := db.PutBotVerifyUnverifiable(rec.ip, "facebookbot", rec.observed); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.PutBotVerify(net.ParseIP("192.0.2.27"), "facebookbot", false, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	n, err := db.SweepBotVerifyUnverifiable(now.Add(-24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("sweep removed %d records, want 1", n)
	}
	if _, ok := db.BotVerifyUnverifiable(old, "facebookbot"); ok {
		t.Error("record observed before the cutoff survived the sweep")
	}
	for _, ip := range []net.IP{edge, fresh} {
		if _, ok := db.BotVerifyUnverifiable(ip, "facebookbot"); !ok {
			t.Errorf("record for %s at or after the cutoff was swept", ip)
		}
	}
	var verdicts int
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		verdicts = tx.Bucket([]byte("botverify")).Stats().KeyN
		return nil
	})
	if verdicts != 1 {
		t.Errorf("sweep touched the verdict cache: %d entries left, want 1", verdicts)
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
	if _, ok := db.BotVerifyUnverifiable(ip, "facebookbot"); ok {
		t.Error("reset left a no-PTR record behind")
	}
	if err := db.PutBotVerifyUnverifiable(ip, "facebookbot", exp); err != nil {
		t.Fatalf("write after reset: %v", err)
	}
	if _, ok := db.BotVerifyUnverifiable(ip, "facebookbot"); !ok {
		t.Error("write after reset did not land")
	}
}

func TestEnsureBotVerifyLogicVersionClearsUnverifiableRecords(t *testing.T) {
	db := openBotVerifyTestDB(t, t.TempDir())
	if _, err := db.EnsureBotVerifyLogicVersion(1); err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP("203.0.113.22")
	if err := db.PutBotVerifyUnverifiable(ip, "facebookbot", time.Now()); err != nil {
		t.Fatal(err)
	}

	if dropped, err := db.EnsureBotVerifyLogicVersion(1); err != nil || dropped {
		t.Fatalf("matching version: dropped=%v err=%v", dropped, err)
	}
	if _, ok := db.BotVerifyUnverifiable(ip, "facebookbot"); !ok {
		t.Fatal("matching version cleared a no-PTR record")
	}
	// A verified_bots change can add suffixes or identities; start over.
	if dropped, err := db.EnsureBotVerifyLogicVersion(2); err != nil || !dropped {
		t.Fatalf("mismatched version: dropped=%v err=%v", dropped, err)
	}
	if _, ok := db.BotVerifyUnverifiable(ip, "facebookbot"); ok {
		t.Error("version change left a no-PTR record behind")
	}
}

func TestBotVerifyUnverifiableReadDuringReset(t *testing.T) {
	db := openBotVerifyTestDB(t, t.TempDir())
	ip := net.ParseIP("192.0.2.23")
	if err := db.PutBotVerifyUnverifiable(ip, "facebookbot", time.Now()); err != nil {
		t.Fatal(err)
	}
	// Hold the writer while the reader sees the old record. Committing a reset
	// must not leave the reader touching the deleted bucket.
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
	if _, ok := db.BotVerifyUnverifiable(ip, "facebookbot"); ok {
		t.Fatal("reset left retry suppression behind")
	}
}

func TestBotVerifyVerdictReplacesUnverifiableRecord(t *testing.T) {
	for _, verified := range []bool{false, true} {
		db := openBotVerifyTestDB(t, t.TempDir())
		ip := net.ParseIP("192.0.2.24")
		expiry := time.Now().Add(time.Hour)
		for _, bot := range []string{"facebookbot", "gptbot"} {
			if err := db.PutBotVerifyUnverifiable(ip, bot, time.Now()); err != nil {
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
