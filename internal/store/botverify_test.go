package store

import (
	"net"
	"testing"
	"time"
)

func TestBotVerifyCache_RoundTrip(t *testing.T) {
	tmp := t.TempDir()
	db, err := Open(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	SetGlobal(db)
	defer SetGlobal(nil)

	ip := net.ParseIP("66.249.66.99")
	if err := db.PutBotVerify(ip, "googlebot", true, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	ok, valid := db.GetBotVerify(ip, "googlebot")
	if !valid {
		t.Fatal("entry not valid")
	}
	if !ok {
		t.Fatal("verified flag lost")
	}
}

func TestResetBotVerify_DropsAllEntries(t *testing.T) {
	tmp := t.TempDir()
	db, err := Open(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	SetGlobal(db)
	defer SetGlobal(nil)

	exp := time.Now().Add(24 * time.Hour)
	if perr := db.PutBotVerify(net.ParseIP("66.249.66.99"), "googlebot", true, exp); perr != nil {
		t.Fatal(perr)
	}
	if perr := db.PutBotVerify(net.ParseIP("198.51.100.10"), "facebookbot", false, exp); perr != nil {
		t.Fatal(perr)
	}
	if perr := db.PutBotVerify(net.ParseIP("203.0.113.5"), "amazonbot", false, exp); perr != nil {
		t.Fatal(perr)
	}

	n, rerr := db.ResetBotVerify()
	if rerr != nil {
		t.Fatalf("ResetBotVerify: %v", rerr)
	}
	if n != 3 {
		t.Errorf("ResetBotVerify cleared %d entries, want 3", n)
	}
	if _, valid := db.GetBotVerify(net.ParseIP("66.249.66.99"), "googlebot"); valid {
		t.Error("googlebot entry should be gone")
	}
	if _, valid := db.GetBotVerify(net.ParseIP("198.51.100.10"), "facebookbot"); valid {
		t.Error("facebookbot entry should be gone")
	}

	// Bucket must still be usable for new writes after the reset.
	if perr := db.PutBotVerify(net.ParseIP("66.249.66.99"), "googlebot", true, exp); perr != nil {
		t.Fatalf("PutBotVerify after reset: %v", perr)
	}
	if _, valid := db.GetBotVerify(net.ParseIP("66.249.66.99"), "googlebot"); !valid {
		t.Error("write after reset did not land")
	}
}

func TestResetBotVerify_EmptyBucket(t *testing.T) {
	tmp := t.TempDir()
	db, err := Open(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	n, rerr := db.ResetBotVerify()
	if rerr != nil {
		t.Fatalf("ResetBotVerify on empty bucket: %v", rerr)
	}
	if n != 0 {
		t.Errorf("empty reset reported %d cleared, want 0", n)
	}
}

func TestEnsureBotVerifyLogicVersion_MatchingVersionIsNoOp(t *testing.T) {
	tmp := t.TempDir()
	db, err := Open(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// First call: marker missing -- treat as a logic bump, marker stored.
	if _, vErr := db.EnsureBotVerifyLogicVersion(2); vErr != nil {
		t.Fatalf("first call: %v", vErr)
	}
	// Populate the bucket and re-call with the same version: cache stays.
	exp := time.Now().Add(24 * time.Hour)
	if perr := db.PutBotVerify(net.ParseIP("66.249.66.99"), "googlebot", true, exp); perr != nil {
		t.Fatal(perr)
	}
	dropped, vErr := db.EnsureBotVerifyLogicVersion(2)
	if vErr != nil {
		t.Fatalf("re-call: %v", vErr)
	}
	if dropped {
		t.Error("matching version must not drop bucket")
	}
	if _, valid := db.GetBotVerify(net.ParseIP("66.249.66.99"), "googlebot"); !valid {
		t.Error("cache wiped despite matching version")
	}
}

func TestEnsureBotVerifyLogicVersion_DropsOnMismatch(t *testing.T) {
	tmp := t.TempDir()
	db, err := Open(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if _, vErr := db.EnsureBotVerifyLogicVersion(1); vErr != nil {
		t.Fatal(vErr)
	}
	exp := time.Now().Add(24 * time.Hour)
	if perr := db.PutBotVerify(net.ParseIP("198.51.100.5"), "facebookbot", false, exp); perr != nil {
		t.Fatal(perr)
	}

	dropped, vErr := db.EnsureBotVerifyLogicVersion(2)
	if vErr != nil {
		t.Fatalf("EnsureBotVerifyLogicVersion(2): %v", vErr)
	}
	if !dropped {
		t.Error("version mismatch should drop bucket")
	}
	if _, valid := db.GetBotVerify(net.ParseIP("198.51.100.5"), "facebookbot"); valid {
		t.Error("entry survived version bump")
	}
}

func TestEnsureBotVerifyLogicVersion_EvictsLegacyUnstampedCache(t *testing.T) {
	tmp := t.TempDir()
	db, err := Open(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// Simulate a pre-versioning deploy: cache entries exist but no
	// version marker is stored in the meta bucket.
	exp := time.Now().Add(24 * time.Hour)
	if perr := db.PutBotVerify(net.ParseIP("198.51.100.6"), "amazonbot", false, exp); perr != nil {
		t.Fatal(perr)
	}

	dropped, vErr := db.EnsureBotVerifyLogicVersion(2)
	if vErr != nil {
		t.Fatalf("EnsureBotVerifyLogicVersion: %v", vErr)
	}
	if !dropped {
		t.Error("legacy cache without version marker must be dropped on first run")
	}
	if _, valid := db.GetBotVerify(net.ParseIP("198.51.100.6"), "amazonbot"); valid {
		t.Error("legacy entry survived version migration")
	}
}

func TestBotVerifyCache_Expired(t *testing.T) {
	tmp := t.TempDir()
	db, err := Open(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	SetGlobal(db)
	defer SetGlobal(nil)

	ip := net.ParseIP("198.51.100.10")
	if err := db.PutBotVerify(ip, "bingbot", false, time.Now().Add(-1*time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, valid := db.GetBotVerify(ip, "bingbot")
	if valid {
		t.Error("expired entry must report invalid")
	}
}
