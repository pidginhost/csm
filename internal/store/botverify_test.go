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
