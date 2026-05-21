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
