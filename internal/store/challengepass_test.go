package store

import (
	"testing"
	"time"
)

func TestChallengePassesRoundTripAndForgetOldOnes(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)
	if err := db.PutChallengePass("203.0.113.80", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.PutChallengePass("2001:db8::80", now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.PutChallengePass("203.0.113.81", now.Add(-10*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.PutChallengePass("not-an-ip", now); err == nil {
		t.Fatal("an invalid address was stored")
	}

	got, err := db.ChallengePasses(now.Add(-7 * 24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !got["203.0.113.80"].Equal(now.Add(-time.Hour)) || !got["2001:db8::80"].Equal(now.Add(-2*time.Hour)) {
		t.Fatalf("passes not read back: %v", got)
	}
	if _, ok := got["203.0.113.81"]; ok {
		t.Fatalf("a pass older than the cutoff was returned: %v", got)
	}
	again, err := db.ChallengePasses(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := again["203.0.113.81"]; ok {
		t.Fatal("a pass older than the cutoff was kept in the store")
	}
}
