package store

import (
	"reflect"
	"testing"
	"time"
)

func TestAppliedTempBlockReplayPreservesUndo(t *testing.T) {
	db := openThreatTestDB(t)
	const ip = "192.0.2.70"
	expires := time.Now().Add(time.Hour)
	if err := db.AddAppliedTempBlock(ip, "CSM auto-block: ssh_brute", expires); err != nil {
		t.Fatal(err)
	}
	first, _ := db.GetPermanentBlock(ip)
	if _, err := db.AppendUndoEntry("operator", UndoEntry{Inverse: "test", Targets: []string{ip}}); err != nil {
		t.Fatal(err)
	}
	for _, expiry := range []time.Time{expires, expires.Add(-time.Minute)} {
		if err := db.AddAppliedTempBlock(ip, "CSM auto-block: ssh_brute", expiry); err != nil {
			t.Fatal(err)
		}
		if again, _ := db.GetPermanentBlock(ip); !reflect.DeepEqual(first, again) {
			t.Fatalf("replay changed the row: %+v -> %+v", first, again)
		}
		if _, ok, err := db.LatestUndoEntry("operator"); err != nil || !ok {
			t.Fatalf("no-op invalidated undo: %t, %v", ok, err)
		}
	}
	if db.getCounter("threats:count") != 1 {
		t.Fatal("replay changed the threat count")
	}
	if err := db.AddAppliedTempBlock(ip, "CSM auto-block: ssh_brute", expires.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := db.LatestUndoEntry("operator"); err != nil || ok {
		t.Fatalf("a real change kept stale undo: %t, %v", ok, err)
	}
}
