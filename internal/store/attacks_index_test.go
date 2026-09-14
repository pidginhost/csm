package store

import (
	"encoding/json"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestRecordAttackEventIndexHoldsNoEventCopy(t *testing.T) {
	db := openTestDB(t)
	ev := AttackEvent{
		Timestamp:  time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC),
		IP:         "192.0.2.10",
		AttackType: "brute_force",
		CheckName:  "email_auth_failure_realtime",
		Severity:   2,
		Message:    "authentication failure",
	}
	if err := db.RecordAttackEvent(ev, 0); err != nil {
		t.Fatalf("RecordAttackEvent: %v", err)
	}

	key := ev.IP + "/" + TimeKey(ev.Timestamp, 0)
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte("attacks:events:ip")).Get([]byte(key))
		if v == nil {
			t.Fatalf("index row %q missing", key)
		}
		if len(v) != 0 {
			t.Errorf("index row holds %d bytes, want an empty value; the event lives in attacks:events", len(v))
		}
		return nil
	})

	got := db.QueryAttackEvents(ev.IP, 10)
	if len(got) != 1 {
		t.Fatalf("QueryAttackEvents = %d events, want 1", len(got))
	}
	if got[0].Message != ev.Message || got[0].CheckName != ev.CheckName || !got[0].Timestamp.Equal(ev.Timestamp) {
		t.Errorf("QueryAttackEvents returned %+v, want %+v", got[0], ev)
	}
}

// Index rows written by earlier builds carry a copy of the event. They must
// keep answering queries until the count cap or retention rotates them out.
func TestQueryAttackEventsReadsIndexRowsWithEventCopy(t *testing.T) {
	db := openTestDB(t)
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	legacy := AttackEvent{Timestamp: base, IP: "192.0.2.20", AttackType: "recon", CheckName: "http_scanner_profile", Severity: 1, Message: "legacy"}
	current := AttackEvent{Timestamp: base.Add(time.Minute), IP: "192.0.2.20", AttackType: "recon", CheckName: "http_scanner_profile", Severity: 1, Message: "current"}

	legacyKey := TimeKey(legacy.Timestamp, 0)
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket([]byte("attacks:events")).Put([]byte(legacyKey), raw); err != nil {
			return err
		}
		return tx.Bucket([]byte("attacks:events:ip")).Put([]byte(legacy.IP+"/"+legacyKey), raw)
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordAttackEvent(current, 0); err != nil {
		t.Fatalf("RecordAttackEvent: %v", err)
	}

	got := db.QueryAttackEvents("192.0.2.20", 10)
	if len(got) != 2 {
		t.Fatalf("QueryAttackEvents = %d events, want 2", len(got))
	}
	if got[0].Message != "current" || got[1].Message != "legacy" {
		t.Errorf("QueryAttackEvents order = [%q %q], want [current legacy]", got[0].Message, got[1].Message)
	}
}

// When a primary row was overwritten by another address's event, the older
// index copy must be returned as it was, with nothing carried over from the
// other event.
func TestQueryAttackEventsIgnoresPrimaryRowOfAnotherAddress(t *testing.T) {
	db := openTestDB(t)
	ts := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	key := TimeKey(ts, 0)
	mine := AttackEvent{Timestamp: ts, IP: "192.0.2.30", AttackType: "recon", CheckName: "http_scanner_profile", Message: "mine"}
	other := AttackEvent{Timestamp: ts, IP: "198.51.100.30", AttackType: "brute_force", CheckName: "wp_login_bruteforce", Account: "otheraccount", Message: "other"}
	mineRaw, _ := json.Marshal(mine)
	otherRaw, _ := json.Marshal(other)
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket([]byte("attacks:events")).Put([]byte(key), otherRaw); err != nil {
			return err
		}
		return tx.Bucket([]byte("attacks:events:ip")).Put([]byte(mine.IP+"/"+key), mineRaw)
	}); err != nil {
		t.Fatal(err)
	}

	got := db.QueryAttackEvents(mine.IP, 10)
	if len(got) != 1 {
		t.Fatalf("QueryAttackEvents = %d events, want 1", len(got))
	}
	if got[0] != mine {
		t.Errorf("QueryAttackEvents returned %+v, want %+v", got[0], mine)
	}
}
