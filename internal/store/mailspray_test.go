package store

import (
	"reflect"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func testMailSprayState() MailSprayState {
	t0 := time.Date(2026, 10, 30, 8, 15, 0, 123456789, time.UTC)
	at := func(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }
	return MailSprayState{
		IPs: map[string]MailSprayIP{
			"198.51.100.7": {
				Failed: map[string]MailSprayFailure{
					"a@example.com": {First: at(0), Last: at(90), Count: 3, Exist: 2},
					"":              {First: at(5), Last: at(5), Count: 1},
				},
				WeakAlerted:     map[string]time.Time{"b@example.com": at(30)},
				Revoked:         map[string]time.Time{"e@example.com": at(35)},
				Untracked:       at(40),
				SuppressedUntil: at(150),
				CompromiseUntil: at(160),
				VerdictAt:       at(90),
				LastSeen:        at(95),
			},
			"2001:db8::7": {LastSeen: at(1)},
		},
		Trust: map[string]map[string]GoodSourcePair{
			"198.51.100.7": {"c@example.com": {First: at(-600), Last: at(80)}},
			"203.0.113.9":  {"d@example.com": {First: at(10), Last: at(20)}},
		},
		Networks: map[string]map[string]time.Time{
			"nobody@example.com": {"198.51.0.0/16": at(7), "2001:db8::/32": at(8)},
		},
	}
}

func TestMailSprayRoundTrip(t *testing.T) {
	db := openTestDB(t)

	empty, err := db.LoadMailSpray()
	if err != nil {
		t.Fatalf("LoadMailSpray before save: %v", err)
	}
	if len(empty.IPs) != 0 || len(empty.Trust) != 0 || len(empty.Networks) != 0 {
		t.Fatalf("LoadMailSpray before save = %+v, want empty", empty)
	}

	want := testMailSprayState()
	if err = db.SaveMailSpray(want); err != nil {
		t.Fatalf("SaveMailSpray: %v", err)
	}

	var raw string
	if err = db.bolt.View(func(tx *bolt.Tx) error {
		raw = string(tx.Bucket([]byte(mailSprayBucket)).Get([]byte("ip:2001:db8::7")))
		return nil
	}); err != nil {
		t.Fatalf("reading stored IPv6 entry: %v", err)
	}
	if wantRaw := `{"last_seen":"2026-10-30T08:16:00.123456789Z"}`; raw != wantRaw {
		t.Errorf("stored IPv6 entry = %s, want %s", raw, wantRaw)
	}

	got, err := db.LoadMailSpray()
	if err != nil {
		t.Fatalf("LoadMailSpray: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip:\n got %+v\nwant %+v", got, want)
	}
}

func TestMailSprayReplaceDropsOld(t *testing.T) {
	db := openTestDB(t)

	if err := db.SaveMailSpray(testMailSprayState()); err != nil {
		t.Fatalf("SaveMailSpray initial: %v", err)
	}
	seen := time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)
	next := MailSprayState{IPs: map[string]MailSprayIP{"192.0.2.1": {LastSeen: seen}}}
	if err := db.SaveMailSpray(next); err != nil {
		t.Fatalf("SaveMailSpray replacement: %v", err)
	}
	got, err := db.LoadMailSpray()
	if err != nil {
		t.Fatalf("LoadMailSpray: %v", err)
	}
	if len(got.IPs) != 1 || !got.IPs["192.0.2.1"].LastSeen.Equal(seen) || len(got.Trust) != 0 || len(got.Networks) != 0 {
		t.Fatalf("after replacement loaded %+v, want only 192.0.2.1", got)
	}

	if err = db.SaveMailSpray(MailSprayState{}); err != nil {
		t.Fatalf("SaveMailSpray empty: %v", err)
	}
	if got, err = db.LoadMailSpray(); err != nil || len(got.IPs) != 0 {
		t.Fatalf("after empty save loaded %+v, %v; want nothing", got, err)
	}
}

func TestMailSprayCorruptEntrySkipped(t *testing.T) {
	db := openTestDB(t)

	want := testMailSprayState()
	if err := db.SaveMailSpray(want); err != nil {
		t.Fatalf("SaveMailSpray: %v", err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(mailSprayBucket))
		for k, v := range map[string]string{
			"ip:198.51.100.9":    "{not json",
			"trust:192.0.2.9":    `{"x@example.com":"later"}`,
			"name:x@example.com": "[1]",
			"other:192.0.2.9":    "{}",
			"ip:":                "{}",
		} {
			if err := b.Put([]byte(k), []byte(v)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("writing corrupt entries: %v", err)
	}

	got, err := db.LoadMailSpray()
	if err != nil {
		t.Fatalf("LoadMailSpray: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("corrupt entries leaked into the load:\n got %+v\nwant %+v", got, want)
	}
}

func TestMailSprayClosedReturnsError(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err = db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err = db.LoadMailSpray(); err == nil {
		t.Errorf("LoadMailSpray on closed store returned nil error")
	}
	if err = db.SaveMailSpray(testMailSprayState()); err == nil {
		t.Errorf("SaveMailSpray on closed store returned nil error")
	}
}
