package store

import (
	"maps"
	"reflect"
	"strings"
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
				Sources:         map[string]MailSpraySource{"198.51.100.7": {SuppressedUntil: at(150), CompromiseUntil: at(160)}},
				Untracked:       at(40),
				RevokedOverflow: at(45),
				VerdictAt:       at(90),
				ObservedAt:      at(91),
				ObservedNames:   2,
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
		Blocked: map[string]time.Time{"198.51.100.7": at(43200), "2001:db8::7": at(100)},
	}
}

func TestMailSprayRoundTrip(t *testing.T) {
	db := openTestDB(t)

	empty, err := loadTestMailSpray(db)
	if err != nil {
		t.Fatalf("LoadMailSpray before save: %v", err)
	}
	if len(empty.IPs) != 0 || len(empty.Trust) != 0 || len(empty.Networks) != 0 || len(empty.Blocked) != 0 {
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

	got, err := loadTestMailSpray(db)
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
	got, err := loadTestMailSpray(db)
	if err != nil {
		t.Fatalf("LoadMailSpray: %v", err)
	}
	if len(got.IPs) != 1 || !got.IPs["192.0.2.1"].LastSeen.Equal(seen) || len(got.Trust) != 0 || len(got.Networks) != 0 || len(got.Blocked) != 0 {
		t.Fatalf("after replacement loaded %+v, want only 192.0.2.1", got)
	}

	if err = db.SaveMailSpray(MailSprayState{}); err != nil {
		t.Fatalf("SaveMailSpray empty: %v", err)
	}
	if got, err = loadTestMailSpray(db); err != nil || len(got.IPs) != 0 {
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
			"blk:192.0.2.9":      "{}",
			"blk:":               `"2026-10-30T08:15:00Z"`,
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

	got, err := loadTestMailSpray(db)
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
	if _, err = loadTestMailSpray(db); err == nil {
		t.Errorf("LoadMailSpray on closed store returned nil error")
	}
	if err = db.SaveMailSpray(testMailSprayState()); err == nil {
		t.Errorf("SaveMailSpray on closed store returned nil error")
	}
}

func TestMailSprayApplyDeltaTouchesOnlyItsKeys(t *testing.T) {
	db := openTestDB(t)

	base := testMailSprayState()
	if err := db.SaveMailSpray(base); err != nil {
		t.Fatalf("SaveMailSpray: %v", err)
	}
	seen := time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)
	delta := MailSprayDelta{
		Put: MailSprayState{
			IPs:      map[string]MailSprayIP{"192.0.2.1": {LastSeen: seen}},
			Networks: map[string]map[string]time.Time{"new@example.com": {"192.0.0.0/16": seen}},
			Blocked:  map[string]time.Time{"192.0.2.1": seen},
		},
		DeleteIPs:     []string{"2001:db8::7", ""},
		DeleteTrust:   []string{"203.0.113.9"},
		DeleteNames:   []string{"nobody@example.com"},
		DeleteBlocked: []string{"2001:db8::7", ""},
	}
	if delta.Empty() || !(MailSprayDelta{}).Empty() ||
		(MailSprayDelta{DeleteBlocked: []string{"192.0.2.1"}}).Empty() ||
		(MailSprayDelta{Put: MailSprayState{Blocked: map[string]time.Time{"192.0.2.1": seen}}}).Empty() {
		t.Fatalf("Empty() wrong")
	}
	if err := db.ApplyMailSprayDelta(delta); err != nil {
		t.Fatalf("ApplyMailSprayDelta: %v", err)
	}

	want := base
	want.IPs = map[string]MailSprayIP{"198.51.100.7": base.IPs["198.51.100.7"], "192.0.2.1": {LastSeen: seen}}
	want.Trust = map[string]map[string]GoodSourcePair{"198.51.100.7": base.Trust["198.51.100.7"]}
	want.Networks = map[string]map[string]time.Time{"new@example.com": {"192.0.0.0/16": seen}}
	want.Blocked = map[string]time.Time{"198.51.100.7": base.Blocked["198.51.100.7"], "192.0.2.1": seen}
	got, err := loadTestMailSpray(db)
	if err != nil {
		t.Fatalf("LoadMailSpray: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("after delta:\n got %+v\nwant %+v", got, want)
	}
}

func TestMailSprayApplyDeltaClosedReturnsError(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err = db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err = db.ApplyMailSprayDelta(MailSprayDelta{DeleteIPs: []string{"192.0.2.1"}}); err == nil {
		t.Fatalf("ApplyMailSprayDelta on closed store returned nil error")
	}
}

func TestMailSprayLoadRejectsOversizedEntry(t *testing.T) {
	db := openTestDB(t)
	good := testMailSprayState()
	if err := db.SaveMailSpray(good); err != nil {
		t.Fatal(err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(mailSprayBucket)).Put([]byte("name:oversized@example.com"), []byte(`{"`+strings.Repeat("x", 1<<20)+`":"2026-10-30T08:15:00Z"}`))
	}); err != nil {
		t.Fatal(err)
	}
	got, err := loadTestMailSpray(db)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, good) {
		t.Fatal("oversized record was decoded into memory")
	}
}

func loadTestMailSpray(db *DB) (MailSprayState, error) {
	st := MailSprayState{
		IPs:      make(map[string]MailSprayIP),
		Trust:    make(map[string]map[string]GoodSourcePair),
		Networks: make(map[string]map[string]time.Time),
		Blocked:  make(map[string]time.Time),
	}
	err := db.LoadMailSpray(1<<20, func(part MailSprayState) {
		maps.Copy(st.IPs, part.IPs)
		maps.Copy(st.Trust, part.Trust)
		maps.Copy(st.Networks, part.Networks)
		maps.Copy(st.Blocked, part.Blocked)
	})
	return st, err
}

func TestMailSprayLoadVisitsTrustBeforeEvidence(t *testing.T) {
	db := openTestDB(t)
	if err := db.SaveMailSpray(testMailSprayState()); err != nil {
		t.Fatal(err)
	}
	var order []string
	if err := db.LoadMailSpray(1<<20, func(part MailSprayState) {
		if len(part.Trust)+len(part.IPs)+len(part.Networks)+len(part.Blocked) != 1 {
			t.Fatal("load buffered multiple entries")
		}
		switch {
		case len(part.Trust) == 1:
			order = append(order, "trust")
		case len(part.IPs) == 1:
			order = append(order, "evidence")
		case len(part.Networks) == 1:
			order = append(order, "corroboration")
		case len(part.Blocked) == 1:
			order = append(order, "marker")
		}
	}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"trust", "trust", "evidence", "evidence", "corroboration", "marker", "marker"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("visit order = %v, want %v", order, want)
	}
}
