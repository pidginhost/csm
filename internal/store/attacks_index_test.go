package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
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

func TestRecordAttackEventPreservesCollidingEvents(t *testing.T) {
	db := openTestDB(t)
	ts := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	events := []AttackEvent{
		{Timestamp: ts, IP: "192.0.2.1", Message: "first"},
		{Timestamp: ts, IP: "192.0.2.10", Message: "second"},
		{Timestamp: ts, IP: "192.0.2.1", Message: "third"},
		{Timestamp: ts, IP: "2001:db8::1", Message: "fourth"},
	}
	// Separate flushes restart the caller's counter. Probe past more than
	// one occupied key, including a collision with the same address.
	for _, ev := range events {
		if err := db.RecordAttackEvent(ev, 7); err != nil {
			t.Fatal(err)
		}
	}
	if got := db.ReadAllAttackEvents(); !reflect.DeepEqual(got, events) {
		t.Errorf("primary events = %+v, want %+v", got, events)
	}
	for ip, want := range map[string][]AttackEvent{
		"192.0.2.1":   {events[2], events[0]},
		"192.0.2.10":  {events[1]},
		"2001:db8::1": {events[3]},
	} {
		if got := db.QueryAttackEvents(ip, 10); !reflect.DeepEqual(got, want) {
			t.Errorf("QueryAttackEvents(%q) = %+v, want %+v", ip, got, want)
		}
	}
	assertAttackIndexConsistent(t, db, len(events))
}

func TestRecordAttackEventConcurrentCollisions(t *testing.T) {
	db := openTestDB(t)
	const writers = 24
	ts := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	var wg sync.WaitGroup
	for i := range writers {
		wg.Go(func() {
			ev := AttackEvent{Timestamp: ts, IP: "192.0.2.1", Message: fmt.Sprintf("event-%d", i)}
			if err := db.RecordAttackEvent(ev, 0); err != nil {
				t.Errorf("RecordAttackEvent: %v", err)
			}
		})
	}
	wg.Wait()
	got := db.QueryAttackEvents("192.0.2.1", writers+1)
	seen := make(map[string]bool)
	for _, ev := range got {
		if seen[ev.Message] {
			t.Errorf("duplicate event %q", ev.Message)
		}
		seen[ev.Message] = true
	}
	for i := range writers {
		if !seen[fmt.Sprintf("event-%d", i)] {
			t.Errorf("event-%d missing", i)
		}
	}
	assertAttackIndexConsistent(t, db, writers)
}

func TestRecordAttackEventCollisionPruning(t *testing.T) {
	oldCap := maxAttackEvents
	maxAttackEvents = 2
	t.Cleanup(func() { maxAttackEvents = oldCap })
	db := openTestDB(t)
	ts := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	events := []AttackEvent{
		{Timestamp: ts, IP: "192.0.2.1", Message: "oldest"},
		{Timestamp: ts, IP: "192.0.2.10", Message: "collision"},
		{Timestamp: ts.Add(time.Minute), IP: "2001:db8::1", Message: "newest"},
	}
	for _, ev := range events {
		if err := db.RecordAttackEvent(ev, 0); err != nil {
			t.Fatal(err)
		}
	}
	if got := db.QueryAttackEvents(events[0].IP, 10); len(got) != 0 {
		t.Errorf("pruned address still has events: %+v", got)
	}
	for _, ev := range events[1:] {
		if got := db.QueryAttackEvents(ev.IP, 10); len(got) != 1 || got[0] != ev {
			t.Errorf("surviving events for %s = %+v, want %+v", ev.IP, got, ev)
		}
	}
	assertAttackIndexConsistent(t, db, 2)
	deleted, err := db.SweepAttackEventsOlderThan(ts.Add(time.Second))
	if err != nil || deleted != 1 {
		t.Fatalf("SweepAttackEventsOlderThan = %d, %v; want 1, nil", deleted, err)
	}
	assertAttackIndexConsistent(t, db, 1)
}

func TestRecordAttackEventCollisionRollback(t *testing.T) {
	db := openTestDB(t)
	ev := AttackEvent{Timestamp: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC), IP: "192.0.2.1", Message: "original"}
	if err := db.RecordAttackEvent(ev, 0); err != nil {
		t.Fatal(err)
	}
	invalid := ev
	invalid.IP = strings.Repeat("x", bolt.MaxKeySize)
	if err := db.RecordAttackEvent(invalid, 0); !errors.Is(err, bolterrors.ErrKeyTooLarge) {
		t.Fatalf("RecordAttackEvent = %v, want ErrKeyTooLarge", err)
	}
	if got := db.ReadAllAttackEvents(); len(got) != 1 || got[0] != ev {
		t.Errorf("failed write changed primary: %+v", got)
	}
	assertAttackIndexConsistent(t, db, 1)
}

func assertAttackIndexConsistent(t *testing.T, db *DB, want int) {
	t.Helper()
	if count := db.getCounter("attacks:events:count"); count != want {
		t.Errorf("event counter = %d, want %d", count, want)
	}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		primary := tx.Bucket([]byte(attackEventsBucketName))
		secondary := tx.Bucket([]byte(attackEventsIPBucket))
		for _, b := range []*bolt.Bucket{primary, secondary} {
			if count := b.Stats().KeyN; count != want {
				t.Errorf("bucket key count = %d, want %d", count, want)
			}
		}
		return secondary.ForEach(func(k, v []byte) error {
			if len(v) != 0 {
				t.Errorf("index %q contains an event copy", k)
			}
			ip, key, ok := strings.Cut(string(k), "/")
			if !ok {
				return fmt.Errorf("invalid index key %q", k)
			}
			var ev AttackEvent
			if err := json.Unmarshal(primary.Get([]byte(key)), &ev); err != nil {
				return fmt.Errorf("resolve index %q: %w", k, err)
			}
			if ev.IP != ip {
				t.Errorf("index %q resolves to address %q", k, ev.IP)
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
}

func TestQueryAttackEventsPrefixAndLimit(t *testing.T) {
	db := openTestDB(t)
	ts := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	ips := []string{"192.0.2.1", "192.0.2.10", "2001:db8::1", "2001:db8::10"}
	for counter, ip := range ips {
		// Insert out of order so this also verifies sorting by timestamp.
		for _, minute := range []int{1, 3, 0, 2} {
			ev := AttackEvent{Timestamp: ts.Add(time.Duration(minute) * time.Minute), IP: ip}
			if err := db.RecordAttackEvent(ev, counter); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, ip := range ips {
		for _, limit := range []int{0, 1, 2, 4, 10} {
			got := db.QueryAttackEvents(ip, limit)
			want := min(limit, 4)
			if len(got) != want {
				t.Errorf("QueryAttackEvents(%q, %d) count = %d, want %d", ip, limit, len(got), want)
				continue
			}
			for i, ev := range got {
				if ev.IP != ip || !ev.Timestamp.Equal(ts.Add(time.Duration(3-i)*time.Minute)) {
					t.Errorf("QueryAttackEvents(%q, %d)[%d] = %+v", ip, limit, i, ev)
				}
			}
		}
	}
	for _, ip := range []string{"192.0.2.0", "192.0.2.11", "2001:db8::2"} {
		if got := db.QueryAttackEvents(ip, 10); len(got) != 0 {
			t.Errorf("absent address %q returned %+v", ip, got)
		}
	}
}

func TestQueryAttackEventsSkipsUnresolvableRows(t *testing.T) {
	db := openTestDB(t)
	ts := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	ip := "192.0.2.1"
	valid := AttackEvent{Timestamp: ts, IP: ip, Message: "valid"}
	if err := db.RecordAttackEvent(valid, 0); err != nil {
		t.Fatal(err)
	}
	legacy := AttackEvent{Timestamp: ts.Add(time.Minute), IP: ip, Message: "legacy orphan"}
	legacyRaw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	other := AttackEvent{Timestamp: ts.Add(2 * time.Minute), IP: "198.51.100.1", Message: "other address"}
	otherRaw, err := json.Marshal(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		primary := tx.Bucket([]byte(attackEventsBucketName))
		secondary := tx.Bucket([]byte(attackEventsIPBucket))
		for i, row := range []struct{ primary, index []byte }{
			{nil, legacyRaw},
			{otherRaw, nil},
			{nil, nil},
			{[]byte("{"), nil},
			{nil, []byte("{")},
			{nil, otherRaw},
		} {
			key := TimeKey(ts.Add(time.Duration(i+1)*time.Minute), 0)
			if row.primary != nil {
				if err := primary.Put([]byte(key), row.primary); err != nil {
					return err
				}
			}
			if err := secondary.Put([]byte(ip+"/"+key), row.index); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, want := db.QueryAttackEvents(ip, 2), []AttackEvent{legacy, valid}; !reflect.DeepEqual(got, want) {
		t.Errorf("QueryAttackEvents = %+v, want %+v", got, want)
	}
}

func TestAttackIndexMigrationPreservesBothValueShapes(t *testing.T) {
	db := openTestDB(t)
	ts := time.Date(2026, 9, 1, 10, 0, 0, 0, time.FixedZone("UTC+3", 3*3600))
	events := []AttackEvent{
		{Timestamp: ts, IP: "192.0.2.1", Message: "legacy copy"},
		{Timestamp: ts.UTC(), IP: "2001:db8::1", Message: "key only"},
	}
	indexValues := make([][]byte, len(events))
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket([]byte("meta")).Delete([]byte(timeKeyUTCMarker)); err != nil {
			return err
		}
		for i, ev := range events {
			raw, err := json.Marshal(ev)
			if err != nil {
				return err
			}
			if i == 0 {
				indexValues[i] = raw
			}
			key := legacyTimeKey(ev.Timestamp, 0)
			if err := tx.Bucket([]byte(attackEventsBucketName)).Put([]byte(key), raw); err != nil {
				return err
			}
			if err := tx.Bucket([]byte(attackEventsIPBucket)).Put([]byte(ev.IP+"/"+key), indexValues[i]); err != nil {
				return err
			}
		}
		return setCounter(tx, "attacks:events:count", len(events))
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(filepath.Dir(db.Path()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	for _, ev := range events {
		got := reopened.QueryAttackEvents(ev.IP, 10)
		if len(got) != 1 || got[0].Message != ev.Message || !got[0].Timestamp.Equal(ev.Timestamp) || got[0].IP != ev.IP {
			t.Errorf("migrated query for %s = %+v, want %+v", ev.IP, got, ev)
		}
	}
	if err := reopened.bolt.View(func(tx *bolt.Tx) error {
		// Both old keys canonicalize to the same instant and counter. The
		// migration relocates one primary row and must keep its index linked.
		for i, ev := range events {
			counter := 1 - i
			key := []byte(ev.IP + "/" + TimeKey(ev.Timestamp, counter))
			got := tx.Bucket([]byte(attackEventsIPBucket)).Get(key)
			if got == nil || !bytes.Equal(got, indexValues[i]) {
				t.Errorf("migrated index %q = %q, want %q", key, got, indexValues[i])
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
