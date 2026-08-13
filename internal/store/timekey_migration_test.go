package store

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	bolt "go.etcd.io/bbolt"
)

func TestOpenMigratesMixedZoneTimeKeysToUTC(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open initial DB: %v", err)
	}

	// These wall clocks straddle Europe's repeated DST hour: 03:30 +03 is
	// earlier than 03:15 +02 even though its legacy key sorts after it.
	earlier := time.Date(2026, 10, 25, 3, 30, 0, 0, time.FixedZone("UTC+3", 3*3600))
	later := time.Date(2026, 10, 25, 3, 15, 0, 0, time.FixedZone("UTC+2", 2*3600))
	sameInstantUTC := earlier.UTC()
	findings := []alert.Finding{
		{Severity: alert.Warning, Check: "earlier-local", Timestamp: earlier},
		{Severity: alert.High, Check: "later-local", Timestamp: later},
		{Severity: alert.Critical, Check: "earlier-utc", Timestamp: sameInstantUTC},
	}
	events := []AttackEvent{
		{Timestamp: earlier, IP: "192.0.2.1", AttackType: "earlier-local"},
		{Timestamp: later, IP: "192.0.2.1", AttackType: "later-local"},
		{Timestamp: sameInstantUTC, IP: "192.0.2.1", AttackType: "earlier-utc"},
	}

	err = db.bolt.Update(func(tx *bolt.Tx) error {
		if deleteErr := tx.Bucket([]byte("meta")).Delete([]byte(timeKeyUTCMarker)); deleteErr != nil {
			return deleteErr
		}
		history := tx.Bucket([]byte(historyBucketName))
		primary := tx.Bucket([]byte(attackEventsBucketName))
		secondary := tx.Bucket([]byte(attackEventsIPBucket))
		for i := range findings {
			findingValue, marshalErr := json.Marshal(findings[i])
			if marshalErr != nil {
				return marshalErr
			}
			eventValue, marshalErr := json.Marshal(events[i])
			if marshalErr != nil {
				return marshalErr
			}
			legacyKey := legacyTimeKey(findings[i].Timestamp, 0)
			if putErr := history.Put([]byte(legacyKey), findingValue); putErr != nil {
				return putErr
			}
			if putErr := primary.Put([]byte(legacyKey), eventValue); putErr != nil {
				return putErr
			}
			if putErr := secondary.Put([]byte(events[i].IP+"/"+legacyKey), eventValue); putErr != nil {
				return putErr
			}
		}
		if counterErr := setCounter(tx, "history:count", len(findings)); counterErr != nil {
			return counterErr
		}
		return setCounter(tx, "attacks:events:count", len(events))
	})
	if err != nil {
		_ = db.Close()
		t.Fatalf("seed legacy keys: %v", err)
	}
	if closeErr := db.Close(); closeErr != nil {
		t.Fatalf("close legacy DB: %v", closeErr)
	}

	db, err = Open(dir)
	if err != nil {
		t.Fatalf("Open migrated DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	history := db.ReadHistorySince(earlier.Add(-time.Minute))
	if len(history) != 3 {
		t.Fatalf("migrated history length = %d, want 3", len(history))
	}
	if history[0].Check != "later-local" {
		t.Errorf("newest history finding = %q, want later-local", history[0].Check)
	}
	if got := db.ReadHistorySince(earlier.Add(30 * time.Minute)); len(got) != 1 || got[0].Check != "later-local" {
		t.Errorf("post-DST cutoff returned %+v, want later-local only", got)
	}

	attacks := db.QueryAttackEvents("192.0.2.1", 10)
	if len(attacks) != 3 {
		t.Fatalf("migrated attacks length = %d, want 3", len(attacks))
	}
	if attacks[0].AttackType != "later-local" {
		t.Errorf("newest attack = %q, want later-local", attacks[0].AttackType)
	}

	err = db.bolt.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("meta"))
		if string(meta.Get([]byte(timeKeyUTCMarker))) != timeKeyMigrationDone {
			return fmt.Errorf("UTC migration marker missing")
		}
		for _, temp := range []string{timeKeyHistoryTemp, timeKeyAttacksTemp, timeKeyAttacksIPTemp} {
			if tx.Bucket([]byte(temp)) != nil {
				return fmt.Errorf("temporary bucket %q survived migration", temp)
			}
		}
		primary := tx.Bucket([]byte(attackEventsBucketName))
		for _, key := range []string{TimeKey(earlier, 0), TimeKey(earlier, 1), TimeKey(later, 0)} {
			if primary.Get([]byte(key)) == nil {
				return fmt.Errorf("canonical attack key %q missing", key)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func legacyTimeKey(timestamp time.Time, counter int) string {
	return fmt.Sprintf("%04d%02d%02d%02d%02d%02d%09d-%04d",
		timestamp.Year(), timestamp.Month(), timestamp.Day(),
		timestamp.Hour(), timestamp.Minute(), timestamp.Second(),
		timestamp.Nanosecond(), counter)
}
