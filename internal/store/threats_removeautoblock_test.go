package store

import (
	"encoding/json"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// TestRemoveAutoBlockDeletesOnlyAutoBlockRows pins STO-18: an operator
// unblock must clear a temporary auto-block threat row (so ip_reputation
// stops re-flagging the IP after stale rows), but must never delete an
// operator permanent block or a legacy no-source row.
func TestRemoveAutoBlockDeletesOnlyAutoBlockRows(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Historical buggy auto-block row with no expiry: newer code must not
	// create this, but RemoveAutoBlock should still be able to clean it up.
	if err := seedRawAutoBlockThreatRow(db, "192.0.2.10", "web_attack", time.Time{}); err != nil {
		t.Fatalf("seed no-expiry auto-block row: %v", err)
	}
	// Auto-block row with a future expiry.
	if err := db.AddTempBlock("192.0.2.11", "web_attack", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("AddTempBlock(expiry): %v", err)
	}
	// Operator permanent block: must survive a firewall-only unblock.
	if err := db.AddPermanentBlock("192.0.2.12", "operator block"); err != nil {
		t.Fatalf("AddPermanentBlock: %v", err)
	}
	// Legacy no-source row: not an operator row we can prove, but not an
	// autoblock-sourced row either; RemoveAutoBlock must leave it alone.
	if err := seedRawThreatRow(db, "192.0.2.13", "some legacy reason"); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}

	if count := db.getCounter("threats:count"); count != 4 {
		t.Fatalf("threats:count after seeding = %d, want 4", count)
	}

	// Auto-block rows are removed.
	if removed, err := db.RemoveAutoBlock("192.0.2.10"); err != nil || !removed {
		t.Fatalf("RemoveAutoBlock(192.0.2.10) = (%v, %v), want (true, nil)", removed, err)
	}
	if _, found := db.GetPermanentBlock("192.0.2.10"); found {
		t.Fatal("no-expiry auto-block row survived RemoveAutoBlock")
	}
	if removed, err := db.RemoveAutoBlock("192.0.2.11"); err != nil || !removed {
		t.Fatalf("RemoveAutoBlock(192.0.2.11) = (%v, %v), want (true, nil)", removed, err)
	}

	// Operator row is preserved.
	if removed, err := db.RemoveAutoBlock("192.0.2.12"); err != nil || removed {
		t.Fatalf("RemoveAutoBlock(operator) = (%v, %v), want (false, nil)", removed, err)
	}
	entry, found := db.GetPermanentBlock("192.0.2.12")
	if !found || entry.Source != ThreatSourceOperator {
		t.Fatalf("operator row not intact: found=%v entry=%+v", found, entry)
	}

	// Legacy no-source row is preserved.
	if removed, err := db.RemoveAutoBlock("192.0.2.13"); err != nil || removed {
		t.Fatalf("RemoveAutoBlock(legacy) = (%v, %v), want (false, nil)", removed, err)
	}
	if _, found := db.GetPermanentBlock("192.0.2.13"); !found {
		t.Fatal("legacy no-source row deleted by RemoveAutoBlock")
	}

	// Absent IP is a no-op.
	if removed, err := db.RemoveAutoBlock("198.51.100.9"); err != nil || removed {
		t.Fatalf("RemoveAutoBlock(absent) = (%v, %v), want (false, nil)", removed, err)
	}

	// Counter dropped by exactly the two auto-block rows removed.
	if count := db.getCounter("threats:count"); count != 2 {
		t.Fatalf("threats:count after removals = %d, want 2", count)
	}
}

func TestAddTempBlockRejectsNoExpiryAutoBlockRows(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := db.AddTempBlock("192.0.2.20", "web_attack", time.Time{}); err != nil {
		t.Fatalf("AddTempBlock(no-expiry): %v", err)
	}
	if _, found := db.GetPermanentBlock("192.0.2.20"); found {
		t.Fatal("AddTempBlock created a never-expiring auto-block row")
	}
	if count := db.getCounter("threats:count"); count != 0 {
		t.Fatalf("threats:count = %d, want 0", count)
	}
}

func seedRawAutoBlockThreatRow(db *DB, ip, reason string, expiresAt time.Time) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("threats"))
		val, err := json.Marshal(PermanentBlockEntry{
			IP:        ip,
			Reason:    reason,
			BlockedAt: time.Now(),
			Source:    ThreatSourceAutoBlock,
			ExpiresAt: expiresAt,
		})
		if err != nil {
			return err
		}
		if err := b.Put([]byte(ip), val); err != nil {
			return err
		}
		return incrCounter(tx, "threats:count", 1)
	})
}

// seedRawThreatRow writes a threat row with no Source tag, mimicking a
// pre-source-tagging migration row.
func seedRawThreatRow(db *DB, ip, reason string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("threats"))
		val, err := json.Marshal(map[string]interface{}{
			"ip":         ip,
			"reason":     reason,
			"blocked_at": time.Now(),
		})
		if err != nil {
			return err
		}
		if err := b.Put([]byte(ip), val); err != nil {
			return err
		}
		return incrCounter(tx, "threats:count", 1)
	})
}
