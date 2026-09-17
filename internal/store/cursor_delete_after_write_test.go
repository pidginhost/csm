package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	bolt "go.etcd.io/bbolt"
)

// A bbolt cursor that deletes and then steps with Next skips keys once the
// same transaction has written to the bucket. These prunes run right after a
// write, so every stale key must still go.

func TestStatsDailyRetentionPrunesEveryStaleDayAfterWrite(t *testing.T) {
	origRet := dailyRetentionDays
	dailyRetentionDays = 60
	t.Cleanup(func() { dailyRetentionDays = origRet })

	db := openTestDB(t)
	now := time.Now()
	// A host that was down for months has many stale days waiting.
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketStatsDaily))
		val, _ := json.Marshal(SeverityBucket{Warning: 1, Total: 1})
		for day := 100; day < 140; day++ {
			key := now.AddDate(0, 0, -day).Format("2006-01-02")
			if err := b.Put([]byte(key), val); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	writeFindings(t, db, []alert.Finding{{Timestamp: now, Severity: alert.Warning, Check: "recent"}})

	cutoff := now.AddDate(0, 0, -(dailyRetentionDays - 1)).Format("2006-01-02")
	var stale []string
	for _, key := range dailyKeys(t, db) {
		if key < cutoff {
			stale = append(stale, key)
		}
	}
	if len(stale) != 0 {
		t.Fatalf("retention left %d stale day(s) behind: %v", len(stale), stale)
	}
}

func TestDeleteFirewallActionRemovesEveryAuditVersionAfterRewrite(t *testing.T) {
	db := openSnapshotDB(t)
	const id = "prune-after-rewrite"
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{firewallAuditBucket, firewallActionsBucket} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		if err := initializeFirewallActionHistory(tx); err != nil {
			return err
		}
		audit := tx.Bucket([]byte(firewallAuditBucket))
		for v := uint64(1); v <= 40; v++ {
			if err := audit.Put(firewallAuditKey(id, v), []byte("event")); err != nil {
				return err
			}
			// A neighbouring action shares the bucket and must survive.
			if err := audit.Put(firewallAuditKey(id+"-other", v), []byte("event")); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		// Acknowledgement rewrites the newest audit leaf in the transaction
		// that prunes the action.
		if err := tx.Bucket([]byte(firewallAuditBucket)).Put(firewallAuditKey(id, 40), []byte("acknowledged")); err != nil {
			return err
		}
		return deleteFirewallAction(tx, firewallActionHistoryEntry{key: []byte("history-key"), id: id})
	}); err != nil {
		t.Fatal(err)
	}

	var left []string
	others := 0
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(firewallAuditBucket)).ForEach(func(key, _ []byte) error {
			switch {
			case strings.HasPrefix(string(key), id+"\x00"):
				left = append(left, fmt.Sprintf("%q", key))
			case strings.HasPrefix(string(key), id+"-other\x00"):
				others++
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("deleted action left %d audit version(s): %v", len(left), left)
	}
	if others != 40 {
		t.Fatalf("neighbouring action kept %d of 40 audit versions", others)
	}
}
