package store

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	bolt "go.etcd.io/bbolt"
)

// Time-keyed buckets receive keys in arrival order. With bbolt's default
// split point every page is left half empty for good, which doubled the
// on-disk size of both buckets on a production host.
const minAppendLeafUse = 0.8

func leafUse(t *testing.T, db *DB, bucket string) (float64, int) {
	t.Helper()
	var st bolt.BucketStats
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		st = tx.Bucket([]byte(bucket)).Stats()
		return nil
	}); err != nil {
		t.Fatalf("stats %s: %v", bucket, err)
	}
	if st.LeafAlloc == 0 {
		t.Fatalf("%s has no leaf pages", bucket)
	}
	return float64(st.LeafInuse) / float64(st.LeafAlloc), st.LeafPageN
}

func TestAppendHistoryFillsLeafPages(t *testing.T) {
	db := openTestDB(t)
	// Run at the cap, as a busy host does: the oldest rows are pruned in the
	// same transactions that append new ones.
	prevMax := maxHistoryEntries
	maxHistoryEntries = 1000
	t.Cleanup(func() { maxHistoryEntries = prevMax })
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	details := strings.Repeat("d", 180)
	n := 0
	for batch := 0; batch < 150; batch++ {
		findings := make([]alert.Finding, 0, 20)
		for i := 0; i < 20; i++ {
			findings = append(findings, alert.Finding{
				Severity:  alert.Warning,
				Check:     "email_auth_failure_realtime",
				Message:   fmt.Sprintf("authentication failure %d", n),
				Details:   details,
				Timestamp: base.Add(time.Duration(n) * time.Second),
			})
			n++
		}
		if err := db.AppendHistory(findings); err != nil {
			t.Fatalf("AppendHistory: %v", err)
		}
	}

	use, pages := leafUse(t, db, "history")
	if pages < 10 {
		t.Fatalf("history spans %d leaf pages; test needs a multi-page bucket", pages)
	}
	if use < minAppendLeafUse {
		t.Errorf("history leaf pages %.0f%% used, want at least %.0f%%", use*100, minAppendLeafUse*100)
	}
}

func TestRecordAttackEventFillsLeafPages(t *testing.T) {
	db := openTestDB(t)
	// One transaction per event; skipping fsync keeps the test fast and does
	// not change how pages are split.
	db.bolt.NoSync = true
	prevMax := maxAttackEvents
	maxAttackEvents = 1000
	t.Cleanup(func() { maxAttackEvents = prevMax })
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 2500; i++ {
		ev := AttackEvent{
			Timestamp:  base.Add(time.Duration(i) * time.Second),
			IP:         fmt.Sprintf("192.0.2.%d", i%250),
			AttackType: "brute_force",
			CheckName:  "email_auth_failure_realtime",
			Severity:   1,
			Message:    "authentication failure for mailbox",
		}
		if err := db.RecordAttackEvent(ev, 0); err != nil {
			t.Fatalf("RecordAttackEvent: %v", err)
		}
	}

	use, pages := leafUse(t, db, "attacks:events")
	if pages < 10 {
		t.Fatalf("attacks:events spans %d leaf pages; test needs a multi-page bucket", pages)
	}
	if use < minAppendLeafUse {
		t.Errorf("attacks:events leaf pages %.0f%% used, want at least %.0f%%", use*100, minAppendLeafUse*100)
	}
}
