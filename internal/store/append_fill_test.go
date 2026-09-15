package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	bolt "go.etcd.io/bbolt"
)

// Ordered appends should leave little unused space even while pruning at
// the count cap. Delayed timestamps need separate, unordered coverage.
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

func openFillTestDB(t *testing.T, pageSize int) *DB {
	t.Helper()
	dir := t.TempDir()
	bdb, err := bolt.Open(filepath.Join(dir, "csm.db"), 0600, &bolt.Options{PageSize: pageSize})
	if err != nil {
		t.Fatal(err)
	}
	if closeErr := bdb.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	db.bolt.NoSync = true
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// Compare the production writers to bbolt's default split policy using the
// same values and transaction boundaries. Random arrivals model delayed log
// parsing; reverse arrivals model draining a newest-first history buffer.
func TestTimeKeyUnorderedFill(t *testing.T) {
	for _, pageSize := range []int{4096, 16384} {
		for _, bucket := range []string{historyBucketName, attackEventsBucketName} {
			orders := []string{"random", "reverse", "backfill"}
			if bucket == historyBucketName {
				orders = append(orders, "mixed", "mixed_large", "mixed_half")
			}
			for _, order := range orders {
				t.Run(fmt.Sprintf("%d/%s/%s", pageSize, bucket, order), func(t *testing.T) {
					testTimeKeyUnorderedFill(t, pageSize, bucket, order)
				})
			}
		}
	}
}

func testTimeKeyUnorderedFill(t *testing.T, pageSize int, bucket, order string) {
	db := openFillTestDB(t, pageSize)
	const count = 6000
	rng := rand.New(rand.NewSource(1))
	indexes := rng.Perm(count)
	switch order {
	case "reverse":
		for i := range indexes {
			indexes[i] = count - i - 1
		}
	case "backfill":
		// First pack a dense chronological history, then insert delayed
		// events throughout its existing pages.
		for i, index := range rng.Perm(count / 2) {
			indexes[i] = i * 2
			indexes[count/2+i] = index*2 + 1
		}
	case "mixed":
		// The final finding in each batch advances the tail. That must
		// not undo the balanced split needed by the older findings.
		for i := 19; i < count; i += 20 {
			indexes[i] = count + i
		}
	case "mixed_large", "mixed_half":
		// Delayed findings can dominate the bytes without being most of
		// the keys. Also cover an even split of equally sized findings:
		// neither workload should leave sparse pages across the backfill.
		late := 8
		if order == "mixed_half" {
			late = 10
		}
		for i := range indexes {
			if i%20 >= late {
				indexes[i] = count + i
			}
		}
	}
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	batchSize := 1
	if bucket == historyBucketName {
		batchSize = 20
	}
	for start := 0; start < count; start += batchSize {
		findings := make([]alert.Finding, batchSize)
		keys := make([][]byte, batchSize)
		values := make([][]byte, batchSize)
		var event AttackEvent
		for i := 0; i < batchSize; i++ {
			ts := base.Add(time.Duration(indexes[start+i]) * time.Second)
			keys[i] = []byte(TimeKey(ts, i))
			var err error
			if bucket == historyBucketName {
				detailsSize := 180
				if order == "mixed_large" {
					detailsSize = 0
					if i < 8 {
						detailsSize = 900
					}
				}
				findings[i] = alert.Finding{Timestamp: ts, Check: "log_auth", Severity: alert.Warning, Details: strings.Repeat("d", detailsSize)}
				values[i], err = json.Marshal(alert.SanitizeFinding(findings[i]))
			} else {
				event = AttackEvent{Timestamp: ts, IP: "192.0.2.1", AttackType: "brute_force", Message: strings.Repeat("d", 180)}
				values[i], err = json.Marshal(event)
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		var err error
		if bucket == historyBucketName {
			err = db.AppendHistory(findings)
		} else {
			err = db.RecordAttackEvent(event, 0)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := db.bolt.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte("default-fill"))
			if err != nil {
				return err
			}
			if order == "backfill" && start < count/2 {
				// Compare delayed inserts from the same dense layout. A
				// half-empty seed has spare space that a packed seed traded
				// away, so it can absorb more backfill before any split.
				b.FillPercent = 0.9
			}
			for i := range keys {
				if err := b.Put(keys[i], values[i]); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	use, pages := leafUse(t, db, bucket)
	defaultUse, defaultPages := leafUse(t, db, "default-fill")
	t.Logf("leaf use %.1f%% vs default %.1f%%; pages %d vs %d", use*100, defaultUse*100, pages, defaultPages)
	// Allow small boundary differences, but no material space
	// regression relative to the previous default policy.
	if float64(pages) > 1.1*float64(defaultPages) {
		t.Errorf("unordered inserts need %d leaf pages, default needs %d", pages, defaultPages)
	}
	if got := db.getCounter(bucket + ":count"); got != count {
		t.Errorf("counter = %d, want %d", got, count)
	}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		actual := tx.Bucket([]byte(bucket))
		if actual.Stats().KeyN != count {
			t.Errorf("record count = %d, want %d", actual.Stats().KeyN, count)
		}
		return tx.Bucket([]byte("default-fill")).ForEach(func(k, v []byte) error {
			if !bytes.Equal(actual.Get(k), v) {
				return fmt.Errorf("value changed for %q", k)
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTimeKeyMigrationFillsLeafPages(t *testing.T) {
	for _, pageSize := range []int{4096, 16384} {
		t.Run(fmt.Sprint(pageSize), func(t *testing.T) {
			db := openFillTestDB(t, pageSize)
			const count = 3000
			base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.FixedZone("UTC+3", 3*3600))
			if err := db.bolt.Update(func(tx *bolt.Tx) error {
				for i := 0; i < count; i++ {
					ts := base.Add(time.Duration(i) * time.Second)
					key := []byte(legacyTimeKey(ts, 0))
					finding := alert.Finding{Timestamp: ts, Check: "log_auth", Details: strings.Repeat("d", 180)}
					fv, err := json.Marshal(finding)
					if err != nil {
						return err
					}
					event := AttackEvent{Timestamp: ts, IP: "192.0.2.1", Message: strings.Repeat("d", 180)}
					ev, err := json.Marshal(event)
					if err != nil {
						return err
					}
					if err := tx.Bucket([]byte(historyBucketName)).Put(key, fv); err != nil {
						return err
					}
					if err := tx.Bucket([]byte(attackEventsBucketName)).Put(key, ev); err != nil {
						return err
					}
				}
				return tx.Bucket([]byte("meta")).Delete([]byte(timeKeyUTCMarker))
			}); err != nil {
				t.Fatal(err)
			}
			if err := db.migrateTimeKeysToUTC(); err != nil {
				t.Fatal(err)
			}
			for _, bucket := range []string{historyBucketName, attackEventsBucketName} {
				use, pages := leafUse(t, db, bucket)
				if pages < 10 || use < minAppendLeafUse {
					t.Errorf("%s after migration: %d leaf pages, %.1f%% used, want at least %.0f%%", bucket, pages, use*100, minAppendLeafUse*100)
				}
				if err := db.bolt.View(func(tx *bolt.Tx) error {
					b := tx.Bucket([]byte(bucket))
					if got := b.Stats().KeyN; got != count {
						return fmt.Errorf("%s after migration: %d keys, want %d", bucket, got, count)
					}
					for i := 0; i < count; i++ {
						key := []byte(TimeKey(base.Add(time.Duration(i)*time.Second), 0))
						if b.Get(key) == nil {
							return fmt.Errorf("%s missing migrated key %q", bucket, key)
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestAppendHistoryFillsLeafPages(t *testing.T) {
	for _, pageSize := range []int{4096, 16384} {
		for _, shuffled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/shuffled=%t", pageSize, shuffled), func(t *testing.T) {
				testAppendHistoryFillsLeafPages(t, pageSize, shuffled)
			})
		}
	}
}

func testAppendHistoryFillsLeafPages(t *testing.T, pageSize int, shuffled bool) {
	db := openFillTestDB(t, pageSize)
	// Run at the cap, as a busy host does: the oldest rows are pruned in the
	// same transactions that append new ones.
	prevMax := maxHistoryEntries
	maxHistoryEntries = 1000
	t.Cleanup(func() { maxHistoryEntries = prevMax })
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	details := strings.Repeat("d", 180)
	rng := rand.New(rand.NewSource(1))
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
		if shuffled {
			// All keys still follow the previously committed tail. Since
			// bbolt sorts them before splitting, their batch order is safe.
			rng.Shuffle(len(findings), func(i, j int) { findings[i], findings[j] = findings[j], findings[i] })
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
	rows, total := db.ReadHistory(maxHistoryEntries+1, 0)
	if total != maxHistoryEntries || len(rows) != maxHistoryEntries {
		t.Fatalf("history total/rows = %d/%d, want %d", total, len(rows), maxHistoryEntries)
	}
	for i, row := range rows {
		if want := base.Add(time.Duration(n-1-i) * time.Second); !row.Timestamp.Equal(want) {
			t.Fatalf("history row %d timestamp = %s, want %s", i, row.Timestamp, want)
		}
	}
}

// Busy hosts append batches in which a few findings carry a timestamp from
// before the last stored row (log lines parsed late). One such finding must
// not cost the whole batch the dense split.
func TestAppendHistoryDelayedFindingKeepsPagesDense(t *testing.T) {
	for _, pageSize := range []int{4096, 16384} {
		t.Run(fmt.Sprint(pageSize), func(t *testing.T) {
			db := openFillTestDB(t, pageSize)
			prevMax := maxHistoryEntries
			maxHistoryEntries = 1000
			t.Cleanup(func() { maxHistoryEntries = prevMax })
			base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
			details := strings.Repeat("d", 180)
			n := 0
			for batch := 0; batch < 150; batch++ {
				findings := make([]alert.Finding, 0, 20)
				for i := 0; i < 20; i++ {
					ts := base.Add(time.Duration(n) * time.Second)
					if i == 0 && batch > 0 {
						ts = ts.Add(-45 * time.Second)
					}
					findings = append(findings, alert.Finding{
						Severity:  alert.Warning,
						Check:     "email_auth_failure_realtime",
						Message:   fmt.Sprintf("authentication failure %d", n),
						Details:   details,
						Timestamp: ts,
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
			if _, total := db.ReadHistory(1, 0); total != maxHistoryEntries {
				t.Errorf("history total = %d, want %d", total, maxHistoryEntries)
			}
		})
	}
}

func TestRecordAttackEventFillsLeafPages(t *testing.T) {
	for _, pageSize := range []int{4096, 16384} {
		t.Run(fmt.Sprint(pageSize), func(t *testing.T) {
			testRecordAttackEventFillsLeafPages(t, pageSize)
		})
	}
}

func testRecordAttackEventFillsLeafPages(t *testing.T, pageSize int) {
	db := openFillTestDB(t, pageSize)
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
	rows := db.ReadAllAttackEvents()
	if len(rows) != maxAttackEvents || db.getCounter("attacks:events:count") != maxAttackEvents {
		t.Fatalf("attack rows/count = %d/%d, want %d", len(rows), db.getCounter("attacks:events:count"), maxAttackEvents)
	}
	for i, row := range rows {
		if want := base.Add(time.Duration(1500+i) * time.Second); !row.Timestamp.Equal(want) {
			t.Fatalf("attack row %d timestamp = %s, want %s", i, row.Timestamp, want)
		}
	}
	for i := 0; i < 250; i++ {
		ip := fmt.Sprintf("192.0.2.%d", i)
		if events := db.QueryAttackEvents(ip, 10); len(events) != 4 {
			t.Errorf("secondary count for %s = %d, want 4", ip, len(events))
		}
	}
}

// Head-only TTL sweeps keep the default fill policy: they can split merged
// nodes at the moving head, but do not rewrite the dense interior pages.
func TestTimeKeyRetentionPreservesDensePages(t *testing.T) {
	for _, pageSize := range []int{4096, 16384} {
		t.Run(fmt.Sprint(pageSize), func(t *testing.T) {
			db := openFillTestDB(t, pageSize)
			base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
			for i := 0; i < 3000; i++ {
				ts := base.Add(time.Duration(i) * time.Second)
				if err := db.AppendHistory([]alert.Finding{{Timestamp: ts, Details: strings.Repeat("d", 180)}}); err != nil {
					t.Fatal(err)
				}
				if err := db.RecordAttackEvent(AttackEvent{Timestamp: ts, IP: "192.0.2.1", Message: strings.Repeat("d", 180)}, 0); err != nil {
					t.Fatal(err)
				}
			}
			for i := 1; i <= 100; i++ {
				cutoff := base.Add(time.Duration(i*17) * time.Second)
				for _, sweep := range []func(time.Time) (int, error){db.SweepHistoryOlderThan, db.SweepAttackEventsOlderThan} {
					if deleted, err := sweep(cutoff); err != nil || deleted != 17 {
						t.Fatalf("sweep: deleted %d, err %v, want 17", deleted, err)
					}
				}
			}
			for _, bucket := range []string{historyBucketName, attackEventsBucketName} {
				use, _ := leafUse(t, db, bucket)
				// A partial head and tail page need a little extra slack.
				if use < minAppendLeafUse-0.02 {
					t.Errorf("%s after retention: %.1f%% used", bucket, use*100)
				}
			}
			if rows, total := db.ReadHistory(3000, 0); len(rows) != 1300 || total != 1300 {
				t.Errorf("history rows/total = %d/%d, want 1300", len(rows), total)
			}
			if rows := db.QueryAttackEvents("192.0.2.1", 3000); len(rows) != 1300 {
				t.Errorf("secondary rows = %d, want 1300", len(rows))
			}
			if rows := db.ReadAllAttackEvents(); len(rows) != 1300 || db.getCounter("attacks:events:count") != 1300 {
				t.Errorf("primary rows/count = %d/%d, want 1300", len(rows), db.getCounter("attacks:events:count"))
			}
		})
	}
}
