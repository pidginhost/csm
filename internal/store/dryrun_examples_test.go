package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

const (
	exampleSession = "0123456789abcdef0123456789abcdef"
	otherSession   = "fedcba9876543210fedcba9876543210"
)

var exampleT0 = time.Date(2026, 10, 15, 12, 0, 0, 123456789, time.UTC)

func exampleDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// example is a forecast pick of ip that passed modelled capacity at at.
func example(at time.Time, ip string, n int) DryRunBlock {
	return DryRunBlock{
		At: at, IP: ip, Check: "ssh_brute", Candidate: admission.CandidateID(fmt.Sprintf("cand_%032x", n)),
		Session: exampleSession, Kind: admission.KindBlockIP, ExpiresAt: at.Add(24*time.Hour + 1500*time.Millisecond),
	}
}

// exampleRows reads the bucket's keys and values in key order.
func exampleRows(t *testing.T, db *DB) (keys []string, values []map[string]any) {
	t.Helper()
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dryRunBlocksBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var m map[string]any
			if err := json.Unmarshal(v, &m); err != nil {
				return err
			}
			keys, values = append(keys, string(k)), append(values, m)
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	return keys, values
}

// seedExamples writes raw records, as an older build or the legacy writer
// left them.
func seedExamples(t *testing.T, db *DB, rows map[string]string) {
	t.Helper()
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(dryRunBlocksBucket))
		if err != nil {
			return err
		}
		for k, v := range rows {
			if err = b.Put([]byte(k), []byte(v)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Spec 3.6: a record keeps the legacy ip, reason and timeout_sec and adds
// candidate_id, session_id, kind and expires_at. Its key is a fixed-width
// UTC time with nanoseconds, the canonical address and the candidate, so
// two decisions for one target at one instant never overwrite each other,
// and the legacy count reads it.
func TestRecordDryRunBlocksWritesBothFamilies(t *testing.T) {
	db := exampleDB(t)
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.FixedZone("ahead", 3600))
	blocks := []DryRunBlock{example(at, "192.0.2.10", 1), example(at, "2001:db8::10", 2), example(at, "192.0.2.10", 3)}
	if err := db.RecordDryRunBlocks(blocks); err != nil {
		t.Fatal(err)
	}
	keys, values := exampleRows(t, db)
	want := []string{
		"2026-10-15T11:00:00.000000000Z:192.0.2.10:cand_00000000000000000000000000000001",
		"2026-10-15T11:00:00.000000000Z:192.0.2.10:cand_00000000000000000000000000000003",
		"2026-10-15T11:00:00.000000000Z:2001:db8::10:cand_00000000000000000000000000000002",
	}
	if strings.Join(keys, "\n") != strings.Join(want, "\n") {
		t.Fatalf("keys = %q, want %q", keys, want)
	}
	if got := values[2]; len(got) != 7 || got["ip"] != "2001:db8::10" || got["reason"] != "ssh_brute" || got["timeout_sec"] != 86401.0 ||
		got["candidate_id"] != "cand_00000000000000000000000000000002" || got["session_id"] != exampleSession ||
		got["kind"] != "block_ip" || got["expires_at"] != "2026-10-16T11:00:01.5Z" {
		t.Fatalf("value = %v", got)
	}
	if n := db.DryRunBlocksCount(); n != 3 {
		t.Fatalf("legacy count = %d", n)
	}
}

// The writer validates every required value and the encoded bounds before
// it writes anything: one bad record refuses the whole batch.
func TestRecordDryRunBlocksRefusesInvalidRecords(t *testing.T) {
	for name, mutate := range map[string]func(*DryRunBlock){
		"no time":             func(b *DryRunBlock) { b.At = time.Time{} },
		"year beyond keys":    func(b *DryRunBlock) { b.At, b.ExpiresAt = b.At.AddDate(9000, 0, 0), b.ExpiresAt.AddDate(9000, 0, 0) },
		"mapped address":      func(b *DryRunBlock) { b.IP = "::ffff:192.0.2.10" },
		"zoned address":       func(b *DryRunBlock) { b.IP = "2001:db8::1%eth0" },
		"uncanonical address": func(b *DryRunBlock) { b.IP = "2001:DB8::10" },
		"name":                func(b *DryRunBlock) { b.IP = "alice" },
		"free reason":         func(b *DryRunBlock) { b.Check = "brute force from 192.0.2.10" },
		"no reason":           func(b *DryRunBlock) { b.Check = "" },
		"candidate":           func(b *DryRunBlock) { b.Candidate = "cand_1" },
		"session":             func(b *DryRunBlock) { b.Session = "ABCDEF" },
		"upper-case session":  func(b *DryRunBlock) { b.Session = strings.ToUpper(exampleSession) },
		"kind":                func(b *DryRunBlock) { b.Kind = 0 },
		"expired":             func(b *DryRunBlock) { b.ExpiresAt = b.At },
		"unencodable expiry":  func(b *DryRunBlock) { b.ExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
		"oversized value":     func(b *DryRunBlock) { b.Check = strings.Repeat("a", maxDryRunValueBytes) },
	} {
		t.Run(name, func(t *testing.T) {
			db := exampleDB(t)
			bad := example(exampleT0, "192.0.2.11", 2)
			mutate(&bad)
			err := db.RecordDryRunBlocks([]DryRunBlock{example(exampleT0, "192.0.2.10", 1), bad})
			if err == nil {
				t.Fatal("accepted an invalid record")
			}
			if keys, _ := exampleRows(t, db); len(keys) != 0 {
				t.Fatalf("a refused batch wrote %q", keys)
			}
		})
	}
	db := exampleDB(t)
	batch := make([]DryRunBlock, maxDryRunBatch+1)
	for i := range batch {
		batch[i] = example(exampleT0, fmt.Sprintf("198.51.100.%d", i), i)
	}
	if err := db.RecordDryRunBlocks(batch); err == nil {
		t.Fatal("accepted a batch above its bound")
	}
}

// A missing or closed store, or a failed transaction, is an error, never
// a successful empty write.
func TestRecordDryRunBlocksReportsStoreFailures(t *testing.T) {
	var none *DB
	if err := none.RecordDryRunBlocks([]DryRunBlock{example(exampleT0, "192.0.2.10", 1)}); err == nil {
		t.Fatal("a nil store accepted examples")
	}
	if _, err := none.MaintainDryRunBlocks(DryRunMaintenance{}); err == nil {
		t.Fatal("a nil store maintained examples")
	}
	db := exampleDB(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordDryRunBlocks([]DryRunBlock{example(exampleT0, "192.0.2.10", 1)}); err == nil {
		t.Fatal("a closed store accepted examples")
	}
	if _, err := db.MaintainDryRunBlocks(DryRunMaintenance{Cutoff: exampleT0}); err == nil {
		t.Fatal("a closed store maintained examples")
	}
}

// A full bucket makes room for a batch in its own transaction by evicting
// the first keys in key order; the bucket never holds more than the cap.
func TestRecordDryRunBlocksEvictsAtTheCap(t *testing.T) {
	db := exampleDB(t)
	rows := map[string]string{}
	for i := range maxDryRunBlocks {
		rows[fmt.Sprintf("2026-10-14T00:00:00.%09dZ:192.0.2.1:cand_%032x", i, i)] = `{}`
	}
	seedExamples(t, db, rows)
	if err := db.RecordDryRunBlocks([]DryRunBlock{example(exampleT0, "192.0.2.10", 1), example(exampleT0, "192.0.2.11", 2)}); err != nil {
		t.Fatal(err)
	}
	keys, _ := exampleRows(t, db)
	if len(keys) != maxDryRunBlocks || keys[0] != fmt.Sprintf("2026-10-14T00:00:00.%09dZ:192.0.2.1:cand_%032x", 2, 2) {
		t.Fatalf("%d records, first %q", len(keys), keys[0])
	}
	if !strings.HasPrefix(keys[len(keys)-1], "2026-10-15T12:00:00.123456789Z:192.0.2.11:") {
		t.Fatalf("last key %q", keys[len(keys)-1])
	}
}

// An inherited bucket above the cap takes no new example until
// maintenance trims it: the writer reports the batch as discarded.
func TestRecordDryRunBlocksRefusesAboveTheCap(t *testing.T) {
	db := exampleDB(t)
	rows := map[string]string{}
	for i := range maxDryRunBlocks + 1 {
		rows[fmt.Sprintf("2026-10-14T00:00:00.%09dZ:192.0.2.1", i)] = `{}`
	}
	seedExamples(t, db, rows)
	if err := db.RecordDryRunBlocks([]DryRunBlock{example(exampleT0, "192.0.2.10", 1)}); !errors.Is(err, ErrDryRunBlocksFull) {
		t.Fatalf("write above the cap = %v", err)
	}
	if n := db.DryRunBlocksCount(); n != maxDryRunBlocks+1 {
		t.Fatalf("count = %d", n)
	}
}

// Maintenance visits or deletes at most 256 records a step and resumes
// after the last key it visited. It trims an oversized bucket from its
// first keys, removes records strictly older than the cutoff, keeps
// records whose key time does not parse, and reports the end of its pass.
func TestMaintainDryRunBlocksIsBoundedAndResumes(t *testing.T) {
	db := exampleDB(t)
	cutoff := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	rows := map[string]string{
		cutoff.Add(-time.Nanosecond).Format(dryRunKeyTime) + ":192.0.2.1:cand_" + strings.Repeat("0", 32): `{}`,
		cutoff.Format(dryRunKeyTime) + ":192.0.2.2:cand_" + strings.Repeat("0", 32):                       `{}`,
		cutoff.Add(-time.Hour).Format(time.RFC3339Nano) + ":2001:db8::1":                                  `{}`,
		"not-a-time:192.0.2.3": `{}`,
	}
	for i := range 600 {
		rows[fmt.Sprintf("2026-10-14T00:00:00.%09dZ:192.0.2.9:cand_%032x", i, i)] = `{}`
	}
	seedExamples(t, db, rows)
	var step DryRunMaintenance
	step.Cutoff = cutoff
	removed, steps := 0, 0
	for {
		steps++
		res, err := db.MaintainDryRunBlocks(step)
		if err != nil {
			t.Fatal(err)
		}
		if res.Visited > maxDryRunMaintenance || res.Removed > maxDryRunMaintenance {
			t.Fatalf("step %d visited %d and removed %d", steps, res.Visited, res.Removed)
		}
		removed += res.Removed
		if res.Done {
			break
		}
		step.Cursor = res.Next
	}
	if steps != 3 || removed != 2 {
		t.Fatalf("%d steps removed %d, want 3 steps removing the two old records", steps, removed)
	}
	keys, _ := exampleRows(t, db)
	if len(keys) != 602 || keys[0] != cutoff.Format(dryRunKeyTime)+":192.0.2.2:cand_"+strings.Repeat("0", 32) || keys[len(keys)-1] != "not-a-time:192.0.2.3" {
		t.Fatalf("%d left, first %q, last %q", len(keys), keys[0], keys[len(keys)-1])
	}
	// An oversized bucket loses its first keys, at most 256 a step.
	more := map[string]string{}
	for i := range maxDryRunBlocks - 602 + 300 {
		more[fmt.Sprintf("2026-10-13T00:00:00.%09dZ:192.0.2.8", i)] = `{}`
	}
	seedExamples(t, db, more)
	res, err := db.MaintainDryRunBlocks(DryRunMaintenance{Cutoff: cutoff})
	if err != nil || res.Removed != maxDryRunMaintenance || res.Visited != maxDryRunMaintenance {
		t.Fatalf("first trim = %+v, %v", res, err)
	}
	if n := db.DryRunBlocksCount(); n != maxDryRunBlocks+300-maxDryRunMaintenance {
		t.Fatalf("count after one trim = %d", n)
	}
	// The kept record at the cutoff sorts first and goes first.
	if keys, _ = exampleRows(t, db); keys[0] != fmt.Sprintf("2026-10-13T00:00:00.%09dZ:192.0.2.8", maxDryRunMaintenance-1) {
		t.Fatalf("first key after a trim = %q", keys[0])
	}
	res, err = db.MaintainDryRunBlocks(DryRunMaintenance{Cutoff: cutoff, Cursor: res.Next})
	if err != nil || res.Removed != 300-maxDryRunMaintenance {
		t.Fatalf("second trim = %+v, %v", res, err)
	}
	if n := db.DryRunBlocksCount(); n != maxDryRunBlocks {
		t.Fatalf("count after trimming = %d", n)
	}
}

// A purge removes every record but those of the session it keeps, legacy
// and unreadable ones included; without a session to keep it removes all.
func TestMaintainDryRunBlocksPurgesOtherSessions(t *testing.T) {
	db := exampleDB(t)
	kept := example(exampleT0, "192.0.2.10", 1)
	other := example(exampleT0, "192.0.2.11", 2)
	other.Session = otherSession
	if err := db.RecordDryRunBlocks([]DryRunBlock{kept, other}); err != nil {
		t.Fatal(err)
	}
	seedExamples(t, db, map[string]string{
		exampleT0.Format(time.RFC3339Nano) + ":192.0.2.12": `{"ip":"192.0.2.12","reason":"x","timeout_sec":1}`,
		exampleT0.Format(dryRunKeyTime) + ":192.0.2.13":    `not json`,
	})
	cutoff := exampleT0.Add(-7 * 24 * time.Hour)
	res, err := db.MaintainDryRunBlocks(DryRunMaintenance{Cutoff: cutoff, Purge: true, Keep: exampleSession})
	if err != nil || !res.Done || res.Removed != 3 {
		t.Fatalf("purge = %+v, %v", res, err)
	}
	if keys, values := exampleRows(t, db); len(keys) != 1 || values[0]["session_id"] != exampleSession {
		t.Fatalf("after purge %q", keys)
	}
	if res, err = db.MaintainDryRunBlocks(DryRunMaintenance{Cutoff: cutoff, Purge: true}); err != nil || res.Removed != 1 || db.DryRunBlocksCount() != 0 {
		t.Fatalf("purge of everything = %+v, %v", res, err)
	}
	// An empty or missing bucket is a finished pass.
	if res, err = exampleDB(t).MaintainDryRunBlocks(DryRunMaintenance{Cutoff: cutoff, Purge: true}); err != nil || !res.Done || res.Removed != 0 {
		t.Fatalf("missing bucket = %+v, %v", res, err)
	}
}

func TestDryRunPurgeWithoutSessionRemovesLegacyRecords(t *testing.T) {
	db := exampleDB(t)
	seedExamples(t, db, map[string]string{"legacy": `{}`, "unreadable": `not json`})
	res, err := db.MaintainDryRunBlocks(DryRunMaintenance{Purge: true})
	if err != nil || !res.Done || res.Removed != 2 || db.DryRunBlocksCount() != 0 {
		t.Fatalf("purge left legacy records: %+v, %v", res, err)
	}
}

func TestDryRunWritesPreserveActiveSessionAtCapacity(t *testing.T) {
	for _, allActive := range []bool{false, true} {
		t.Run(fmt.Sprintf("all_active=%v", allActive), func(t *testing.T) {
			db := exampleDB(t)
			active := example(exampleT0.Add(-time.Hour), "192.0.2.10", 1)
			key, value, err := active.encode()
			if err != nil {
				t.Fatal(err)
			}
			stored := string(value)
			if !allActive {
				stored = strings.ReplaceAll(stored, exampleSession, otherSession)
			}
			rows := map[string]string{string(key): stored}
			for i := range maxDryRunBlocks - 1 {
				v := `{}`
				if allActive {
					v = string(value)
				}
				rows[fmt.Sprintf("z%08d", i)] = v
			}
			seedExamples(t, db, rows)
			// Updating an existing key must not make an evicted key new again.
			err = db.RecordDryRunBlocks([]DryRunBlock{active, example(exampleT0, "192.0.2.11", 2)})
			if allActive && !errors.Is(err, ErrDryRunBlocksFull) || !allActive && err != nil {
				t.Fatalf("write = %v", err)
			}
			if n := db.DryRunBlocksCount(); n != maxDryRunBlocks {
				t.Fatalf("count = %d", n)
			}
			if err := db.bolt.View(func(tx *bolt.Tx) error {
				if string(tx.Bucket([]byte(dryRunBlocksBucket)).Get(key)) != string(value) {
					t.Error("active record was evicted")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDryRunMaintenanceProtectsActiveSessionAndResumes(t *testing.T) {
	db := exampleDB(t)
	rows := map[string]string{}
	for i := range maxDryRunBlocks + 2 {
		v := `{}`
		if i < maxDryRunMaintenance+1 {
			v = `{"session_id":"` + exampleSession + `"}`
		}
		rows[fmt.Sprintf("2026-10-01T00:00:00.%09dZ:192.0.2.1", i)] = v
	}
	seedExamples(t, db, rows)
	step := DryRunMaintenance{Purge: true, Keep: exampleSession, Cutoff: exampleT0}
	removed := 0
	for turns := 0; ; turns++ {
		if turns > 100 {
			t.Fatal("maintenance did not progress past protected records")
		}
		res, err := db.MaintainDryRunBlocks(step)
		if err != nil || res.Visited > maxDryRunMaintenance || res.Removed > maxDryRunMaintenance {
			t.Fatalf("step = %+v, %v", res, err)
		}
		if turns == 0 && (res.Removed != 0 || res.Done || len(res.Next) == 0) {
			t.Fatalf("protected prefix: %+v", res)
		}
		removed += res.Removed
		if res.Done {
			break
		}
		step.Cursor = res.Next
	}
	if removed != maxDryRunBlocks+2-(maxDryRunMaintenance+1) || db.DryRunBlocksCount() != maxDryRunMaintenance+1 {
		t.Fatalf("removed %d, retained %d", removed, db.DryRunBlocksCount())
	}
}

func TestDryRunMaintenanceFailureRollsBackCursorAndDeletes(t *testing.T) {
	db := exampleDB(t)
	seedExamples(t, db, map[string]string{"first": `{}`})
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		_, err := tx.Bucket([]byte(dryRunBlocksBucket)).CreateBucket([]byte("last"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	res, err := db.MaintainDryRunBlocks(DryRunMaintenance{Purge: true})
	if !errors.Is(err, bolterrors.ErrIncompatibleValue) || res.Next != nil || res.Done || res.Visited != 0 || res.Removed != 0 {
		t.Fatalf("failed transaction advanced maintenance: %+v, %v", res, err)
	}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dryRunBlocksBucket))
		if string(b.Get([]byte("first"))) != `{}` || b.Bucket([]byte("last")) == nil {
			t.Error("failed maintenance partially deleted records")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
