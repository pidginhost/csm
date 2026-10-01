package attackdb

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// Builds before keying on the structured source counted C2, webshell,
// phishing, spam and cPanel-login events against addresses read from
// message text: destinations, process names, file paths. No producer of
// those types carries a source address, so every such stored count is
// text-derived. Loading drops them, so a poisoned score stops counting at
// upgrade instead of after the retention window.
func TestLoadDropsTextDerivedAttackCounts(t *testing.T) {
	now := time.Now()
	poisoned := map[AttackType]int{AttackC2: 300, AttackWebshell: 2, AttackPhishing: 1, AttackSPAM: 1, AttackCPanelLogin: 1}
	mixed := map[AttackType]int{AttackC2: 40, AttackBruteForce: 3}
	// Balanced: its stored score already equals the corrected one (3 events,
	// vol 6 + brute 15, no accounts), so only the dropped counts mark it for
	// persistence.
	balanced := map[AttackType]int{AttackC2: 5, AttackBruteForce: 3}
	check := func(t *testing.T, db *DB) {
		t.Helper()
		if rec := db.records["203.0.113.60"]; rec != nil {
			t.Fatalf("a record holding only text-derived counts survived: %+v", rec)
		}
		if _, deleted := db.deletedIPs["203.0.113.60"]; !deleted {
			t.Fatal("the dropped record is not removed from storage")
		}
		rec := db.records["203.0.113.61"]
		if rec == nil || rec.EventCount != 3 || rec.AttackCounts[AttackC2] != 0 || rec.AttackCounts[AttackBruteForce] != 3 {
			t.Fatalf("mixed record = %+v, want only its 3 brute-force events", rec)
		}
		if rec.ThreatScore != ComputeScore(rec) || rec.ThreatScore >= 70 {
			t.Fatalf("mixed record score %d not recomputed below the block threshold", rec.ThreatScore)
		}
		if _, dirty := db.dirtyIPs["203.0.113.61"]; !dirty {
			t.Fatal("the corrected record is not persisted")
		}
		if rec := db.records["203.0.113.62"]; rec == nil || rec.EventCount != 3 || rec.ThreatScore != 21 {
			t.Fatalf("balanced record = %+v", rec)
		}
		if _, dirty := db.dirtyIPs["203.0.113.62"]; !dirty {
			t.Fatal("dropped counts alone did not mark the record for persistence")
		}
	}

	t.Run("bbolt", func(t *testing.T) {
		dir, cleanup := setupBboltStore(t)
		defer cleanup()
		for ip, counts := range map[string]map[AttackType]int{"203.0.113.60": poisoned, "203.0.113.61": mixed, "203.0.113.62": balanced} {
			total, stored := 0, map[string]int{}
			for k, v := range counts {
				total += v
				stored[string(k)] = v
			}
			accounts, score := map[string]int{"alice": 1, "bob": 1}, 75
			if ip == "203.0.113.62" {
				accounts, score = map[string]int{}, 21
			}
			if err := store.Global().SaveIPRecord(store.IPRecord{IP: ip, FirstSeen: now, LastSeen: now, EventCount: total, AttackCounts: stored, Accounts: accounts, ThreatScore: score}); err != nil {
				t.Fatal(err)
			}
		}
		db := newTestDB(t)
		db.dbPath = dir
		db.load()
		check(t, db)
	})

	t.Run("records.json", func(t *testing.T) {
		src := newTestDB(t)
		for ip, counts := range map[string]map[AttackType]int{"203.0.113.60": poisoned, "203.0.113.61": mixed, "203.0.113.62": balanced} {
			total := 0
			for _, v := range counts {
				total += v
			}
			accounts, score := map[string]int{"alice": 1, "bob": 1}, 75
			if ip == "203.0.113.62" {
				accounts, score = map[string]int{}, 21
			}
			src.records[ip] = &IPRecord{IP: ip, FirstSeen: now, LastSeen: now, EventCount: total, AttackCounts: counts, Accounts: accounts, ThreatScore: score}
		}
		src.dirty = true
		src.saveRecords()
		db := newTestDB(t)
		db.dbPath = src.dbPath
		db.load()
		check(t, db)
	})
}
