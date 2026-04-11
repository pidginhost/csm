package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// openTestDB opens a fresh bbolt DB in a temp dir and wires a cleanup.
func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// --- ParseTimeKeyPrefix ------------------------------------------------

func TestParseTimeKeyPrefixStandardFormat(t *testing.T) {
	if got := ParseTimeKeyPrefix("2026-04-11"); got != "20260411" {
		t.Errorf("got %q, want 20260411", got)
	}
}

func TestParseTimeKeyPrefixNonStandardPassesThrough(t *testing.T) {
	if got := ParseTimeKeyPrefix("garbage"); got != "garbage" {
		t.Errorf("got %q, want pass-through", got)
	}
}

func TestParseTimeKeyPrefixWrongLength(t *testing.T) {
	if got := ParseTimeKeyPrefix("2026-4-1"); got != "2026-4-1" {
		t.Errorf("short input should pass through, got %q", got)
	}
}

// --- Close on nil-bolt -------------------------------------------------

func TestCloseOnNilDBIsNoOp(t *testing.T) {
	db := &DB{bolt: nil}
	if err := db.Close(); err != nil {
		t.Errorf("Close on nil bolt = %v, want nil", err)
	}
}

// --- Aggregate queries -------------------------------------------------

func writeFindings(t *testing.T, db *DB, findings []alert.Finding) {
	t.Helper()
	if err := db.AppendHistory(findings); err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}
}

func TestAggregateByHourEmpty(t *testing.T) {
	db := openTestDB(t)
	buckets := db.AggregateByHour()
	if len(buckets) != 24 {
		t.Errorf("AggregateByHour len = %d, want 24", len(buckets))
	}
	for i, b := range buckets {
		if b.Total != 0 {
			t.Errorf("bucket[%d].Total = %d, want 0", i, b.Total)
		}
	}
}

func TestAggregateByHourCountsBySeverity(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	writeFindings(t, db, []alert.Finding{
		{Timestamp: now.Add(-30 * time.Minute), Severity: alert.Critical, Check: "x", Message: "a"},
		{Timestamp: now.Add(-40 * time.Minute), Severity: alert.High, Check: "x", Message: "b"},
		{Timestamp: now.Add(-50 * time.Minute), Severity: alert.Warning, Check: "x", Message: "c"},
		{Timestamp: now.Add(-2 * time.Hour), Severity: alert.Critical, Check: "x", Message: "d"},
	})
	buckets := db.AggregateByHour()
	if len(buckets) != 24 {
		t.Fatalf("expected 24 buckets, got %d", len(buckets))
	}

	// Count how many total findings landed in the last 24 buckets. We
	// don't pin each finding to a specific bucket because hour-truncation
	// depends on the clock; just verify the totals reconcile.
	var crit, high, warn int
	for _, b := range buckets {
		crit += b.Critical
		high += b.High
		warn += b.Warning
	}
	if crit != 2 {
		t.Errorf("critical total = %d, want 2", crit)
	}
	if high != 1 {
		t.Errorf("high total = %d, want 1", high)
	}
	if warn != 1 {
		t.Errorf("warning total = %d, want 1", warn)
	}
}

func TestAggregateByHourSkipsOutOfRange(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	writeFindings(t, db, []alert.Finding{
		{Timestamp: now.Add(-48 * time.Hour), Severity: alert.Critical, Check: "old"}, // beyond 24h
		{Timestamp: now.Add(-30 * time.Minute), Severity: alert.High, Check: "recent"},
	})
	buckets := db.AggregateByHour()
	var total int
	for _, b := range buckets {
		total += b.Total
	}
	if total != 1 {
		t.Errorf("only the recent finding should count, got total %d", total)
	}
}

func TestReadHistorySinceReturnsNewestFirst(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	writeFindings(t, db, []alert.Finding{
		{Timestamp: now.Add(-3 * time.Hour), Severity: alert.Warning, Check: "a"},
		{Timestamp: now.Add(-2 * time.Hour), Severity: alert.High, Check: "b"},
		{Timestamp: now.Add(-1 * time.Hour), Severity: alert.Critical, Check: "c"},
	})

	results := db.ReadHistorySince(now.Add(-24 * time.Hour))
	if len(results) != 3 {
		t.Fatalf("got %d, want 3", len(results))
	}
	// Newest first.
	if !results[0].Timestamp.After(results[1].Timestamp) {
		t.Errorf("results[0] should be newer than results[1]")
	}
	if !results[1].Timestamp.After(results[2].Timestamp) {
		t.Errorf("results[1] should be newer than results[2]")
	}
}

func TestReadHistorySinceCutoffExcludesOlder(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	writeFindings(t, db, []alert.Finding{
		{Timestamp: now.Add(-10 * time.Hour), Severity: alert.Warning, Check: "a"},
		{Timestamp: now.Add(-2 * time.Hour), Severity: alert.High, Check: "b"},
	})
	results := db.ReadHistorySince(now.Add(-5 * time.Hour))
	if len(results) != 1 {
		t.Fatalf("expected 1 within cutoff, got %d", len(results))
	}
	if results[0].Check != "b" {
		t.Errorf("expected check 'b', got %q", results[0].Check)
	}
}

func TestAggregateByDayEmpty(t *testing.T) {
	db := openTestDB(t)
	buckets := db.AggregateByDay()
	if len(buckets) != 30 {
		t.Errorf("AggregateByDay len = %d, want 30", len(buckets))
	}
	for _, b := range buckets {
		if b.Total != 0 {
			t.Errorf("%s Total = %d, want 0", b.Date, b.Total)
		}
	}
}

func TestAggregateByDayCountsWithinWindow(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	writeFindings(t, db, []alert.Finding{
		{Timestamp: now.Add(-2 * 24 * time.Hour), Severity: alert.Critical, Check: "a"},
		{Timestamp: now.Add(-1 * 24 * time.Hour), Severity: alert.High, Check: "b"},
		{Timestamp: now, Severity: alert.Warning, Check: "c"},
	})
	buckets := db.AggregateByDay()
	var total int
	for _, b := range buckets {
		total += b.Total
	}
	if total != 3 {
		t.Errorf("expected 3 findings in 30-day window, got %d", total)
	}
}

func TestAggregateByDayExcludesOlderThan30Days(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	writeFindings(t, db, []alert.Finding{
		{Timestamp: now.Add(-40 * 24 * time.Hour), Severity: alert.Critical, Check: "old"},
		{Timestamp: now, Severity: alert.Warning, Check: "recent"},
	})
	buckets := db.AggregateByDay()
	var total int
	for _, b := range buckets {
		total += b.Total
	}
	if total != 1 {
		t.Errorf("40-day-old finding should be excluded, got total %d", total)
	}
}

// --- ReadHistoryFiltered -----------------------------------------------

func TestReadHistoryFilteredNoFilter(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	writeFindings(t, db, []alert.Finding{
		{Timestamp: now.Add(-2 * time.Hour), Severity: alert.High, Check: "a", Message: "alpha"},
		{Timestamp: now.Add(-1 * time.Hour), Severity: alert.Warning, Check: "b", Message: "bravo"},
	})
	results, matched := db.ReadHistoryFiltered(10, 0, "", "", -1, "")
	if matched != 2 {
		t.Errorf("matched = %d, want 2", matched)
	}
	if len(results) != 2 {
		t.Errorf("len(results) = %d, want 2", len(results))
	}
}

func TestReadHistoryFilteredBySeverity(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	writeFindings(t, db, []alert.Finding{
		{Timestamp: now.Add(-2 * time.Hour), Severity: alert.High, Check: "a"},
		{Timestamp: now.Add(-1 * time.Hour), Severity: alert.Warning, Check: "b"},
		{Timestamp: now.Add(-30 * time.Minute), Severity: alert.High, Check: "c"},
	})
	results, matched := db.ReadHistoryFiltered(10, 0, "", "", int(alert.High), "")
	if matched != 2 {
		t.Errorf("matched = %d, want 2", matched)
	}
	for _, r := range results {
		if r.Severity != alert.High {
			t.Errorf("result with severity %v slipped through severity filter", r.Severity)
		}
	}
}

func TestReadHistoryFilteredBySearch(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	writeFindings(t, db, []alert.Finding{
		{Timestamp: now.Add(-2 * time.Hour), Severity: alert.High, Check: "rootkit_scan", Message: "clean"},
		{Timestamp: now.Add(-1 * time.Hour), Severity: alert.Warning, Check: "waf_rules", Message: "stale"},
		{Timestamp: now.Add(-30 * time.Minute), Severity: alert.High, Check: "ssh_brute", Message: "root logon attempt"},
	})
	results, matched := db.ReadHistoryFiltered(10, 0, "", "", -1, "root")
	// "root" matches rootkit_scan (check) AND root logon attempt (message)
	if matched != 2 {
		t.Errorf("matched = %d, want 2", matched)
	}
	if len(results) != 2 {
		t.Errorf("len(results) = %d, want 2", len(results))
	}
}

func TestReadHistoryFilteredByDateRange(t *testing.T) {
	db := openTestDB(t)
	old := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	mid := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC)
	writeFindings(t, db, []alert.Finding{
		{Timestamp: old, Severity: alert.High, Check: "a"},
		{Timestamp: mid, Severity: alert.High, Check: "b"},
		{Timestamp: recent, Severity: alert.High, Check: "c"},
	})
	results, matched := db.ReadHistoryFiltered(10, 0, "2026-04-04", "2026-04-08", -1, "")
	if matched != 1 {
		t.Errorf("matched = %d, want 1 (only mid)", matched)
	}
	if len(results) == 1 && results[0].Check != "b" {
		t.Errorf("expected check 'b', got %q", results[0].Check)
	}
}

func TestReadHistoryFilteredPagination(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	for i := 0; i < 10; i++ {
		writeFindings(t, db, []alert.Finding{
			{Timestamp: now.Add(time.Duration(-i) * time.Minute), Severity: alert.High, Check: "x"},
		})
	}
	results, matched := db.ReadHistoryFiltered(3, 2, "", "", -1, "")
	if matched != 10 {
		t.Errorf("matched = %d, want 10", matched)
	}
	if len(results) != 3 {
		t.Errorf("len(results) = %d, want 3 (paginated)", len(results))
	}
}

// --- AllReputation ----------------------------------------------------

func TestAllReputationEmpty(t *testing.T) {
	db := openTestDB(t)
	if got := db.AllReputation(); len(got) != 0 {
		t.Errorf("empty DB = %v, want empty map", got)
	}
}

func TestAllReputationReturnsAllEntries(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	entries := []struct {
		ip       string
		score    int
		category string
	}{
		{"1.1.1.1", 10, "clean"},
		{"2.2.2.2", 75, "brute"},
		{"3.3.3.3", 100, "malware"},
	}
	for _, e := range entries {
		if err := db.SetReputation(e.ip, ReputationEntry{
			Score: e.score, Category: e.category, CheckedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	got := db.AllReputation()
	if len(got) != 3 {
		t.Errorf("len = %d, want 3", len(got))
	}
	if got["2.2.2.2"].Score != 75 {
		t.Errorf("2.2.2.2 Score = %d", got["2.2.2.2"].Score)
	}
}

// --- LoadAllIPRecords / DeleteIPRecord / ReadAllAttackEvents ----------

func TestLoadAllIPRecords(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	rec1 := IPRecord{
		IP:           "1.2.3.4",
		FirstSeen:    now.Add(-time.Hour),
		LastSeen:     now,
		EventCount:   3,
		ThreatScore:  50,
		AttackCounts: map[string]int{"brute": 3},
	}
	rec2 := IPRecord{
		IP:           "5.6.7.8",
		FirstSeen:    now.Add(-2 * time.Hour),
		LastSeen:     now,
		EventCount:   5,
		ThreatScore:  80,
		AttackCounts: map[string]int{"scan": 5},
	}
	if err := db.SaveIPRecord(rec1); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveIPRecord(rec2); err != nil {
		t.Fatal(err)
	}

	all := db.LoadAllIPRecords()
	if len(all) != 2 {
		t.Fatalf("len = %d, want 2", len(all))
	}
	if all["1.2.3.4"].ThreatScore != 50 {
		t.Errorf("1.2.3.4 ThreatScore = %d", all["1.2.3.4"].ThreatScore)
	}
}

func TestDeleteIPRecord(t *testing.T) {
	db := openTestDB(t)
	rec := IPRecord{IP: "1.2.3.4", ThreatScore: 50, FirstSeen: time.Now(), LastSeen: time.Now()}
	if err := db.SaveIPRecord(rec); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteIPRecord("1.2.3.4"); err != nil {
		t.Fatalf("DeleteIPRecord: %v", err)
	}
	if _, found := db.LoadIPRecord("1.2.3.4"); found {
		t.Error("record should be gone after DeleteIPRecord")
	}
	// Delete of a non-existent record should not error.
	if err := db.DeleteIPRecord("9.9.9.9"); err != nil {
		t.Errorf("DeleteIPRecord(missing) = %v, want nil", err)
	}
}

func TestReadAllAttackEvents(t *testing.T) {
	db := openTestDB(t)
	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	events := []AttackEvent{
		{Timestamp: base, IP: "1.1.1.1", AttackType: "brute", CheckName: "ssh"},
		{Timestamp: base.Add(time.Minute), IP: "2.2.2.2", AttackType: "scan", CheckName: "port"},
		{Timestamp: base.Add(2 * time.Minute), IP: "1.1.1.1", AttackType: "recon", CheckName: "dir"},
	}
	for i, ev := range events {
		if err := db.RecordAttackEvent(ev, i); err != nil {
			t.Fatal(err)
		}
	}

	all := db.ReadAllAttackEvents()
	if len(all) != 3 {
		t.Errorf("len = %d, want 3", len(all))
	}
}

// --- Firewall remove operations ---------------------------------------

func TestRemoveAllow(t *testing.T) {
	db := openTestDB(t)
	if err := db.AllowIP("10.0.0.1", "trusted", time.Time{}); err != nil {
		t.Fatal(err)
	}
	// Confirm it's present by loading state.
	state := db.LoadFirewallState()
	found := false
	for _, a := range state.Allowed {
		if a.IP == "10.0.0.1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("precondition: 10.0.0.1 should be in allowed state")
	}

	if err := db.RemoveAllow("10.0.0.1"); err != nil {
		t.Fatalf("RemoveAllow: %v", err)
	}
	state = db.LoadFirewallState()
	for _, a := range state.Allowed {
		if a.IP == "10.0.0.1" {
			t.Error("10.0.0.1 should be gone after RemoveAllow")
		}
	}
}

func TestRemoveSubnet(t *testing.T) {
	db := openTestDB(t)
	if err := db.AddSubnet("203.0.113.0/24", "scanner range"); err != nil {
		t.Fatal(err)
	}
	state := db.LoadFirewallState()
	if len(state.Subnets) != 1 {
		t.Fatalf("precondition: 1 subnet expected, got %d", len(state.Subnets))
	}
	if err := db.RemoveSubnet("203.0.113.0/24"); err != nil {
		t.Fatalf("RemoveSubnet: %v", err)
	}
	state = db.LoadFirewallState()
	if len(state.Subnets) != 0 {
		t.Errorf("after RemoveSubnet len = %d, want 0", len(state.Subnets))
	}
}

func TestRemovePortAllow(t *testing.T) {
	db := openTestDB(t)
	if err := db.AddPortAllow("10.0.0.2", 2222, "tcp", "admin bastion"); err != nil {
		t.Fatal(err)
	}
	list := db.ListPortAllows()
	if len(list) != 1 {
		t.Fatalf("precondition: 1 port allow, got %d", len(list))
	}
	if err := db.RemovePortAllow("10.0.0.2", 2222, "tcp"); err != nil {
		t.Fatalf("RemovePortAllow: %v", err)
	}
	list = db.ListPortAllows()
	if len(list) != 0 {
		t.Errorf("after RemovePortAllow len = %d, want 0", len(list))
	}
}

// --- Whitelist removal -------------------------------------------------

func TestRemoveWhitelistEntry(t *testing.T) {
	db := openTestDB(t)
	if err := db.AddWhitelistEntry("10.1.2.3", time.Time{}, true); err != nil {
		t.Fatal(err)
	}
	if !db.IsWhitelisted("10.1.2.3") {
		t.Fatal("precondition: should be whitelisted")
	}
	if err := db.RemoveWhitelistEntry("10.1.2.3"); err != nil {
		t.Fatalf("RemoveWhitelistEntry: %v", err)
	}
	if db.IsWhitelisted("10.1.2.3") {
		t.Error("should no longer be whitelisted after RemoveWhitelistEntry")
	}
}

// --- ModSec no-escalate rules -----------------------------------------

func TestGetModSecNoEscalateRulesEmpty(t *testing.T) {
	db := openTestDB(t)
	// The default seed adds 900112 on first Open — clear it for a clean
	// empty-state test.
	if err := db.SetModSecNoEscalateRules(map[int]bool{}); err != nil {
		t.Fatal(err)
	}
	got := db.GetModSecNoEscalateRules()
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestGetModSecNoEscalateRulesAfterSet(t *testing.T) {
	db := openTestDB(t)
	want := map[int]bool{900001: true, 900002: true, 900003: true}
	if err := db.SetModSecNoEscalateRules(want); err != nil {
		t.Fatal(err)
	}
	got := db.GetModSecNoEscalateRules()
	for id := range want {
		if !got[id] {
			t.Errorf("rule %d missing from GetModSecNoEscalateRules", id)
		}
	}
}

func TestAddModSecNoEscalateRuleIdempotent(t *testing.T) {
	db := openTestDB(t)
	if err := db.SetModSecNoEscalateRules(map[int]bool{}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddModSecNoEscalateRule(900500); err != nil {
		t.Fatal(err)
	}
	// Add again — no duplicate.
	if err := db.AddModSecNoEscalateRule(900500); err != nil {
		t.Fatal(err)
	}
	got := db.GetModSecNoEscalateRules()
	if len(got) != 1 || !got[900500] {
		t.Errorf("got %v, want {900500:true}", got)
	}
}

func TestRemoveModSecNoEscalateRule(t *testing.T) {
	db := openTestDB(t)
	if err := db.SetModSecNoEscalateRules(map[int]bool{900100: true, 900200: true}); err != nil {
		t.Fatal(err)
	}
	if err := db.RemoveModSecNoEscalateRule(900100); err != nil {
		t.Fatal(err)
	}
	got := db.GetModSecNoEscalateRules()
	if got[900100] {
		t.Error("900100 should be removed")
	}
	if !got[900200] {
		t.Error("900200 should still be present")
	}
}

func TestRemoveModSecNoEscalateRuleMissingIsNoOp(t *testing.T) {
	db := openTestDB(t)
	if err := db.SetModSecNoEscalateRules(map[int]bool{900100: true}); err != nil {
		t.Fatal(err)
	}
	if err := db.RemoveModSecNoEscalateRule(999999); err != nil {
		t.Errorf("RemoveModSecNoEscalateRule on missing id = %v, want nil", err)
	}
	got := db.GetModSecNoEscalateRules()
	if !got[900100] {
		t.Error("900100 should still be present")
	}
}

// --- ModSec rule hits --------------------------------------------------

func TestIncrModSecRuleHitAndGet(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	db.IncrModSecRuleHit(900111, now)
	db.IncrModSecRuleHit(900111, now)
	db.IncrModSecRuleHit(900112, now.Add(-2*time.Hour))

	hits := db.GetModSecRuleHits()
	if hits[900111].Hits != 2 {
		t.Errorf("900111 Hits = %d, want 2", hits[900111].Hits)
	}
	if hits[900112].Hits != 1 {
		t.Errorf("900112 Hits = %d, want 1", hits[900112].Hits)
	}
}

func TestIncrModSecRuleHitPrunesOldBuckets(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	// Inject a hit from 48h ago — should be pruned on the next GetModSecRuleHits.
	db.IncrModSecRuleHit(900200, now.Add(-48*time.Hour))
	db.IncrModSecRuleHit(900200, now) // fresh hit

	hits := db.GetModSecRuleHits()
	if hits[900200].Hits != 1 {
		t.Errorf("only the fresh hit should be counted, got %d", hits[900200].Hits)
	}
}

// --- hourBucket / modsecHitKey helpers --------------------------------

func TestHourBucketFormat(t *testing.T) {
	tm := time.Date(2026, 4, 11, 9, 30, 0, 0, time.UTC)
	if got := hourBucket(tm); got != "2026041109" {
		t.Errorf("got %q, want 2026041109", got)
	}
}

func TestModsecHitKeyFormat(t *testing.T) {
	if got := modsecHitKey(900111); got != "modsec:hits:900111" {
		t.Errorf("got %q", got)
	}
}

// --- Open error: state path is a file, not a dir ---------------------

func TestOpenFailsWhenStatePathIsAFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state")
	if err := os.WriteFile(path, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("Open on non-dir state path should error")
	}
}
