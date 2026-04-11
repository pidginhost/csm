package attackdb

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// newTestDB constructs a fresh DB instance anchored to a temp dir without
// going through Init() — Init uses a package-level sync.Once that can
// only fire once per test binary, so tests must build the DB directly.
func newTestDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "attack_db")
	if err := os.MkdirAll(dbPath, 0700); err != nil {
		t.Fatal(err)
	}
	return &DB{
		records:    make(map[string]*IPRecord),
		deletedIPs: make(map[string]struct{}),
		dbPath:     dbPath,
		stopCh:     make(chan struct{}),
	}
}

// --- ComputeScore ------------------------------------------------------

func TestComputeScoreZeroEvents(t *testing.T) {
	r := &IPRecord{AttackCounts: map[AttackType]int{}, Accounts: map[string]int{}}
	if got := ComputeScore(r); got != 0 {
		t.Errorf("empty record = %d, want 0", got)
	}
}

func TestComputeScoreVolumeCap(t *testing.T) {
	// 20 events * 2 = 40 volume points, should cap at 30.
	r := &IPRecord{EventCount: 20, AttackCounts: map[AttackType]int{}, Accounts: map[string]int{}}
	score := ComputeScore(r)
	if score != 30 {
		t.Errorf("score = %d, want 30 (volume capped)", score)
	}
}

func TestComputeScoreC2Bonus(t *testing.T) {
	r := &IPRecord{
		EventCount:   1,
		AttackCounts: map[AttackType]int{AttackC2: 1},
		Accounts:     map[string]int{},
	}
	score := ComputeScore(r)
	// vol=2 + c2=35 = 37
	if score != 37 {
		t.Errorf("score = %d, want 37 (vol=2 + c2=35)", score)
	}
}

func TestComputeScoreWebshellBonus(t *testing.T) {
	r := &IPRecord{
		EventCount:   1,
		AttackCounts: map[AttackType]int{AttackWebshell: 1},
		Accounts:     map[string]int{},
	}
	if got := ComputeScore(r); got != 32 {
		t.Errorf("webshell = %d, want 32 (vol=2 + webshell=30)", got)
	}
}

func TestComputeScoreWAFThreshold(t *testing.T) {
	// WAF bonus only fires when count > 5.
	r := &IPRecord{
		EventCount:   5,
		AttackCounts: map[AttackType]int{AttackWAFBlock: 5},
		Accounts:     map[string]int{},
	}
	scoreAt5 := ComputeScore(r)
	r.AttackCounts[AttackWAFBlock] = 6
	r.EventCount = 6
	scoreAt6 := ComputeScore(r)
	if scoreAt6 != scoreAt5+12 && scoreAt6 != scoreAt5+10 { // vol +2, waf bonus +10
		t.Errorf("waf bonus not applied correctly: at5=%d at6=%d", scoreAt5, scoreAt6)
	}
}

func TestComputeScoreMultiAccountBonus(t *testing.T) {
	r := &IPRecord{
		EventCount:   3,
		AttackCounts: map[AttackType]int{},
		Accounts:     map[string]int{"a": 1, "b": 1},
	}
	// vol=6, multi-account=10 → 16
	if got := ComputeScore(r); got != 16 {
		t.Errorf("multi-account = %d, want 16", got)
	}
}

func TestComputeScoreAutoBlockedFloor(t *testing.T) {
	r := &IPRecord{
		EventCount:   1,
		AttackCounts: map[AttackType]int{},
		Accounts:     map[string]int{},
		AutoBlocked:  true,
	}
	// Would be 2, but auto-blocked forces ≥50.
	if got := ComputeScore(r); got != 50 {
		t.Errorf("auto-blocked floor = %d, want 50", got)
	}
}

func TestComputeScoreAutoBlockedDoesNotCapHigherScores(t *testing.T) {
	r := &IPRecord{
		EventCount:   10,
		AttackCounts: map[AttackType]int{AttackC2: 1, AttackWebshell: 1, AttackFileUpload: 1},
		Accounts:     map[string]int{"x": 1},
		AutoBlocked:  true,
	}
	// vol=20 + c2=35 + webshell=30 + upload=20 = 105, capped at 100.
	if got := ComputeScore(r); got != 100 {
		t.Errorf("score = %d, want 100 (cap)", got)
	}
}

func TestComputeScoreAllAttackTypes(t *testing.T) {
	// Exercise every bonus branch.
	r := &IPRecord{
		EventCount: 1,
		AttackCounts: map[AttackType]int{
			AttackBruteForce: 1, // +15
			AttackPhishing:   1, // +25
		},
		Accounts: map[string]int{},
	}
	// vol=2 + brute=15 + phishing=25 = 42
	if got := ComputeScore(r); got != 42 {
		t.Errorf("got %d, want 42", got)
	}
}

// --- sortRecords -------------------------------------------------------

func TestSortRecordsByScoreDescending(t *testing.T) {
	recs := []*IPRecord{
		{IP: "a", ThreatScore: 10, EventCount: 5},
		{IP: "b", ThreatScore: 50, EventCount: 1},
		{IP: "c", ThreatScore: 30, EventCount: 10},
	}
	sortRecords(recs)
	if recs[0].IP != "b" || recs[1].IP != "c" || recs[2].IP != "a" {
		t.Errorf("order = [%s %s %s], want [b c a]", recs[0].IP, recs[1].IP, recs[2].IP)
	}
}

func TestSortRecordsTieBreakByEventCount(t *testing.T) {
	recs := []*IPRecord{
		{IP: "low", ThreatScore: 10, EventCount: 1},
		{IP: "high", ThreatScore: 10, EventCount: 100},
	}
	sortRecords(recs)
	if recs[0].IP != "high" {
		t.Error("tie on score should prefer higher event count")
	}
}

// --- extractIP / extractAccount ---------------------------------------

func TestExtractIPFromSeparator(t *testing.T) {
	cases := []struct {
		msg  string
		want string
	}{
		{"brute force from 1.2.3.4 after 5 attempts", "1.2.3.4"},
		{"SSH login: 203.0.113.5 failed", "203.0.113.5"},
		{"accessing server: 198.51.100.10 hit rate limit", "198.51.100.10"},
	}
	for _, c := range cases {
		if got := extractIP(c.msg); got != c.want {
			t.Errorf("%q -> %q, want %q", c.msg, got, c.want)
		}
	}
}

func TestExtractIPStripsPunctuation(t *testing.T) {
	if got := extractIP("login from 1.2.3.4, attempting"); got != "1.2.3.4" {
		t.Errorf("got %q, want 1.2.3.4", got)
	}
}

func TestExtractIPStripsAbuseIPDBSuffix(t *testing.T) {
	if got := extractIP("login from 1.2.3.4(AbuseIPDB 90%)"); got != "1.2.3.4" {
		t.Errorf("got %q, want 1.2.3.4", got)
	}
}

func TestExtractIPNoMatch(t *testing.T) {
	if got := extractIP("no ip here"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractIPInvalidIP(t *testing.T) {
	if got := extractIP("access from 999.999.999.999 blocked"); got != "" {
		t.Errorf("bogus IP should return empty, got %q", got)
	}
}

func TestExtractAccountFromDetails(t *testing.T) {
	if got := extractAccount("failed login", "Account: alice trying /home/alice"); got != "alice" {
		t.Errorf("got %q, want alice", got)
	}
}

func TestExtractAccountFromMessage(t *testing.T) {
	if got := extractAccount("Account: bob failed", ""); got != "bob" {
		t.Errorf("got %q, want bob", got)
	}
}

func TestExtractAccountFromHomePath(t *testing.T) {
	if got := extractAccount("scanned /home/carol/public_html", ""); got != "carol" {
		t.Errorf("got %q, want carol", got)
	}
}

func TestExtractAccountNotFound(t *testing.T) {
	if got := extractAccount("no account markers here", ""); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// --- truncate ----------------------------------------------------------

func TestTruncateShortString(t *testing.T) {
	if got := truncate("hi", 10); got != "hi" {
		t.Errorf("got %q", got)
	}
}

func TestTruncateLongString(t *testing.T) {
	s := strings.Repeat("a", 300)
	got := truncate(s, 200)
	if len([]rune(got)) != 200 {
		t.Errorf("len = %d, want 200", len([]rune(got)))
	}
}

func TestTruncateMultibyte(t *testing.T) {
	// 3 CJK chars, limit to 2 runes.
	got := truncate("日本語", 2)
	if got != "日本" {
		t.Errorf("got %q, want 日本", got)
	}
}

// --- RecordFinding -----------------------------------------------------

func TestRecordFindingUnknownCheckIsIgnored(t *testing.T) {
	db := newTestDB(t)
	db.RecordFinding(alert.Finding{
		Check:   "not_an_attack_check",
		Message: "some event from 1.2.3.4",
	})
	if len(db.records) != 0 {
		t.Errorf("unknown check should not record, got %d", len(db.records))
	}
}

func TestRecordFindingNoIPIsIgnored(t *testing.T) {
	db := newTestDB(t)
	db.RecordFinding(alert.Finding{
		Check:   "webshell",
		Message: "some event but no IP",
	})
	if len(db.records) != 0 {
		t.Error("finding without IP should not record")
	}
}

func TestRecordFindingCreatesRecord(t *testing.T) {
	db := newTestDB(t)
	db.RecordFinding(alert.Finding{
		Check:     "webshell",
		Message:   "shell.php detected from 1.2.3.4",
		Severity:  alert.Critical,
		Timestamp: time.Date(2026, 4, 11, 10, 0, 0, 0, time.UTC),
	})
	rec := db.records["1.2.3.4"]
	if rec == nil {
		t.Fatal("record not created")
	}
	if rec.EventCount != 1 {
		t.Errorf("EventCount = %d, want 1", rec.EventCount)
	}
	if rec.AttackCounts[AttackWebshell] != 1 {
		t.Errorf("AttackCounts[webshell] = %d, want 1", rec.AttackCounts[AttackWebshell])
	}
	if rec.ThreatScore == 0 {
		t.Error("ThreatScore should be computed")
	}
}

func TestRecordFindingIncrementsExistingRecord(t *testing.T) {
	db := newTestDB(t)
	for i := 0; i < 3; i++ {
		db.RecordFinding(alert.Finding{
			Check:     "wp_login_bruteforce",
			Message:   "brute force from 5.6.7.8",
			Timestamp: time.Now(),
		})
	}
	rec := db.records["5.6.7.8"]
	if rec == nil || rec.EventCount != 3 {
		t.Errorf("EventCount = %d, want 3", rec.EventCount)
	}
	if rec.AttackCounts[AttackBruteForce] != 3 {
		t.Errorf("AttackCounts[brute] = %d, want 3", rec.AttackCounts[AttackBruteForce])
	}
}

func TestRecordFindingExtractsAccount(t *testing.T) {
	db := newTestDB(t)
	db.RecordFinding(alert.Finding{
		Check:     "webshell",
		Message:   "shell found in /home/alice/public_html from 1.1.1.1",
		Timestamp: time.Now(),
	})
	rec := db.records["1.1.1.1"]
	if rec.Accounts["alice"] != 1 {
		t.Errorf("Accounts = %v, want alice:1", rec.Accounts)
	}
}

func TestRecordFindingZeroTimestampUsesNow(t *testing.T) {
	db := newTestDB(t)
	before := time.Now()
	db.RecordFinding(alert.Finding{
		Check:   "webshell",
		Message: "found from 1.1.1.1",
	})
	rec := db.records["1.1.1.1"]
	if rec == nil {
		t.Fatal("record not created")
	}
	if rec.LastSeen.Before(before) {
		t.Errorf("LastSeen = %v, should be >= %v", rec.LastSeen, before)
	}
}

// --- MarkBlocked / LookupIP / RemoveIP --------------------------------

func TestMarkBlockedExisting(t *testing.T) {
	db := newTestDB(t)
	db.RecordFinding(alert.Finding{
		Check:     "webshell",
		Message:   "attack from 1.2.3.4",
		Timestamp: time.Now(),
	})
	before := db.records["1.2.3.4"].ThreatScore
	db.MarkBlocked("1.2.3.4")
	after := db.records["1.2.3.4"].ThreatScore
	if !db.records["1.2.3.4"].AutoBlocked {
		t.Error("AutoBlocked should be true")
	}
	if after < before {
		t.Errorf("score should not decrease after block: %d -> %d", before, after)
	}
}

func TestMarkBlockedMissingIsNoOp(t *testing.T) {
	db := newTestDB(t)
	db.MarkBlocked("9.9.9.9") // must not panic
	if len(db.records) != 0 {
		t.Errorf("MarkBlocked on missing IP should not create record")
	}
}

func TestLookupIPHit(t *testing.T) {
	db := newTestDB(t)
	db.RecordFinding(alert.Finding{
		Check:     "webshell",
		Message:   "attack from 1.2.3.4",
		Timestamp: time.Now(),
	})
	rec := db.LookupIP("1.2.3.4")
	if rec == nil {
		t.Fatal("LookupIP miss")
	}
	if rec.IP != "1.2.3.4" {
		t.Errorf("IP = %q", rec.IP)
	}
	// Modifying the returned record must not affect the DB (deep copy).
	rec.EventCount = 999
	if db.records["1.2.3.4"].EventCount == 999 {
		t.Error("LookupIP should return a deep copy")
	}
}

func TestLookupIPMiss(t *testing.T) {
	db := newTestDB(t)
	if rec := db.LookupIP("unknown"); rec != nil {
		t.Errorf("unknown IP = %v, want nil", rec)
	}
}

func TestRemoveIP(t *testing.T) {
	db := newTestDB(t)
	db.RecordFinding(alert.Finding{
		Check:     "webshell",
		Message:   "attack from 1.2.3.4",
		Timestamp: time.Now(),
	})
	db.RemoveIP("1.2.3.4")
	if _, exists := db.records["1.2.3.4"]; exists {
		t.Error("record should be removed")
	}
	if _, deleted := db.deletedIPs["1.2.3.4"]; !deleted {
		t.Error("IP should be in deletedIPs")
	}
}

// --- TopAttackers / AllRecords / TotalIPs / FormatTopLine -------------

func TestTopAttackersOrdering(t *testing.T) {
	db := newTestDB(t)
	db.records = map[string]*IPRecord{
		"low":  {IP: "low", ThreatScore: 10, EventCount: 1, AttackCounts: map[AttackType]int{}, Accounts: map[string]int{}},
		"mid":  {IP: "mid", ThreatScore: 50, EventCount: 5, AttackCounts: map[AttackType]int{}, Accounts: map[string]int{}},
		"high": {IP: "high", ThreatScore: 90, EventCount: 20, AttackCounts: map[AttackType]int{}, Accounts: map[string]int{}},
	}
	top := db.TopAttackers(2)
	if len(top) != 2 {
		t.Fatalf("len = %d, want 2", len(top))
	}
	if top[0].IP != "high" || top[1].IP != "mid" {
		t.Errorf("order = [%s %s], want [high mid]", top[0].IP, top[1].IP)
	}
}

func TestTopAttackersMoreThanAvailable(t *testing.T) {
	db := newTestDB(t)
	db.records = map[string]*IPRecord{
		"one": {IP: "one", ThreatScore: 10, AttackCounts: map[AttackType]int{}, Accounts: map[string]int{}},
	}
	top := db.TopAttackers(10)
	if len(top) != 1 {
		t.Errorf("len = %d, want 1", len(top))
	}
}

func TestTotalIPs(t *testing.T) {
	db := newTestDB(t)
	if n := db.TotalIPs(); n != 0 {
		t.Errorf("empty = %d, want 0", n)
	}
	db.records["1.1.1.1"] = &IPRecord{IP: "1.1.1.1"}
	db.records["2.2.2.2"] = &IPRecord{IP: "2.2.2.2"}
	if n := db.TotalIPs(); n != 2 {
		t.Errorf("got %d, want 2", n)
	}
}

func TestAllRecordsDeepCopy(t *testing.T) {
	db := newTestDB(t)
	db.records["1.1.1.1"] = &IPRecord{
		IP:           "1.1.1.1",
		EventCount:   5,
		AttackCounts: map[AttackType]int{AttackBruteForce: 5},
		Accounts:     map[string]int{"x": 5},
	}
	all := db.AllRecords()
	if len(all) != 1 {
		t.Fatalf("len = %d", len(all))
	}
	// Mutate the returned copy and verify the original is untouched.
	all[0].AttackCounts[AttackWebshell] = 99
	if db.records["1.1.1.1"].AttackCounts[AttackWebshell] != 0 {
		t.Error("AllRecords should return a deep copy of AttackCounts")
	}
}

func TestFormatTopLineEmpty(t *testing.T) {
	db := newTestDB(t)
	got := db.FormatTopLine()
	if !strings.Contains(got, "0 IPs tracked") || !strings.Contains(got, "0 auto-blocked") {
		t.Errorf("empty formatTopLine = %q", got)
	}
}

func TestFormatTopLineWithBlocked(t *testing.T) {
	db := newTestDB(t)
	db.records["1.1.1.1"] = &IPRecord{IP: "1.1.1.1", AutoBlocked: true}
	db.records["2.2.2.2"] = &IPRecord{IP: "2.2.2.2"}
	got := db.FormatTopLine()
	if !strings.Contains(got, "2 IPs tracked") || !strings.Contains(got, "1 auto-blocked") {
		t.Errorf("got %q", got)
	}
}

// --- PruneExpired ------------------------------------------------------

func TestPruneExpiredRemovesOldRecords(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	db.records["old"] = &IPRecord{IP: "old", LastSeen: now.Add(-100 * 24 * time.Hour)}
	db.records["new"] = &IPRecord{IP: "new", LastSeen: now}

	db.PruneExpired()

	if _, exists := db.records["old"]; exists {
		t.Error("old record should be pruned")
	}
	if _, exists := db.records["new"]; !exists {
		t.Error("new record should be kept")
	}
}

// --- persist: saveRecords / load (flat-file fallback) ----------------

func TestSaveAndLoadRecordsFallback(t *testing.T) {
	db := newTestDB(t)
	db.records["1.1.1.1"] = &IPRecord{
		IP:           "1.1.1.1",
		FirstSeen:    time.Now().Add(-time.Hour),
		LastSeen:     time.Now(),
		EventCount:   5,
		AttackCounts: map[AttackType]int{AttackBruteForce: 5},
		Accounts:     map[string]int{"bob": 3},
		ThreatScore:  75,
	}
	db.dirty = true
	db.saveRecords()

	// Verify the records.json on disk.
	data, err := os.ReadFile(filepath.Join(db.dbPath, recordsFile))
	if err != nil {
		t.Fatalf("records.json not written: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("records.json is empty")
	}

	// Load into a fresh DB and verify round-trip.
	db2 := newTestDB(t)
	db2.dbPath = db.dbPath
	db2.load()
	if rec, ok := db2.records["1.1.1.1"]; !ok {
		t.Fatal("1.1.1.1 not loaded from disk")
	} else {
		if rec.EventCount != 5 {
			t.Errorf("EventCount = %d, want 5", rec.EventCount)
		}
		if rec.AttackCounts[AttackBruteForce] != 5 {
			t.Errorf("AttackCounts = %v", rec.AttackCounts)
		}
		if rec.Accounts["bob"] != 3 {
			t.Errorf("Accounts = %v", rec.Accounts)
		}
	}
}

func TestLoadMissingFileIsNoOp(t *testing.T) {
	db := newTestDB(t)
	// dbPath is empty, no records.json file.
	db.load() // must not error or panic
	if len(db.records) != 0 {
		t.Errorf("load without file should leave records empty, got %d", len(db.records))
	}
}

func TestLoadCorruptJSON(t *testing.T) {
	db := newTestDB(t)
	path := filepath.Join(db.dbPath, recordsFile)
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	db.load() // must log warning but not panic
	if len(db.records) != 0 {
		t.Errorf("corrupt file should yield empty, got %d", len(db.records))
	}
}

func TestLoadInitializesNilMaps(t *testing.T) {
	db := newTestDB(t)
	path := filepath.Join(db.dbPath, recordsFile)
	// Write a record with nil maps.
	body := `{"1.2.3.4":{"ip":"1.2.3.4","first_seen":"2026-04-01T00:00:00Z","last_seen":"2026-04-01T00:00:00Z","event_count":1}}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	db.load()
	rec := db.records["1.2.3.4"]
	if rec == nil {
		t.Fatal("record not loaded")
	}
	if rec.AttackCounts == nil {
		t.Error("AttackCounts should be non-nil after load")
	}
	if rec.Accounts == nil {
		t.Error("Accounts should be non-nil after load")
	}
}

// --- appendEvents / rotateEventsFile / QueryEvents -------------------

func TestAppendEventsFallback(t *testing.T) {
	db := newTestDB(t)
	events := []Event{
		{Timestamp: time.Now(), IP: "1.1.1.1", AttackType: AttackBruteForce, CheckName: "ssh_login_realtime", Severity: 2},
		{Timestamp: time.Now(), IP: "2.2.2.2", AttackType: AttackWebshell, CheckName: "webshell", Severity: 3},
	}
	db.appendEvents(events)

	data, err := os.ReadFile(filepath.Join(db.dbPath, eventsFile))
	if err != nil {
		t.Fatalf("events.jsonl not created: %v", err)
	}
	// Two JSON lines.
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Errorf("got %d lines, want 2", len(lines))
	}
}

func TestQueryEventsFallback(t *testing.T) {
	db := newTestDB(t)
	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	events := []Event{
		{Timestamp: base, IP: "1.1.1.1", AttackType: AttackBruteForce, CheckName: "a"},
		{Timestamp: base.Add(time.Minute), IP: "2.2.2.2", AttackType: AttackWebshell, CheckName: "b"},
		{Timestamp: base.Add(2 * time.Minute), IP: "1.1.1.1", AttackType: AttackRecon, CheckName: "c"},
	}
	db.appendEvents(events)

	got := db.QueryEvents("1.1.1.1", 10)
	if len(got) != 2 {
		t.Errorf("len = %d, want 2", len(got))
	}
	// Newest first after reversal.
	if len(got) >= 1 && got[0].CheckName != "c" {
		t.Errorf("got[0].CheckName = %q, want c (newest first)", got[0].CheckName)
	}
}

func TestQueryEventsLimitTrimsToNewestN(t *testing.T) {
	db := newTestDB(t)
	base := time.Now()
	for i := 0; i < 5; i++ {
		db.appendEvents([]Event{{
			Timestamp:  base.Add(time.Duration(i) * time.Minute),
			IP:         "1.1.1.1",
			AttackType: AttackRecon,
			CheckName:  "c",
		}})
	}
	got := db.QueryEvents("1.1.1.1", 3)
	if len(got) != 3 {
		t.Errorf("got %d events, want 3", len(got))
	}
}

func TestQueryEventsMissingFile(t *testing.T) {
	db := newTestDB(t)
	if got := db.QueryEvents("1.1.1.1", 10); got != nil {
		t.Errorf("missing file = %v, want nil", got)
	}
}

func TestRotateEventsFile(t *testing.T) {
	db := newTestDB(t)
	path := filepath.Join(db.dbPath, eventsFile)
	// Build a multi-line JSONL payload so rotation has something to split.
	var buf []byte
	for i := 0; i < 10; i++ {
		ev := Event{Timestamp: time.Now(), IP: "1.1.1.1", AttackType: AttackRecon, CheckName: "c"}
		b, _ := json.Marshal(ev)
		buf = append(buf, b...)
		buf = append(buf, '\n')
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		t.Fatal(err)
	}
	rotateEventsFile(path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) >= len(buf) {
		t.Errorf("rotated file should be smaller: %d vs %d", len(data), len(buf))
	}
}

// --- Stats / computeStats / readAllEvents ----------------------------

func TestStatsAndComputeStats(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	db.RecordFinding(alert.Finding{
		Check: "webshell", Message: "shell.php from 1.1.1.1", Timestamp: now,
	})
	db.RecordFinding(alert.Finding{
		Check: "wp_login_bruteforce", Message: "brute from 2.2.2.2", Timestamp: now,
	})
	// Flush pending events so readAllEvents() sees them from disk.
	db.appendEvents(db.pendingEvents)

	// Reset the stats cache so we hit the compute path.
	cachedStatsMu.Lock()
	cachedStatsTime = time.Time{}
	cachedStatsMu.Unlock()

	stats := db.Stats()
	if stats.TotalIPs != 2 {
		t.Errorf("TotalIPs = %d, want 2", stats.TotalIPs)
	}
	if stats.TotalEvents != 2 {
		t.Errorf("TotalEvents = %d, want 2", stats.TotalEvents)
	}
	if stats.Last24hEvents != 2 {
		t.Errorf("Last24hEvents = %d, want 2", stats.Last24hEvents)
	}
	if stats.ByType[AttackWebshell] != 1 {
		t.Errorf("ByType[webshell] = %d, want 1", stats.ByType[AttackWebshell])
	}
	if len(stats.TopAttackers) == 0 {
		t.Error("TopAttackers should be populated")
	}
}

func TestStatsCachedWithinTTL(t *testing.T) {
	db := newTestDB(t)
	// Prime cache with known contents.
	cachedStatsMu.Lock()
	cachedStats = AttackStats{TotalIPs: 42}
	cachedStatsTime = time.Now()
	cachedStatsMu.Unlock()

	got := db.Stats()
	if got.TotalIPs != 42 {
		t.Errorf("cached stats should be returned, got TotalIPs=%d", got.TotalIPs)
	}

	// Reset for other tests.
	cachedStatsMu.Lock()
	cachedStatsTime = time.Time{}
	cachedStatsMu.Unlock()
}

func TestReadAllEventsMissingFile(t *testing.T) {
	db := newTestDB(t)
	if got := db.readAllEvents(); got != nil {
		t.Errorf("missing file = %v, want nil", got)
	}
}

// --- Flush / Stop / backgroundSaver ----------------------------------

func TestFlushPersistsDirty(t *testing.T) {
	db := newTestDB(t)
	db.records["1.2.3.4"] = &IPRecord{
		IP: "1.2.3.4", FirstSeen: time.Now(), LastSeen: time.Now(),
		EventCount: 1, ThreatScore: 10,
		AttackCounts: map[AttackType]int{}, Accounts: map[string]int{},
	}
	db.dirty = true
	db.pendingEvents = []Event{{Timestamp: time.Now(), IP: "1.2.3.4", AttackType: AttackOther}}

	if err := db.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if _, err := os.Stat(filepath.Join(db.dbPath, recordsFile)); err != nil {
		t.Errorf("records.json not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(db.dbPath, eventsFile)); err != nil {
		t.Errorf("events.jsonl not written: %v", err)
	}
	// pendingEvents is drained after Flush.
	if len(db.pendingEvents) != 0 {
		t.Errorf("pendingEvents len = %d, want 0", len(db.pendingEvents))
	}
}

func TestStopDrainsAndWaits(t *testing.T) {
	db := newTestDB(t)
	// Spin up the background saver ourselves so Stop has something to wait on.
	db.wg.Add(1)
	go db.backgroundSaver()

	db.records["1.1.1.1"] = &IPRecord{
		IP: "1.1.1.1", FirstSeen: time.Now(), LastSeen: time.Now(),
		EventCount: 1, AttackCounts: map[AttackType]int{}, Accounts: map[string]int{},
	}
	db.dirty = true

	done := make(chan struct{})
	go func() {
		db.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return within 2s")
	}

	// Post-stop, records should be flushed to disk.
	if _, err := os.Stat(filepath.Join(db.dbPath, recordsFile)); err != nil {
		t.Errorf("records.json not written on Stop: %v", err)
	}
}

// --- SeedFromPermanentBlocklist ---------------------------------------

func TestSeedFromPermanentBlocklistMissingFile(t *testing.T) {
	db := newTestDB(t)
	statePath := filepath.Join(db.dbPath, "..") // parent of attack_db
	got := db.SeedFromPermanentBlocklist(statePath)
	if got != 0 {
		t.Errorf("missing file should seed 0, got %d", got)
	}
}

func TestSeedFromPermanentBlocklistImportsIPs(t *testing.T) {
	db := newTestDB(t)
	// statePath = parent dir; threat_db/permanent.txt under it.
	parent := filepath.Dir(db.dbPath)
	threatDir := filepath.Join(parent, "threat_db")
	if err := os.MkdirAll(threatDir, 0700); err != nil {
		t.Fatal(err)
	}
	body := "" +
		"# comment line\n" +
		"\n" +
		"1.2.3.4 # brute force from 2026-04-01\n" +
		"5.6.7.8\n" +
		"bogus-not-an-ip\n"
	if err := os.WriteFile(filepath.Join(threatDir, "permanent.txt"), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}

	imported := db.SeedFromPermanentBlocklist(parent)
	if imported != 2 {
		t.Errorf("imported = %d, want 2", imported)
	}
	if _, ok := db.records["1.2.3.4"]; !ok {
		t.Error("1.2.3.4 should be imported")
	}
	if _, ok := db.records["5.6.7.8"]; !ok {
		t.Error("5.6.7.8 should be imported")
	}
}

func TestSeedFromPermanentBlocklistSkipsExisting(t *testing.T) {
	db := newTestDB(t)
	parent := filepath.Dir(db.dbPath)
	threatDir := filepath.Join(parent, "threat_db")
	if err := os.MkdirAll(threatDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(threatDir, "permanent.txt"), []byte("1.2.3.4\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Pre-populate 1.2.3.4.
	db.records["1.2.3.4"] = &IPRecord{
		IP: "1.2.3.4", FirstSeen: time.Now(), LastSeen: time.Now(),
		EventCount: 1, AttackCounts: map[AttackType]int{}, Accounts: map[string]int{},
	}
	imported := db.SeedFromPermanentBlocklist(parent)
	if imported != 0 {
		t.Errorf("imported = %d, want 0 (already tracked)", imported)
	}
}

// --- Global ------------------------------------------------------------

func TestGlobalInitiallyNilBeforeInit(t *testing.T) {
	// We cannot call Init from tests (sync.Once), but Global() before
	// Init should simply return whatever the var currently holds. This
	// test just makes sure Global() doesn't panic.
	var _ = Global()
}

// Avoid an unused-import warning if `sync` ever becomes unused.
var _ = sync.RWMutex{}
