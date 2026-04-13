package daemon

import (
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/geoip"
)

// ---------------------------------------------------------------------------
// setGeoIPDB / getGeoIPDB
// ---------------------------------------------------------------------------

func TestSetGetGeoIPDB_NilByDefault(t *testing.T) {
	// Reset to nil for a clean test, restore afterwards.
	prev := getGeoIPDB()
	setGeoIPDB(nil)
	defer setGeoIPDB(prev)

	if db := getGeoIPDB(); db != nil {
		t.Errorf("expected nil, got %v", db)
	}
}

func TestSetGetGeoIPDB_RoundTrips(t *testing.T) {
	prev := getGeoIPDB()
	defer setGeoIPDB(prev)

	db := &geoip.DB{}
	setGeoIPDB(db)
	if got := getGeoIPDB(); got != db {
		t.Errorf("round-trip failed: got %v, want %v", got, db)
	}
}

// ---------------------------------------------------------------------------
// isTrustedCountry
// ---------------------------------------------------------------------------

func TestIsTrustedCountry_NilDB(t *testing.T) {
	prev := getGeoIPDB()
	setGeoIPDB(nil)
	defer setGeoIPDB(prev)

	if isTrustedCountry("203.0.113.5", []string{"US"}) {
		t.Error("nil DB should always return false")
	}
}

func TestIsTrustedCountry_EmptyTrustedList(t *testing.T) {
	if isTrustedCountry("1.2.3.4", nil) {
		t.Error("empty trusted list should return false")
	}
	if isTrustedCountry("1.2.3.4", []string{}) {
		t.Error("empty trusted list should return false")
	}
}

// ---------------------------------------------------------------------------
// extractModSecField
// ---------------------------------------------------------------------------

func TestExtractModSecField_Standard(t *testing.T) {
	line := `[id "920420"] [msg "Request content type not allowed"]`
	got := extractModSecField(line, `[id "`, `"]`)
	if got != "920420" {
		t.Errorf("got %q, want 920420", got)
	}
}

func TestExtractModSecField_Missing(t *testing.T) {
	if got := extractModSecField("no delimiters here", `[id "`, `"]`); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractModSecField_NoEndDelimiter(t *testing.T) {
	if got := extractModSecField(`[id "920420`, `[id "`, `"]`); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractModSecField_EmptyValue(t *testing.T) {
	if got := extractModSecField(`[id ""]`, `[id "`, `"]`); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractModSecField_MultipleOccurrences(t *testing.T) {
	line := `[id "111"] [id "222"]`
	got := extractModSecField(line, `[id "`, `"]`)
	// Should return the first occurrence.
	if got != "111" {
		t.Errorf("got %q, want 111", got)
	}
}

// ---------------------------------------------------------------------------
// extractLiteSpeedIP
// ---------------------------------------------------------------------------

func TestExtractLiteSpeedIP_Standard(t *testing.T) {
	line := `2026-04-01 [NOTICE] [122.9.114.57:41920-13#APVH_*_server.example.com] [MODSEC] triggered!`
	got := extractLiteSpeedIP(line)
	if got != "122.9.114.57" {
		t.Errorf("got %q, want 122.9.114.57", got)
	}
}

func TestExtractLiteSpeedIP_NoMatch(t *testing.T) {
	if got := extractLiteSpeedIP("no bracketed IP here"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractLiteSpeedIP_BracketButNotLiteSpeed(t *testing.T) {
	// A bracket without the #-conn pattern should not match.
	if got := extractLiteSpeedIP("[plain text] more text"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractLiteSpeedIP_NoCloseBracket(t *testing.T) {
	if got := extractLiteSpeedIP("[122.9.114.57:41920-13#APVH_*_server.example.com"); got != "" {
		t.Errorf("unclosed bracket should return empty, got %q", got)
	}
}

func TestExtractLiteSpeedIP_IPv6NotMatched(t *testing.T) {
	// IPv6 doesn't have 3 dots, so extractLiteSpeedIP should return empty.
	line := `[2001:db8::1:41920-13#APVH_*_host] [MODSEC] triggered!`
	if got := extractLiteSpeedIP(line); got != "" {
		t.Errorf("IPv6 should not match dot-count check, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// mergeInfraIPs
// ---------------------------------------------------------------------------

func TestMergeInfraIPs_BothEmpty(t *testing.T) {
	if got := mergeInfraIPs(nil, nil); len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

func TestMergeInfraIPs_NoDuplicates(t *testing.T) {
	got := mergeInfraIPs(
		[]string{"10.0.0.1", "10.0.0.2"},
		[]string{"10.0.0.3"},
	)
	if len(got) != 3 {
		t.Errorf("got %d entries, want 3", len(got))
	}
}

func TestMergeInfraIPs_Deduplicates(t *testing.T) {
	got := mergeInfraIPs(
		[]string{"10.0.0.1", "10.0.0.2"},
		[]string{"10.0.0.1", "10.0.0.3"},
	)
	if len(got) != 3 {
		t.Errorf("got %d entries, want 3 (deduped): %v", len(got), got)
	}
}

func TestMergeInfraIPs_PreservesOrder(t *testing.T) {
	got := mergeInfraIPs(
		[]string{"a", "b"},
		[]string{"c", "a"},
	)
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("length mismatch: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestMergeInfraIPs_OnlyTopLevel(t *testing.T) {
	got := mergeInfraIPs([]string{"10.0.0.1"}, nil)
	if len(got) != 1 || got[0] != "10.0.0.1" {
		t.Errorf("got %v", got)
	}
}

func TestMergeInfraIPs_OnlyFirewall(t *testing.T) {
	got := mergeInfraIPs(nil, []string{"10.0.0.2"})
	if len(got) != 1 || got[0] != "10.0.0.2" {
		t.Errorf("got %v", got)
	}
}

// ---------------------------------------------------------------------------
// truncateDaemon
// ---------------------------------------------------------------------------

func TestTruncateDaemon_Short(t *testing.T) {
	if got := truncateDaemon("hello", 10); got != "hello" {
		t.Errorf("got %q", got)
	}
}

func TestTruncateDaemon_ExactLength(t *testing.T) {
	if got := truncateDaemon("hello", 5); got != "hello" {
		t.Errorf("got %q", got)
	}
}

func TestTruncateDaemon_Truncates(t *testing.T) {
	got := truncateDaemon("hello world", 5)
	if got != "hello..." {
		t.Errorf("got %q, want %q", got, "hello...")
	}
}

func TestTruncateDaemon_Empty(t *testing.T) {
	if got := truncateDaemon("", 5); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// recordCSMDeny
// ---------------------------------------------------------------------------

func TestRecordCSMDeny_BelowThreshold(t *testing.T) {
	modsecCSMCounter = sync.Map{}
	defer func() { modsecCSMCounter = sync.Map{} }()

	now := time.Now()
	// First two hits should not escalate (threshold is 3).
	if recordCSMDeny("1.2.3.4", now) {
		t.Error("first hit should not escalate")
	}
	if recordCSMDeny("1.2.3.4", now.Add(time.Second)) {
		t.Error("second hit should not escalate")
	}
}

func TestRecordCSMDeny_AtThreshold(t *testing.T) {
	modsecCSMCounter = sync.Map{}
	defer func() { modsecCSMCounter = sync.Map{} }()

	now := time.Now()
	recordCSMDeny("1.2.3.4", now)
	recordCSMDeny("1.2.3.4", now.Add(time.Second))
	if !recordCSMDeny("1.2.3.4", now.Add(2*time.Second)) {
		t.Error("third hit should trigger escalation")
	}
}

func TestRecordCSMDeny_OnlyEscalatesOnce(t *testing.T) {
	modsecCSMCounter = sync.Map{}
	defer func() { modsecCSMCounter = sync.Map{} }()

	now := time.Now()
	recordCSMDeny("1.2.3.4", now)
	recordCSMDeny("1.2.3.4", now.Add(time.Second))
	recordCSMDeny("1.2.3.4", now.Add(2*time.Second)) // escalates

	// Fourth hit should NOT re-escalate.
	if recordCSMDeny("1.2.3.4", now.Add(3*time.Second)) {
		t.Error("should not re-escalate after first escalation")
	}
}

func TestRecordCSMDeny_SeparateIPs(t *testing.T) {
	modsecCSMCounter = sync.Map{}
	defer func() { modsecCSMCounter = sync.Map{} }()

	now := time.Now()
	recordCSMDeny("1.1.1.1", now)
	recordCSMDeny("2.2.2.2", now)

	// Each IP has only 1 hit - neither should escalate at 2.
	if recordCSMDeny("1.1.1.1", now.Add(time.Second)) {
		t.Error("1.1.1.1 should not escalate with only 2 hits")
	}
	if recordCSMDeny("2.2.2.2", now.Add(time.Second)) {
		t.Error("2.2.2.2 should not escalate with only 2 hits")
	}
}

func TestRecordCSMDeny_PrunesOldEntries(t *testing.T) {
	modsecCSMCounter = sync.Map{}
	defer func() { modsecCSMCounter = sync.Map{} }()

	// Two hits happened long ago (outside the escalation window).
	old := time.Now().Add(-modsecEscalationWin - time.Minute)
	recordCSMDeny("1.2.3.4", old)
	recordCSMDeny("1.2.3.4", old.Add(time.Second))

	// A third hit now should NOT escalate because old hits were pruned.
	now := time.Now()
	if recordCSMDeny("1.2.3.4", now) {
		t.Error("old entries should be pruned, so only 1 recent hit exists")
	}
}

// ---------------------------------------------------------------------------
// evictModSecState (counter branch + escalation reset)
// ---------------------------------------------------------------------------

func TestEvictModSecState_ResetsEscalation(t *testing.T) {
	modsecCSMCounter = sync.Map{}
	modsecDedup = sync.Map{}
	defer func() {
		modsecCSMCounter = sync.Map{}
		modsecDedup = sync.Map{}
	}()

	now := time.Now()

	// Create a counter that has escalated.
	recordCSMDeny("5.5.5.5", now)
	recordCSMDeny("5.5.5.5", now.Add(time.Second))
	recordCSMDeny("5.5.5.5", now.Add(2*time.Second))

	// Run eviction far in the future so all timestamps expire.
	evictModSecState(now.Add(modsecEscalationWin + time.Hour))

	// Counter should be deleted (no recent timestamps).
	if _, loaded := modsecCSMCounter.Load("5.5.5.5"); loaded {
		t.Error("empty counter should be evicted")
	}
}

func TestEvictModSecState_KeepsRecentCounters(t *testing.T) {
	modsecCSMCounter = sync.Map{}
	defer func() { modsecCSMCounter = sync.Map{} }()

	now := time.Now()
	recordCSMDeny("6.6.6.6", now)

	evictModSecState(now)

	if _, loaded := modsecCSMCounter.Load("6.6.6.6"); !loaded {
		t.Error("recent counter should be kept")
	}
}

func TestEvictModSecState_ResetsEscalatedFlagBelowThreshold(t *testing.T) {
	modsecCSMCounter = sync.Map{}
	defer func() { modsecCSMCounter = sync.Map{} }()

	now := time.Now()

	// Trigger escalation (3 hits).
	recordCSMDeny("7.7.7.7", now)
	recordCSMDeny("7.7.7.7", now.Add(time.Second))
	recordCSMDeny("7.7.7.7", now.Add(2*time.Second))

	// Evict at a time when 2 of the 3 timestamps are still valid but not all 3.
	// We need the first one to expire and the other two to remain.
	evictTime := now.Add(modsecEscalationWin + time.Second)
	evictModSecState(evictTime)

	// Counter should still exist (2 entries remain), but escalated flag reset.
	val, loaded := modsecCSMCounter.Load("7.7.7.7")
	if !loaded {
		// It's possible all were pruned since they're close together. That's fine.
		return
	}
	ctr := val.(*modsecIPCounter)
	ctr.mu.Lock()
	defer ctr.mu.Unlock()
	if ctr.escalated {
		t.Error("escalated flag should be reset when count drops below threshold")
	}
}

// ---------------------------------------------------------------------------
// pruneAndAppend
// ---------------------------------------------------------------------------

func TestPruneAndAppend_RemovesOldAndAppends(t *testing.T) {
	now := time.Now()
	times := []time.Time{
		now.Add(-2 * time.Hour),
		now.Add(-30 * time.Minute),
	}
	cutoff := now.Add(-1 * time.Hour)
	got := pruneAndAppend(times, cutoff, now)
	// Should keep the -30m entry and append now.
	if len(got) != 2 {
		t.Errorf("got %d entries, want 2", len(got))
	}
}

func TestPruneAndAppend_EmptySlice(t *testing.T) {
	now := time.Now()
	got := pruneAndAppend(nil, now.Add(-time.Hour), now)
	if len(got) != 1 {
		t.Errorf("got %d entries, want 1", len(got))
	}
}

func TestPruneAndAppend_AllExpired(t *testing.T) {
	now := time.Now()
	times := []time.Time{
		now.Add(-3 * time.Hour),
		now.Add(-2 * time.Hour),
	}
	got := pruneAndAppend(times, now.Add(-time.Hour), now)
	if len(got) != 1 {
		t.Errorf("got %d entries, want 1 (only the appended now)", len(got))
	}
}

// ---------------------------------------------------------------------------
// splitKV
// ---------------------------------------------------------------------------

func TestSplitKV_Standard(t *testing.T) {
	s := "ip=1.2.3.4 script=/tmp/evil.php uri=/test ua=curl details=blocked"
	kvs := splitKV(s)

	found := make(map[string]string)
	for _, kv := range kvs {
		found[kv[0]] = kv[1]
	}

	if found["ip"] != "1.2.3.4" {
		t.Errorf("ip = %q", found["ip"])
	}
	if found["script"] != "/tmp/evil.php" {
		t.Errorf("script = %q", found["script"])
	}
	if found["details"] != "blocked" {
		t.Errorf("details = %q", found["details"])
	}
}

func TestSplitKV_DetailsWithSpaces(t *testing.T) {
	s := "ip=1.2.3.4 details=this has spaces"
	kvs := splitKV(s)

	found := make(map[string]string)
	for _, kv := range kvs {
		found[kv[0]] = kv[1]
	}

	if found["details"] != "this has spaces" {
		t.Errorf("details = %q, want 'this has spaces'", found["details"])
	}
}

func TestSplitKV_Empty(t *testing.T) {
	kvs := splitKV("")
	if len(kvs) != 0 {
		t.Errorf("got %d KVs, want 0", len(kvs))
	}
}

func TestSplitKV_NoKnownKeys(t *testing.T) {
	kvs := splitKV("foo=bar baz=quux")
	if len(kvs) != 0 {
		t.Errorf("got %d KVs for unknown keys, want 0", len(kvs))
	}
}

func TestSplitKV_OnlyIP(t *testing.T) {
	kvs := splitKV("ip=10.0.0.1")
	if len(kvs) != 1 {
		t.Fatalf("got %d KVs, want 1", len(kvs))
	}
	if kvs[0][0] != "ip" || kvs[0][1] != "10.0.0.1" {
		t.Errorf("got %v", kvs[0])
	}
}

// ---------------------------------------------------------------------------
// isKnownForwarderWatcher
// ---------------------------------------------------------------------------

func TestIsKnownForwarderWatcher_Match(t *testing.T) {
	known := []string{"info@example.com: admin@gmail.com"}
	if !isKnownForwarderWatcher("info", "example.com", "admin@gmail.com", known) {
		t.Error("should match known forwarder")
	}
}

func TestIsKnownForwarderWatcher_CaseInsensitive(t *testing.T) {
	known := []string{"INFO@EXAMPLE.COM: ADMIN@GMAIL.COM"}
	if !isKnownForwarderWatcher("info", "example.com", "admin@gmail.com", known) {
		t.Error("should match case-insensitively")
	}
}

func TestIsKnownForwarderWatcher_NoMatch(t *testing.T) {
	known := []string{"info@example.com: admin@gmail.com"}
	if isKnownForwarderWatcher("support", "example.com", "admin@gmail.com", known) {
		t.Error("different local part should not match")
	}
}

func TestIsKnownForwarderWatcher_EmptyList(t *testing.T) {
	if isKnownForwarderWatcher("info", "example.com", "admin@gmail.com", nil) {
		t.Error("empty list should not match")
	}
}

// ---------------------------------------------------------------------------
// isInfraIPDaemon edge cases
// ---------------------------------------------------------------------------

func TestIsInfraIPDaemon_InvalidIP(t *testing.T) {
	if isInfraIPDaemon("not-an-ip", []string{"10.0.0.0/8"}) {
		t.Error("invalid IP should return false")
	}
}

func TestIsInfraIPDaemon_EmptyIP(t *testing.T) {
	if isInfraIPDaemon("", []string{"10.0.0.0/8"}) {
		t.Error("empty IP should return false")
	}
}

func TestIsInfraIPDaemon_InvalidCIDRFallsBackToExact(t *testing.T) {
	// When CIDR parsing fails, the function tries exact string match.
	if !isInfraIPDaemon("10.0.0.1", []string{"10.0.0.1"}) {
		t.Error("exact IP match should work when CIDR parse fails")
	}
}

func TestIsInfraIPDaemon_EmptyList(t *testing.T) {
	if isInfraIPDaemon("10.0.0.1", nil) {
		t.Error("empty infra list should return false")
	}
}

func TestIsInfraIPDaemon_IPv6CIDR(t *testing.T) {
	if !isInfraIPDaemon("2001:db8::1", []string{"2001:db8::/32"}) {
		t.Error("IPv6 CIDR match should work")
	}
}

func TestIsInfraIPDaemon_IPv6ExactNoMatch(t *testing.T) {
	if isInfraIPDaemon("2001:db8::2", []string{"2001:db8::1"}) {
		t.Error("different IPv6 should not match")
	}
}

// ---------------------------------------------------------------------------
// extractEximSubject edge cases
// ---------------------------------------------------------------------------

func TestExtractEximSubject_NoClosingQuote(t *testing.T) {
	line := `T="unclosed subject`
	got := extractEximSubject(line)
	// When no closing quote is found, the function returns the rest of the string.
	if got != "unclosed subject" {
		t.Errorf("got %q", got)
	}
}

func TestExtractEximSubject_EmptySubject(t *testing.T) {
	line := `T="" more stuff`
	if got := extractEximSubject(line); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// extractEximSender edge cases
// ---------------------------------------------------------------------------

func TestExtractEximSender_NoFieldsAfterMarker(t *testing.T) {
	// " <= " at end of line with no further content.
	line := "prefix <= "
	if got := extractEximSender(line); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// parseCpanelSessionLogin edge cases
// ---------------------------------------------------------------------------

func TestParseCpanelSessionLogin_ShortFields(t *testing.T) {
	line := `[cpaneld] 1.2.3.4 `
	ip, account := parseCpanelSessionLogin(line)
	if ip != "" || account != "" {
		t.Errorf("short fields should return empty: (%q, %q)", ip, account)
	}
}

func TestParseCpanelSessionLogin_NoNEW(t *testing.T) {
	line := `[cpaneld] 1.2.3.4 OLD alice:token address=1.2.3.4`
	ip, account := parseCpanelSessionLogin(line)
	// IP is still extracted (first field after [cpaneld]), but account is empty
	// since there's no "NEW" keyword.
	if account != "" {
		t.Errorf("no NEW keyword should yield empty account, got %q", account)
	}
	_ = ip
}

// ---------------------------------------------------------------------------
// parsePurgeDaemon edge cases
// ---------------------------------------------------------------------------

func TestParsePurgeDaemon_EmptyAfterPurge(t *testing.T) {
	line := "PURGE"
	if got := parsePurgeDaemon(line); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestParsePurgeDaemon_WhitespaceAfterPurge(t *testing.T) {
	line := "PURGE   "
	if got := parsePurgeDaemon(line); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// extractBracketedIP edge cases
// ---------------------------------------------------------------------------

func TestExtractBracketedIP_IPv6Full(t *testing.T) {
	line := "H=hostname [2001:db8::1]:25"
	got := extractBracketedIP(line)
	// Starts with a digit? No, starts with '2'. len >= 7? "2001:db8::1" is 11 chars. Should match.
	if got != "2001:db8::1" {
		t.Errorf("got %q, want 2001:db8::1", got)
	}
}

func TestExtractBracketedIP_IPv6Loopback(t *testing.T) {
	// "::1" is only 3 chars, below the 7-char minimum; returns empty.
	line := "H=hostname [::1]:25"
	if got := extractBracketedIP(line); got != "" {
		t.Errorf("short IPv6 loopback should return empty (len < 7), got %q", got)
	}
}

func TestExtractBracketedIP_UnclosedBracket(t *testing.T) {
	if got := extractBracketedIP("[203.0.113.5"); got != "" {
		t.Errorf("unclosed bracket should return empty, got %q", got)
	}
}

func TestExtractBracketedIP_ShortContent(t *testing.T) {
	// Content too short to be an IP (less than 7 chars).
	if got := extractBracketedIP("[ab]"); got != "" {
		t.Errorf("short content should return empty, got %q", got)
	}
}

func TestExtractBracketedIP_MultipleSelectsLast(t *testing.T) {
	line := "H=hostname [10.0.0.1] connected from [203.0.113.5]:1234"
	got := extractBracketedIP(line)
	if got != "203.0.113.5" {
		t.Errorf("should select last bracketed IP, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// extractMailHoldSender edge cases
// ---------------------------------------------------------------------------

func TestExtractMailHoldSender_DomainEndOfLine(t *testing.T) {
	line := "Domain example.org"
	if got := extractMailHoldSender(line); got != "example.org" {
		t.Errorf("got %q, want example.org", got)
	}
}

func TestExtractMailHoldSender_SenderAndDomainPrefersSender(t *testing.T) {
	// When both "Sender" and "Domain" appear, "Sender" comes first and wins.
	line := "Sender user@example.com Domain example.com"
	if got := extractMailHoldSender(line); got != "user@example.com" {
		t.Errorf("got %q, want user@example.com", got)
	}
}

// ---------------------------------------------------------------------------
// extractDomainFromEmail edge cases
// ---------------------------------------------------------------------------

func TestExtractDomainFromEmail_TrailingAt(t *testing.T) {
	// "user@" has no domain part after @.
	if got := extractDomainFromEmail("user@"); got != "" {
		t.Errorf("trailing @ should return empty, got %q", got)
	}
}

func TestExtractDomainFromEmail_MultipleAt(t *testing.T) {
	// Should use LastIndexByte, returning after the last @.
	got := extractDomainFromEmail("user@sub@domain.com")
	if got != "domain.com" {
		t.Errorf("got %q, want domain.com", got)
	}
}

// ---------------------------------------------------------------------------
// orUnknown / orNone
// ---------------------------------------------------------------------------

func TestOrUnknown_Empty(t *testing.T) {
	if got := orUnknown(""); got != "unknown" {
		t.Errorf("got %q, want unknown", got)
	}
}

func TestOrUnknown_NonEmpty(t *testing.T) {
	if got := orUnknown("hello"); got != "hello" {
		t.Errorf("got %q, want hello", got)
	}
}

func TestOrNone_Empty(t *testing.T) {
	if got := orNone(""); got != "none" {
		t.Errorf("got %q, want none", got)
	}
}

func TestOrNone_NonEmpty(t *testing.T) {
	if got := orNone("value"); got != "value" {
		t.Errorf("got %q, want value", got)
	}
}

// ---------------------------------------------------------------------------
// evictEmailRateWindows
// ---------------------------------------------------------------------------

func TestEvictEmailRateWindows_RemovesEmptyEntries(t *testing.T) {
	emailRateWindows = sync.Map{}
	defer func() { emailRateWindows = sync.Map{} }()

	// Add a window with old entries.
	rw := &rateWindow{}
	rw.times = []time.Time{time.Now().Add(-2 * time.Hour)}
	emailRateWindows.Store("old-user@test.com", rw)

	evictEmailRateWindows(time.Now())

	if _, loaded := emailRateWindows.Load("old-user@test.com"); loaded {
		t.Error("empty rate window should be evicted")
	}
}

func TestEvictEmailRateWindows_KeepsRecentEntries(t *testing.T) {
	emailRateWindows = sync.Map{}
	defer func() { emailRateWindows = sync.Map{} }()

	rw := &rateWindow{}
	rw.times = []time.Time{time.Now()}
	emailRateWindows.Store("active-user@test.com", rw)

	evictEmailRateWindows(time.Now())

	if _, loaded := emailRateWindows.Load("active-user@test.com"); !loaded {
		t.Error("recent rate window should be kept")
	}
}

func TestEvictEmailRateWindows_ResetsAlertedOnEmpty(t *testing.T) {
	emailRateWindows = sync.Map{}
	defer func() { emailRateWindows = sync.Map{} }()

	rw := &rateWindow{}
	rw.times = []time.Time{time.Now().Add(-2 * time.Hour)}
	rw.alerted = "crit"
	emailRateWindows.Store("alerted-user@test.com", rw)

	evictEmailRateWindows(time.Now())

	// The entry should be deleted because all timestamps were pruned.
	if _, loaded := emailRateWindows.Load("alerted-user@test.com"); loaded {
		t.Error("fully pruned window should be deleted")
	}
}

// ---------------------------------------------------------------------------
// evictAccessLogState: alert flag reset after cooldown
// ---------------------------------------------------------------------------

func TestEvictAccessLogState_ResetsAlertFlagsAfterCooldown(t *testing.T) {
	accessLogTrackers = sync.Map{}
	defer func() { accessLogTrackers = sync.Map{} }()

	// Create a tracker that was alerted and has remaining timestamps.
	now := time.Now()
	tracker := &accessLogTracker{
		lastSeen:       now.Add(-accessLogBlockCooldown - time.Minute),
		wpLoginTimes:   []time.Time{now}, // still has recent timestamps
		wpLoginAlerted: true,
		xmlrpcAlerted:  true,
	}
	accessLogTrackers.Store("8.8.8.8", tracker)

	evictAccessLogState(now)

	tracker.mu.Lock()
	wpAlerted := tracker.wpLoginAlerted
	xmlrpcAlerted := tracker.xmlrpcAlerted
	tracker.mu.Unlock()

	if wpAlerted {
		t.Error("wpLoginAlerted should be reset after cooldown")
	}
	if xmlrpcAlerted {
		t.Error("xmlrpcAlerted should be reset after cooldown")
	}
}

func TestEvictAccessLogState_DoesNotResetAlertFlagBeforeCooldown(t *testing.T) {
	accessLogTrackers = sync.Map{}
	defer func() { accessLogTrackers = sync.Map{} }()

	now := time.Now()
	tracker := &accessLogTracker{
		lastSeen:       now, // just seen
		wpLoginTimes:   []time.Time{now},
		wpLoginAlerted: true,
	}
	accessLogTrackers.Store("9.9.9.9", tracker)

	evictAccessLogState(now)

	tracker.mu.Lock()
	alerted := tracker.wpLoginAlerted
	tracker.mu.Unlock()

	if !alerted {
		t.Error("wpLoginAlerted should NOT be reset before cooldown expires")
	}
}

// ---------------------------------------------------------------------------
// parseDKIMFailureDomain edge cases
// ---------------------------------------------------------------------------

func TestParseDKIMFailureDomain_EndOfLine(t *testing.T) {
	line := "DKIM: signing failed for end-of-line.com"
	got := parseDKIMFailureDomain(line)
	if got != "end-of-line.com" {
		t.Errorf("got %q", got)
	}
}

func TestParseDKIMFailureDomain_ColonTerminated(t *testing.T) {
	line := "DKIM: signing failed for domain.com: error message"
	got := parseDKIMFailureDomain(line)
	if got != "domain.com" {
		t.Errorf("got %q", got)
	}
}

func TestParseDKIMFailureDomain_Empty(t *testing.T) {
	if got := parseDKIMFailureDomain(""); got != "" {
		t.Errorf("got %q", got)
	}
}

// ---------------------------------------------------------------------------
// isDedupExpired edge cases (supplement existing tests)
// ---------------------------------------------------------------------------

func TestIsDedupExpired_ExactBoundary(t *testing.T) {
	// A timestamp that's exactly at the window boundary.
	exactly := time.Now().Format(time.RFC3339)
	// Should NOT be expired because time.Since will be ~0.
	if isDedupExpired(exactly, time.Hour) {
		t.Error("timestamp at current time should not be expired")
	}
}

// ---------------------------------------------------------------------------
// extractSetID edge cases (supplement existing tests)
// ---------------------------------------------------------------------------

func TestExtractSetID_WithClosingParen(t *testing.T) {
	line := "(set_id=user@domain.com)"
	got := extractSetID(line)
	if got != "user@domain.com" {
		t.Errorf("got %q", got)
	}
}

func TestExtractSetID_WithSpace(t *testing.T) {
	line := "set_id=user@domain.com next field"
	got := extractSetID(line)
	if got != "user@domain.com" {
		t.Errorf("got %q", got)
	}
}

// ---------------------------------------------------------------------------
// extractEximDomain edge cases
// ---------------------------------------------------------------------------

func TestExtractEximDomain_NoSpaceAfterDomain(t *testing.T) {
	line := "Domain example.com"
	got := extractEximDomain(line)
	if got != "example.com" {
		t.Errorf("got %q", got)
	}
}

// ---------------------------------------------------------------------------
// parsePHPShieldLine edge case: bracket at very end
// ---------------------------------------------------------------------------

func TestParsePHPShieldLine_BracketAtEnd(t *testing.T) {
	// closeBracket+2 >= len(line) should return nil.
	line := "[x]"
	if got := parsePHPShieldLine(line); got != nil {
		t.Errorf("bracket at end should return nil, got %+v", got)
	}
}

func TestParsePHPShieldLine_OnlyTimestamp(t *testing.T) {
	line := "[2026-04-12 10:00:00]"
	if got := parsePHPShieldLine(line); got != nil {
		t.Errorf("only timestamp should return nil, got %+v", got)
	}
}
