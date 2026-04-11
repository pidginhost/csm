package checks

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- downloadFeed ------------------------------------------------------

func TestDownloadFeedParsesIPsAndCIDRs(t *testing.T) {
	body := `# comment line
; another comment
203.0.113.1
203.0.113.2  ; inline comment
198.51.100.0/24
2001:db8::1
invalid-entry
203.0.113.3 # inline hash
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	ips, nets, err := downloadFeed(client, srv.URL, "test-feed")
	if err != nil {
		t.Fatalf("downloadFeed: %v", err)
	}

	wantIPs := map[string]bool{
		"203.0.113.1": true,
		"203.0.113.2": true,
		"203.0.113.3": true,
		"2001:db8::1": true,
	}
	if len(ips) != len(wantIPs) {
		t.Errorf("got %d IPs %v, want %d", len(ips), ips, len(wantIPs))
	}
	for _, ip := range ips {
		if !wantIPs[ip] {
			t.Errorf("unexpected IP %q", ip)
		}
	}

	if len(nets) != 1 {
		t.Fatalf("got %d CIDRs, want 1", len(nets))
	}
	if nets[0].String() != "198.51.100.0/24" {
		t.Errorf("CIDR = %q, want 198.51.100.0/24", nets[0].String())
	}
}

func TestDownloadFeedHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, _, err := downloadFeed(&http.Client{Timeout: 5 * time.Second}, srv.URL, "broken")
	if err == nil {
		t.Error("expected error for HTTP 500")
	}
}

func TestDownloadFeedNetworkError(t *testing.T) {
	// Closed server → connection refused
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	_, _, err := downloadFeed(&http.Client{Timeout: 2 * time.Second}, srv.URL, "dead")
	if err == nil {
		t.Error("expected network error")
	}
}

func TestDownloadFeedEmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	ips, nets, err := downloadFeed(&http.Client{Timeout: 5 * time.Second}, srv.URL, "empty")
	if err != nil {
		t.Fatalf("downloadFeed: %v", err)
	}
	if len(ips) != 0 || len(nets) != 0 {
		t.Errorf("empty body should return no entries, got %d ips, %d nets", len(ips), len(nets))
	}
}

// --- saveLines / loadLines round-trip ---------------------------------

func TestSaveLoadLinesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.txt")

	input := []string{"203.0.113.5", "198.51.100.1", "203.0.113.1"}
	saveLines(path, input)

	got := loadLines(path)
	// saveLines sorts; loadLines preserves file order.
	want := []string{"198.51.100.1", "203.0.113.1", "203.0.113.5"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLoadLinesMissingFile(t *testing.T) {
	got := loadLines(filepath.Join(t.TempDir(), "does-not-exist.txt"))
	if got != nil {
		t.Errorf("missing file should return nil, got %v", got)
	}
}

func TestLoadLinesSkipsCommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.txt")
	content := "# header comment\n\n203.0.113.1\n  \n# another\n203.0.113.2\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := loadLines(path)
	if len(got) != 2 {
		t.Fatalf("got %d, want 2: %v", len(got), got)
	}
	if got[0] != "203.0.113.1" || got[1] != "203.0.113.2" {
		t.Errorf("unexpected contents: %v", got)
	}
}

// --- compactPermanentFile --------------------------------------------

func TestCompactPermanentFileDeduplicates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "permanent.txt")
	// 3 unique IPs, 8 lines total (5 duplicates to exceed the "not worth compacting" threshold)
	content := `# header
203.0.113.1 # reason one
203.0.113.1 # reason one dup
203.0.113.2 # reason two
203.0.113.1 # reason one dup again
203.0.113.2 # reason two dup
203.0.113.3 # reason three
203.0.113.1 # more dups
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	unique := map[string]bool{
		"203.0.113.1": true,
		"203.0.113.2": true,
		"203.0.113.3": true,
	}
	compactPermanentFile(path, unique)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after compact: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	// header + 3 unique IPs = 4 lines
	if len(lines) != 4 {
		t.Errorf("got %d lines after compact, want 4: %v", len(lines), lines)
	}
	// Comment preserved
	if lines[0] != "# header" {
		t.Errorf("header dropped: %v", lines)
	}
	// First occurrence of each IP kept
	seen := make(map[string]bool)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		ip := fields[0]
		if seen[ip] {
			t.Errorf("duplicate %q survived compaction", ip)
		}
		seen[ip] = true
	}
}

func TestCompactPermanentFileSkipsWhenNotWorth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "permanent.txt")
	// 3 unique IPs, 4 lines → below compaction threshold (len(lines) <= len(uniqueIPs)+5)
	content := "203.0.113.1\n203.0.113.2\n203.0.113.3\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	before, _ := os.ReadFile(path)

	unique := map[string]bool{"203.0.113.1": true, "203.0.113.2": true, "203.0.113.3": true}
	compactPermanentFile(path, unique)

	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Errorf("file should be untouched when below threshold\nbefore=%q\nafter=%q", before, after)
	}
}

func TestCompactPermanentFileMissingFile(t *testing.T) {
	// Should not panic on missing file.
	compactPermanentFile(filepath.Join(t.TempDir(), "missing.txt"), map[string]bool{"1.2.3.4": true})
}

// --- ThreatDB.Lookup --------------------------------------------------

func newTestThreatDB(t *testing.T) *ThreatDB {
	t.Helper()
	dir := t.TempDir()
	return &ThreatDB{
		badIPs:        make(map[string]string),
		whitelist:     make(map[string]bool),
		whitelistMeta: make(map[string]*whitelistEntry),
		dbPath:        dir,
	}
}

func TestThreatDBLookupExactMatch(t *testing.T) {
	db := newTestThreatDB(t)
	db.badIPs["203.0.113.5"] = "spamhaus-drop"

	source, ok := db.Lookup("203.0.113.5")
	if !ok || source != "spamhaus-drop" {
		t.Errorf("Lookup(hit) = (%q, %v), want (spamhaus-drop, true)", source, ok)
	}
}

func TestThreatDBLookupMiss(t *testing.T) {
	db := newTestThreatDB(t)
	_, ok := db.Lookup("203.0.113.99")
	if ok {
		t.Errorf("unknown IP should miss, got true")
	}
}

func TestThreatDBLookupWhitelistedOverride(t *testing.T) {
	db := newTestThreatDB(t)
	db.badIPs["203.0.113.5"] = "spamhaus-drop"
	db.whitelist["203.0.113.5"] = true

	_, ok := db.Lookup("203.0.113.5")
	if ok {
		t.Errorf("whitelisted IP should not match even if on blocklist")
	}
}

func TestThreatDBLookupCIDRMatch(t *testing.T) {
	db := newTestThreatDB(t)
	_, cidr, _ := net.ParseCIDR("198.51.100.0/24")
	db.badNets = []*net.IPNet{cidr}

	source, ok := db.Lookup("198.51.100.42")
	if !ok || source != "threat-feed-cidr" {
		t.Errorf("CIDR match = (%q, %v), want (threat-feed-cidr, true)", source, ok)
	}
}

func TestThreatDBLookupCIDRNonMatch(t *testing.T) {
	db := newTestThreatDB(t)
	_, cidr, _ := net.ParseCIDR("198.51.100.0/24")
	db.badNets = []*net.IPNet{cidr}

	_, ok := db.Lookup("203.0.113.1")
	if ok {
		t.Errorf("out-of-range IP should not match CIDR")
	}
}

func TestThreatDBLookupInvalidIP(t *testing.T) {
	db := newTestThreatDB(t)
	_, cidr, _ := net.ParseCIDR("198.51.100.0/24")
	db.badNets = []*net.IPNet{cidr}

	_, ok := db.Lookup("not-an-ip")
	if ok {
		t.Errorf("invalid IP string should not match anything")
	}
}

// --- AddPermanent / RemovePermanent (file fallback) -------------------

func TestThreatDBAddPermanentFileFallback(t *testing.T) {
	db := newTestThreatDB(t)

	db.AddPermanent("203.0.113.5", "bruteforce ssh")

	if src, ok := db.Lookup("203.0.113.5"); !ok || src != "bruteforce ssh" {
		t.Errorf("in-memory lookup after add = (%q, %v)", src, ok)
	}

	data, err := os.ReadFile(filepath.Join(db.dbPath, "permanent.txt"))
	if err != nil {
		t.Fatalf("permanent.txt not written: %v", err)
	}
	if !strings.Contains(string(data), "203.0.113.5") {
		t.Errorf("permanent.txt does not contain IP: %q", data)
	}
	if !strings.Contains(string(data), "bruteforce ssh") {
		t.Errorf("permanent.txt does not contain reason: %q", data)
	}
}

func TestThreatDBAddPermanentDedupesExisting(t *testing.T) {
	db := newTestThreatDB(t)
	db.AddPermanent("203.0.113.5", "first reason")
	db.AddPermanent("203.0.113.5", "second reason")

	data, _ := os.ReadFile(filepath.Join(db.dbPath, "permanent.txt"))
	// Dedup path returns before writing, so only the first AddPermanent
	// persists — file should contain a single line with the first reason.
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 persisted line, got %d: %v", len(lines), lines)
	}
	// In-memory value should be updated to the latest reason, though.
	if src, _ := db.Lookup("203.0.113.5"); src != "second reason" {
		t.Errorf("in-memory reason = %q, want second reason", src)
	}
}

func TestThreatDBRemovePermanentFileFallback(t *testing.T) {
	db := newTestThreatDB(t)
	db.AddPermanent("203.0.113.5", "r1")
	db.AddPermanent("203.0.113.6", "r2")
	db.AddPermanent("203.0.113.7", "r3")

	db.RemovePermanent("203.0.113.6")

	// In-memory gone
	if _, ok := db.Lookup("203.0.113.6"); ok {
		t.Errorf("removed IP still in memory")
	}
	// File rewritten without the removed IP
	data, _ := os.ReadFile(filepath.Join(db.dbPath, "permanent.txt"))
	if strings.Contains(string(data), "203.0.113.6") {
		t.Errorf("removed IP still in file: %q", data)
	}
	if !strings.Contains(string(data), "203.0.113.5") || !strings.Contains(string(data), "203.0.113.7") {
		t.Errorf("surviving IPs missing from file: %q", data)
	}
}

func TestThreatDBRemovePermanentMissingFile(t *testing.T) {
	db := newTestThreatDB(t)
	// No file written; removing should be a no-op, not a panic.
	db.badIPs["203.0.113.5"] = "test"
	db.RemovePermanent("203.0.113.5")
	if _, ok := db.Lookup("203.0.113.5"); ok {
		t.Errorf("in-memory entry not removed")
	}
}

// --- Whitelist operations --------------------------------------------

func TestThreatDBAddWhitelistPermanent(t *testing.T) {
	db := newTestThreatDB(t)
	db.badIPs["203.0.113.5"] = "test"

	db.AddWhitelist("203.0.113.5")

	// Whitelist wins over badIPs — also AddWhitelist deletes from badIPs.
	if _, ok := db.Lookup("203.0.113.5"); ok {
		t.Errorf("whitelisted IP should not be reported as bad")
	}
	if db.badIPs["203.0.113.5"] != "" {
		t.Errorf("AddWhitelist did not delete from badIPs")
	}

	// Persisted to file.
	data, err := os.ReadFile(filepath.Join(db.dbPath, "whitelist.txt"))
	if err != nil {
		t.Fatalf("whitelist.txt not written: %v", err)
	}
	if !strings.Contains(string(data), "203.0.113.5 permanent") {
		t.Errorf("whitelist.txt missing expected line: %q", data)
	}
}

func TestThreatDBTempWhitelistTTL(t *testing.T) {
	db := newTestThreatDB(t)
	db.TempWhitelist("203.0.113.5", 1*time.Hour)

	entry := db.whitelistMeta["203.0.113.5"]
	if entry == nil {
		t.Fatal("TempWhitelist did not store metadata")
	}
	if entry.ExpiresAt.IsZero() {
		t.Error("TempWhitelist should set ExpiresAt")
	}
	if time.Until(entry.ExpiresAt) > 1*time.Hour+time.Minute {
		t.Errorf("expiry too far out: %v", entry.ExpiresAt)
	}

	// File encoded with expires=...
	data, _ := os.ReadFile(filepath.Join(db.dbPath, "whitelist.txt"))
	if !strings.Contains(string(data), "expires=") {
		t.Errorf("whitelist.txt should encode expires=: %q", data)
	}
}

func TestThreatDBRemoveWhitelist(t *testing.T) {
	db := newTestThreatDB(t)
	db.AddWhitelist("203.0.113.5")
	db.AddWhitelist("203.0.113.6")

	db.RemoveWhitelist("203.0.113.5")
	if db.whitelist["203.0.113.5"] {
		t.Error("removed IP still whitelisted in memory")
	}
	if !db.whitelist["203.0.113.6"] {
		t.Error("unrelated IP was also removed")
	}

	// File rewritten without the removed IP.
	data, _ := os.ReadFile(filepath.Join(db.dbPath, "whitelist.txt"))
	if strings.Contains(string(data), "203.0.113.5") {
		t.Errorf("removed IP still in file: %q", data)
	}
}

func TestThreatDBPruneExpiredWhitelist(t *testing.T) {
	db := newTestThreatDB(t)
	// Permanent entry — must survive.
	db.AddWhitelist("203.0.113.1")
	// Expired temp entry — must be pruned.
	db.whitelist["203.0.113.2"] = true
	db.whitelistMeta["203.0.113.2"] = &whitelistEntry{ExpiresAt: time.Now().Add(-1 * time.Minute)}
	// Future temp entry — must survive.
	db.whitelist["203.0.113.3"] = true
	db.whitelistMeta["203.0.113.3"] = &whitelistEntry{ExpiresAt: time.Now().Add(1 * time.Hour)}

	pruned := db.PruneExpiredWhitelist()
	if pruned != 1 {
		t.Errorf("pruned = %d, want 1", pruned)
	}
	if !db.whitelist["203.0.113.1"] {
		t.Error("permanent entry pruned by mistake")
	}
	if db.whitelist["203.0.113.2"] {
		t.Error("expired entry not pruned")
	}
	if !db.whitelist["203.0.113.3"] {
		t.Error("unexpired temp entry pruned by mistake")
	}
}

func TestThreatDBPruneExpiredWhitelistNoop(t *testing.T) {
	db := newTestThreatDB(t)
	db.AddWhitelist("203.0.113.1")
	if got := db.PruneExpiredWhitelist(); got != 0 {
		t.Errorf("no expired entries should return 0, got %d", got)
	}
}

func TestThreatDBWhitelistedIPs(t *testing.T) {
	db := newTestThreatDB(t)
	db.AddWhitelist("203.0.113.3")
	db.AddWhitelist("203.0.113.1")
	db.TempWhitelist("203.0.113.2", 1*time.Hour)

	list := db.WhitelistedIPs()
	if len(list) != 3 {
		t.Fatalf("got %d, want 3", len(list))
	}
	// Sorted order
	want := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}
	for i, w := range want {
		if list[i].IP != w {
			t.Errorf("index %d: got %q, want %q", i, list[i].IP, w)
		}
	}
	// 203.0.113.2 is the temp one
	if list[1].Permanent {
		t.Errorf("index 1 should be temporary")
	}
	if list[1].ExpiresAt == nil {
		t.Errorf("temp entry should have ExpiresAt set")
	}
	if !list[0].Permanent || !list[2].Permanent {
		t.Errorf("permanent entries should be marked Permanent=true")
	}
}

// --- saveWhitelistFile / loadPersistedWhitelist round-trip ------------

func TestThreatDBWhitelistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	db := &ThreatDB{
		badIPs:        make(map[string]string),
		whitelist:     make(map[string]bool),
		whitelistMeta: make(map[string]*whitelistEntry),
		dbPath:        dir,
	}
	db.AddWhitelist("203.0.113.1")
	db.TempWhitelist("203.0.113.2", 2*time.Hour)

	// Fresh DB reading the same file.
	db2 := &ThreatDB{
		badIPs:        make(map[string]string),
		whitelist:     make(map[string]bool),
		whitelistMeta: make(map[string]*whitelistEntry),
		dbPath:        dir,
	}
	db2.loadPersistedWhitelist()

	if !db2.whitelist["203.0.113.1"] {
		t.Error("permanent entry not reloaded")
	}
	if !db2.whitelist["203.0.113.2"] {
		t.Error("temp entry not reloaded")
	}
	if meta := db2.whitelistMeta["203.0.113.2"]; meta == nil || meta.ExpiresAt.IsZero() {
		t.Error("temp entry expiry not reloaded")
	}
	if meta := db2.whitelistMeta["203.0.113.1"]; meta == nil || !meta.ExpiresAt.IsZero() {
		t.Error("permanent entry should have zero ExpiresAt")
	}
}

func TestThreatDBLoadPersistedWhitelistSkipsExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.txt")
	// Write by hand: one permanent, one expired, one future.
	content := "203.0.113.1 permanent\n" +
		"203.0.113.2 expires=" + time.Now().Add(-1*time.Hour).Format(time.RFC3339) + "\n" +
		"203.0.113.3 expires=" + time.Now().Add(1*time.Hour).Format(time.RFC3339) + "\n" +
		"# comment\n" +
		"\n" +
		"not-an-ip\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	db := &ThreatDB{
		badIPs:    make(map[string]string),
		whitelist: make(map[string]bool),
		dbPath:    dir,
	}
	db.loadPersistedWhitelist()

	if !db.whitelist["203.0.113.1"] {
		t.Error("permanent entry not loaded")
	}
	if db.whitelist["203.0.113.2"] {
		t.Error("expired entry should have been skipped")
	}
	if !db.whitelist["203.0.113.3"] {
		t.Error("future entry not loaded")
	}
	if db.whitelist["not-an-ip"] {
		t.Error("invalid IP should be skipped")
	}
}

func TestThreatDBLoadPersistedWhitelistMissingFile(t *testing.T) {
	db := &ThreatDB{
		badIPs:    make(map[string]string),
		whitelist: make(map[string]bool),
		dbPath:    t.TempDir(),
	}
	// Should not panic.
	db.loadPersistedWhitelist()
	if len(db.whitelist) != 0 {
		t.Errorf("empty load should leave whitelist empty, got %v", db.whitelist)
	}
}

// --- Count / Stats / FeedsStale ---------------------------------------

func TestThreatDBCount(t *testing.T) {
	db := newTestThreatDB(t)
	db.badIPs["203.0.113.1"] = "a"
	db.badIPs["203.0.113.2"] = "b"
	_, cidr, _ := net.ParseCIDR("198.51.100.0/24")
	db.badNets = []*net.IPNet{cidr}

	if got := db.Count(); got != 3 {
		t.Errorf("Count = %d, want 3", got)
	}
}

func TestThreatDBStats(t *testing.T) {
	db := newTestThreatDB(t)
	db.badIPs["203.0.113.1"] = "a"
	db.whitelist["203.0.113.9"] = true
	db.PermanentCount = 5
	db.FeedIPCount = 100
	db.FeedNetCount = 20
	db.LastFeedUpdate = time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)

	s := db.Stats()
	if s["permanent_ips"].(int) != 5 {
		t.Errorf("permanent_ips = %v", s["permanent_ips"])
	}
	if s["feed_ips"].(int) != 100 {
		t.Errorf("feed_ips = %v", s["feed_ips"])
	}
	if s["feed_cidrs"].(int) != 20 {
		t.Errorf("feed_cidrs = %v", s["feed_cidrs"])
	}
	if s["total"].(int) != 1 {
		t.Errorf("total = %v", s["total"])
	}
	if s["whitelist"].(int) != 1 {
		t.Errorf("whitelist = %v", s["whitelist"])
	}
	if !strings.HasPrefix(s["last_update"].(string), "2026-04-01") {
		t.Errorf("last_update = %v", s["last_update"])
	}
}

func TestThreatDBFeedsStaleZeroTime(t *testing.T) {
	db := newTestThreatDB(t)
	// Both zero → stale.
	if !db.FeedsStale() {
		t.Error("uninitialized feeds should be stale")
	}
}

func TestThreatDBFeedsStaleRecent(t *testing.T) {
	db := newTestThreatDB(t)
	db.LastUpdated = time.Now().Add(-1 * time.Hour)
	if db.FeedsStale() {
		t.Error("recently updated feeds should not be stale")
	}
}

func TestThreatDBFeedsStaleOldLastUpdated(t *testing.T) {
	db := newTestThreatDB(t)
	db.LastUpdated = time.Now().Add(-8 * 24 * time.Hour)
	if !db.FeedsStale() {
		t.Error("8-day-old feeds should be stale")
	}
}

func TestThreatDBFeedsStaleLegacyLastUpdate(t *testing.T) {
	db := newTestThreatDB(t)
	// LastUpdated zero, lastUpdate recent → not stale.
	db.lastUpdate = time.Now().Add(-1 * time.Hour)
	if db.FeedsStale() {
		t.Error("recent lastUpdate should not be stale when LastUpdated is zero")
	}
}

// --- loadPermanentBlocklist -------------------------------------------

func TestThreatDBLoadPermanentBlocklistFileFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "permanent.txt")
	content := "# header\n" +
		"203.0.113.1 # reason one\n" +
		"203.0.113.2 # reason two\n" +
		"203.0.113.1 # dup dropped\n" +
		"\n" +
		"not-an-ip\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	db := &ThreatDB{
		badIPs:    make(map[string]string),
		whitelist: make(map[string]bool),
		dbPath:    dir,
	}
	db.loadPermanentBlocklist()

	if db.badIPs["203.0.113.1"] != "permanent-blocklist" {
		t.Errorf("first IP not loaded as permanent-blocklist, got %q", db.badIPs["203.0.113.1"])
	}
	if db.badIPs["203.0.113.2"] != "permanent-blocklist" {
		t.Errorf("second IP not loaded")
	}
	if db.PermanentCount != 2 {
		t.Errorf("PermanentCount = %d, want 2", db.PermanentCount)
	}
}

func TestThreatDBLoadPermanentBlocklistMissingFile(t *testing.T) {
	db := &ThreatDB{
		badIPs: make(map[string]string),
		dbPath: t.TempDir(),
	}
	db.loadPermanentBlocklist()
	if db.PermanentCount != 0 {
		t.Errorf("PermanentCount should be 0 for missing file, got %d", db.PermanentCount)
	}
}

// --- loadFeedCache ----------------------------------------------------

func TestThreatDBLoadFeedCacheReadsTimestampAndFeeds(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 4, 10, 9, 0, 0, 0, time.UTC).Format(time.RFC3339)
	if err := os.WriteFile(filepath.Join(dir, "last_update"), []byte(ts), 0600); err != nil {
		t.Fatalf("write last_update: %v", err)
	}
	// Write a cache file for the first real feed name so loadFeedCache picks it up.
	feedName := threatFeeds[0].name
	saveLines(filepath.Join(dir, feedName+".txt"), []string{"203.0.113.50", "203.0.113.51"})

	db := &ThreatDB{
		badIPs: make(map[string]string),
		dbPath: dir,
	}
	db.loadFeedCache()

	if db.LastUpdated.IsZero() {
		t.Error("LastUpdated not set from last_update file")
	}
	if src, ok := db.badIPs["203.0.113.50"]; !ok || src != feedName {
		t.Errorf("feed IP not loaded with source %q, got %q", feedName, src)
	}
	if db.FeedIPCount != 2 {
		t.Errorf("FeedIPCount = %d, want 2", db.FeedIPCount)
	}
}

func TestThreatDBLoadFeedCacheEmptyDir(t *testing.T) {
	// No last_update, no cache files — should not panic, leave zeros.
	db := &ThreatDB{
		badIPs: make(map[string]string),
		dbPath: t.TempDir(),
	}
	db.loadFeedCache()
	if !db.LastUpdated.IsZero() {
		t.Error("LastUpdated should remain zero")
	}
	if db.FeedIPCount != 0 {
		t.Errorf("FeedIPCount = %d, want 0", db.FeedIPCount)
	}
}
