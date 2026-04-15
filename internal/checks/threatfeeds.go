package checks

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// ThreatDB is a local IP reputation database built from:
// 1. CSM's own block history (permanent)
// 2. Public threat intelligence feeds (updated daily)
// 3. AbuseIPDB as fallback for unknown IPs
type ThreatDB struct {
	mu            sync.RWMutex
	badIPs        map[string]string          // ip -> source/reason
	badNets       []*net.IPNet               // CIDR ranges from feeds
	whitelist     map[string]bool            // IPs to never flag
	whitelistMeta map[string]*whitelistEntry // expiry metadata
	lastUpdate    time.Time
	dbPath        string

	// Stats for WebUI
	PermanentCount int
	FeedIPCount    int
	FeedNetCount   int
	LastFeedUpdate time.Time
	LastUpdated    time.Time // tracks when feeds were last successfully loaded
}

var (
	globalThreatDB *ThreatDB
	threatDBOnce   sync.Once
)

// Minimum expected entries per feed - alerts if feed returns less (corrupted/down)
var feedMinEntries = map[string]int{
	"spamhaus-drop":  50,
	"spamhaus-edrop": 10,
	"blocklist-de":   1000,
	"cins-army":      5000,
}

// Free public threat intelligence feeds
var threatFeeds = []struct {
	name string
	url  string
}{
	{"spamhaus-drop", "https://www.spamhaus.org/drop/drop.txt"},
	{"spamhaus-edrop", "https://www.spamhaus.org/drop/edrop.txt"},
	{"blocklist-de", "https://lists.blocklist.de/lists/all.txt"},
	{"cins-army", "https://cinsscore.com/list/ci-badguys.txt"},
}

// InitThreatDB initializes the global threat database.
func InitThreatDB(statePath string, whitelistIPs []string) *ThreatDB {
	threatDBOnce.Do(func() {
		wl := make(map[string]bool)
		for _, ip := range whitelistIPs {
			wl[ip] = true
		}

		db := &ThreatDB{
			badIPs:    make(map[string]string),
			whitelist: wl,
			dbPath:    filepath.Join(statePath, "threat_db"),
		}
		_ = os.MkdirAll(db.dbPath, 0700)
		db.loadPermanentBlocklist()
		db.loadPersistedWhitelist()
		db.loadFeedCache()
		globalThreatDB = db
	})
	return globalThreatDB
}

// GetThreatDB returns the global threat database.
func GetThreatDB() *ThreatDB {
	return globalThreatDB
}

// Lookup checks if an IP is in the local threat database.
// Returns (source, true) if found, ("", false) if unknown.
// Whitelisted IPs always return false.
func (db *ThreatDB) Lookup(ip string) (string, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// Never flag whitelisted IPs
	if db.whitelist[ip] {
		return "", false
	}

	// Check exact IP match
	if source, ok := db.badIPs[ip]; ok {
		return source, true
	}

	// Check CIDR ranges (supports both IPv4 and IPv6)
	parsed := net.ParseIP(ip)
	if parsed != nil {
		for _, cidr := range db.badNets {
			if cidr.Contains(parsed) {
				return "threat-feed-cidr", true
			}
		}
	}

	return "", false
}

// AddPermanent adds an IP to the permanent local blocklist.
// Called when CSM auto-blocks an IP - persists across restarts.
func (db *ThreatDB) AddPermanent(ip, reason string) {
	db.mu.Lock()
	_, exists := db.badIPs[ip]
	db.badIPs[ip] = reason
	db.mu.Unlock()

	// Only persist if this is a new IP (dedup)
	if exists {
		return
	}

	if sdb := store.Global(); sdb != nil {
		_ = sdb.AddPermanentBlock(ip, reason)
		return
	}

	// Fallback: flat-file permanent.txt.
	f, err := os.OpenFile(filepath.Join(db.dbPath, "permanent.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	fmt.Fprintf(f, "%s # %s [%s]\n", ip, reason, time.Now().Format("2006-01-02"))
}

// RemovePermanent removes an IP from the permanent blocklist and in-memory DB.
func (db *ThreatDB) RemovePermanent(ip string) {
	db.mu.Lock()
	delete(db.badIPs, ip)
	db.mu.Unlock()

	if sdb := store.Global(); sdb != nil {
		_ = sdb.RemovePermanentBlock(ip)
		return
	}

	// Fallback: rewrite permanent.txt without this IP.
	path := filepath.Join(db.dbPath, "permanent.txt")
	data, err := osFS.ReadFile(path)
	if err != nil {
		return
	}
	var kept []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			kept = append(kept, line)
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) > 0 && fields[0] == ip {
			continue // skip this IP
		}
		kept = append(kept, line)
	}
	tmpPath := path + ".tmp"
	_ = os.WriteFile(tmpPath, []byte(strings.Join(kept, "\n")+"\n"), 0600)
	_ = os.Rename(tmpPath, path)
}

// whitelistEntry tracks an IP with optional expiry.
type whitelistEntry struct {
	ExpiresAt time.Time // zero = permanent
}

// AddWhitelist adds an IP to the permanent whitelist.
func (db *ThreatDB) AddWhitelist(ip string) {
	db.addWhitelistEntry(ip, time.Time{})
}

// TempWhitelist adds an IP to the whitelist with a TTL.
func (db *ThreatDB) TempWhitelist(ip string, ttl time.Duration) {
	db.addWhitelistEntry(ip, time.Now().Add(ttl))
}

func (db *ThreatDB) addWhitelistEntry(ip string, expiresAt time.Time) {
	db.mu.Lock()
	db.whitelist[ip] = true
	if db.whitelistMeta == nil {
		db.whitelistMeta = make(map[string]*whitelistEntry)
	}
	db.whitelistMeta[ip] = &whitelistEntry{ExpiresAt: expiresAt}
	delete(db.badIPs, ip)
	db.mu.Unlock()

	if sdb := store.Global(); sdb != nil {
		permanent := expiresAt.IsZero()
		_ = sdb.AddWhitelistEntry(ip, expiresAt, permanent)
		return
	}

	db.saveWhitelistFile()
}

// RemoveWhitelist removes an IP from the whitelist.
func (db *ThreatDB) RemoveWhitelist(ip string) {
	db.mu.Lock()
	delete(db.whitelist, ip)
	delete(db.whitelistMeta, ip)
	db.mu.Unlock()

	if sdb := store.Global(); sdb != nil {
		_ = sdb.RemoveWhitelistEntry(ip)
		return
	}

	db.saveWhitelistFile()
}

// PruneExpiredWhitelist removes expired temporary whitelist entries.
// Called periodically from the daemon heartbeat.
func (db *ThreatDB) PruneExpiredWhitelist() int {
	now := time.Now()
	pruned := 0
	db.mu.Lock()
	for ip, entry := range db.whitelistMeta {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			delete(db.whitelist, ip)
			delete(db.whitelistMeta, ip)
			pruned++
		}
	}
	db.mu.Unlock()

	if pruned > 0 {
		if sdb := store.Global(); sdb != nil {
			sdb.PruneExpiredWhitelist()
		} else {
			db.saveWhitelistFile()
		}
		fmt.Fprintf(os.Stderr, "[%s] Pruned %d expired whitelist entries\n",
			time.Now().Format("2006-01-02 15:04:05"), pruned)
	}
	return pruned
}

// WhitelistInfo returns all whitelisted IPs with their expiry info.
type WhitelistIP struct {
	IP        string     `json:"ip"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // nil = permanent
	Permanent bool       `json:"permanent"`
}

func (db *ThreatDB) WhitelistedIPs() []WhitelistIP {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var ips []string
	for ip := range db.whitelist {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	result := make([]WhitelistIP, len(ips))
	for i, ip := range ips {
		entry := db.whitelistMeta[ip]
		w := WhitelistIP{IP: ip, Permanent: true}
		if entry != nil && !entry.ExpiresAt.IsZero() {
			t := entry.ExpiresAt
			w.ExpiresAt = &t
			w.Permanent = false
		}
		result[i] = w
	}
	return result
}

func (db *ThreatDB) saveWhitelistFile() {
	path := filepath.Join(db.dbPath, "whitelist.txt")
	db.mu.RLock()
	var lines []string
	for ip := range db.whitelist {
		entry := db.whitelistMeta[ip]
		if entry != nil && !entry.ExpiresAt.IsZero() {
			lines = append(lines, fmt.Sprintf("%s expires=%s", ip, entry.ExpiresAt.Format(time.RFC3339)))
		} else {
			lines = append(lines, fmt.Sprintf("%s permanent", ip))
		}
	}
	db.mu.RUnlock()

	sort.Strings(lines)
	tmpPath := path + ".tmp"
	_ = os.WriteFile(tmpPath, []byte(strings.Join(lines, "\n")+"\n"), 0600)
	_ = os.Rename(tmpPath, path)
}

// loadPersistedWhitelist loads IPs from the bbolt store (if available)
// or from the flat-file whitelist.txt.
func (db *ThreatDB) loadPersistedWhitelist() {
	if db.whitelistMeta == nil {
		db.whitelistMeta = make(map[string]*whitelistEntry)
	}

	if sdb := store.Global(); sdb != nil {
		entries := sdb.ListWhitelist()
		now := time.Now()
		for _, e := range entries {
			// Skip expired entries
			if !e.Permanent && !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt) {
				continue
			}
			db.whitelist[e.IP] = true
			db.whitelistMeta[e.IP] = &whitelistEntry{ExpiresAt: e.ExpiresAt}
			delete(db.badIPs, e.IP)
		}
		return
	}

	// Fallback: flat-file whitelist.txt.
	path := filepath.Join(db.dbPath, "whitelist.txt")
	f, err := osFS.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	now := time.Now()
	needsRewrite := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		ip := fields[0]
		if net.ParseIP(ip) == nil {
			continue
		}

		entry := &whitelistEntry{}
		// Parse "expires=2026-03-28T19:00:00Z" if present
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "expires=") {
				if t, err := time.Parse(time.RFC3339, f[8:]); err == nil {
					entry.ExpiresAt = t
				}
			}
		}

		// Skip expired entries
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			needsRewrite = true
			continue
		}

		db.whitelist[ip] = true
		db.whitelistMeta[ip] = entry
		delete(db.badIPs, ip)
	}

	if needsRewrite {
		// Synchronous: the load path runs once at startup, so the cost
		// is negligible, and a fire-and-forget goroutine would race the
		// daemon's shutdown (potentially leaving a `.tmp` file behind or
		// writing a half-serialized whitelist.txt if the process is
		// killed before the rewrite lands).
		db.saveWhitelistFile()
	}
}

// Count returns the total number of entries in the database.
func (db *ThreatDB) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.badIPs) + len(db.badNets)
}

// Stats returns statistics for the WebUI dashboard.
func (db *ThreatDB) Stats() map[string]interface{} {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return map[string]interface{}{
		"permanent_ips": db.PermanentCount,
		"feed_ips":      db.FeedIPCount,
		"feed_cidrs":    db.FeedNetCount,
		"total":         len(db.badIPs) + len(db.badNets),
		"whitelist":     len(db.whitelist),
		"last_update":   db.LastFeedUpdate.Format(time.RFC3339),
	}
}

// FeedsStale returns true if threat feeds have not been updated in over 7 days.
func (db *ThreatDB) FeedsStale() bool {
	db.mu.RLock()
	defer db.mu.RUnlock()
	if db.LastUpdated.IsZero() {
		return db.lastUpdate.IsZero() || time.Since(db.lastUpdate) > 7*24*time.Hour
	}
	return time.Since(db.LastUpdated) > 7*24*time.Hour
}

// UpdateFeeds downloads fresh threat intelligence feeds.
// Downloads outside the lock, then swaps data under lock to avoid blocking lookups.
func (db *ThreatDB) UpdateFeeds() error {
	db.mu.RLock()
	lastUpdate := db.lastUpdate
	db.mu.RUnlock()

	// Only update once per day
	if time.Since(lastUpdate) < 20*time.Hour {
		return nil
	}

	client := &http.Client{Timeout: 30 * time.Second}

	// Download all feeds OUTSIDE the lock
	newIPs := make(map[string]string)
	var newNets []*net.IPNet
	totalIPs := 0
	totalNets := 0

	for _, feed := range threatFeeds {
		ips, nets, err := downloadFeed(client, feed.url, feed.name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "threatdb: error downloading %s: %v\n", feed.name, err)
			continue
		}

		// Validate feed - reject partial downloads to avoid losing good data
		minExpected := feedMinEntries[feed.name]
		if minExpected > 0 && len(ips)+len(nets) < minExpected {
			fmt.Fprintf(os.Stderr, "threatdb: WARNING %s returned only %d entries (expected >%d), keeping cached version\n",
				feed.name, len(ips)+len(nets), minExpected)
			continue // keep previous cached data for this feed
		}

		for _, ip := range ips {
			newIPs[ip] = feed.name
		}
		newNets = append(newNets, nets...)
		totalIPs += len(ips)
		totalNets += len(nets)

		// Cache to disk
		cachePath := filepath.Join(db.dbPath, feed.name+".txt")
		saveLines(cachePath, ips)
	}

	// Swap data UNDER the lock - fast operation
	db.mu.Lock()
	// Clear old feed data but keep permanent entries
	for ip, source := range db.badIPs {
		if source == "permanent-blocklist" {
			continue
		}
		// Check if it's a feed entry (not permanent)
		isPermanent := source == "permanent-blocklist"
		if !isPermanent {
			delete(db.badIPs, ip)
		}
	}
	// Add new feed data
	for ip, source := range newIPs {
		if _, isPermanent := db.badIPs[ip]; !isPermanent {
			db.badIPs[ip] = source
		}
	}
	// Replace CIDR ranges entirely (fixes accumulation bug)
	db.badNets = newNets
	now := time.Now()
	db.lastUpdate = now
	db.FeedIPCount = totalIPs
	db.FeedNetCount = totalNets
	db.LastFeedUpdate = now
	db.LastUpdated = now
	db.mu.Unlock()

	// Save timestamp
	_ = os.WriteFile(filepath.Join(db.dbPath, "last_update"),
		[]byte(db.lastUpdate.Format(time.RFC3339)), 0600)

	fmt.Fprintf(os.Stderr, "threatdb: updated %d IPs + %d CIDR ranges from %d feeds\n",
		totalIPs, totalNets, len(threatFeeds))

	return nil
}

// loadPermanentBlocklist loads the permanent blocklist from bbolt store
// (if available) or from the flat-file permanent.txt.
func (db *ThreatDB) loadPermanentBlocklist() {
	if sdb := store.Global(); sdb != nil {
		blocks := sdb.AllPermanentBlocks()
		for _, b := range blocks {
			db.badIPs[b.IP] = "permanent-blocklist"
		}
		db.PermanentCount = len(blocks)
		return
	}

	// Fallback: flat-file permanent.txt.
	path := filepath.Join(db.dbPath, "permanent.txt")
	f, err := osFS.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip := strings.Fields(line)[0]
		// Support both IPv4 and IPv6
		if net.ParseIP(ip) != nil && !seen[ip] {
			db.badIPs[ip] = "permanent-blocklist"
			seen[ip] = true
		}
	}
	db.PermanentCount = len(seen)

	// Compact the file if it has duplicates (rewrite with unique entries)
	if db.PermanentCount > 0 {
		compactPermanentFile(path, seen)
	}
}

// compactPermanentFile rewrites the permanent blocklist with unique entries only.
func compactPermanentFile(path string, uniqueIPs map[string]bool) {
	// Read all lines to preserve comments/reasons
	data, err := osFS.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) <= len(uniqueIPs)+5 {
		return // not worth compacting - minimal duplicates
	}

	// Rewrite with deduplication
	seen := make(map[string]bool)
	var unique []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			unique = append(unique, line)
			continue
		}
		ip := strings.Fields(trimmed)[0]
		if !seen[ip] {
			seen[ip] = true
			unique = append(unique, line)
		}
	}

	tmpPath := path + ".tmp"
	_ = os.WriteFile(tmpPath, []byte(strings.Join(unique, "\n")+"\n"), 0600)
	_ = os.Rename(tmpPath, path)
}

// loadFeedCache loads cached feed data from disk.
func (db *ThreatDB) loadFeedCache() {
	data, err := osFS.ReadFile(filepath.Join(db.dbPath, "last_update"))
	if err == nil {
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data))); err == nil {
			db.lastUpdate = t
			db.LastFeedUpdate = t
			db.LastUpdated = t
		}
	}

	for _, feed := range threatFeeds {
		cachePath := filepath.Join(db.dbPath, feed.name+".txt")
		lines := loadLines(cachePath)
		for _, ip := range lines {
			db.badIPs[ip] = feed.name
		}
		db.FeedIPCount += len(lines)
	}

	// Warn on startup if feeds are stale
	if db.LastUpdated.IsZero() && db.FeedIPCount == 0 {
		fmt.Fprintf(os.Stderr, "threatdb: WARNING no threat feed data loaded, feeds have never been fetched\n")
	} else if !db.LastUpdated.IsZero() && time.Since(db.LastUpdated) > 7*24*time.Hour {
		fmt.Fprintf(os.Stderr, "threatdb: WARNING threat feeds are stale (last updated %s, %d days ago)\n",
			db.LastUpdated.Format("2006-01-02"), int(time.Since(db.LastUpdated).Hours()/24))
	}
}

func downloadFeed(client *http.Client, url, name string) ([]string, []*net.IPNet, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, 10*1024*1024)
	scanner := bufio.NewScanner(limited)

	var ips []string
	var nets []*net.IPNet

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if idx := strings.IndexAny(line, ";#"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}

		if strings.Contains(line, "/") {
			_, cidr, err := net.ParseCIDR(line)
			if err == nil {
				nets = append(nets, cidr)
			}
			continue
		}

		ip := strings.Fields(line)[0]
		if net.ParseIP(ip) != nil {
			ips = append(ips, ip)
		}
	}

	return ips, nets, nil
}

func saveLines(path string, lines []string) {
	sort.Strings(lines) // sorted for diffing
	// #nosec G304 -- path is filepath.Join under operator-configured statePath.
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	w := bufio.NewWriter(f)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	_ = w.Flush()
}

func loadLines(path string) []string {
	f, err := osFS.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}
