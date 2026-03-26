package checks

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ThreatDB is a local IP reputation database built from:
// 1. CSM's own block history (permanent)
// 2. Public threat intelligence feeds (updated daily)
// 3. AbuseIPDB as fallback for unknown IPs
type ThreatDB struct {
	mu         sync.RWMutex
	badIPs     map[string]string // ip -> source/reason
	badNets    []*net.IPNet      // CIDR ranges from feeds
	lastUpdate time.Time
	dbPath     string
}

var (
	globalThreatDB *ThreatDB
	threatDBOnce   sync.Once
)

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
func InitThreatDB(statePath string) *ThreatDB {
	threatDBOnce.Do(func() {
		db := &ThreatDB{
			badIPs: make(map[string]string),
			dbPath: filepath.Join(statePath, "threat_db"),
		}
		_ = os.MkdirAll(db.dbPath, 0700)
		db.loadPermanentBlocklist()
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
func (db *ThreatDB) Lookup(ip string) (string, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// Check exact IP match
	if source, ok := db.badIPs[ip]; ok {
		return source, true
	}

	// Check CIDR ranges
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
// Called when CSM auto-blocks an IP — persists across restarts.
func (db *ThreatDB) AddPermanent(ip, reason string) {
	db.mu.Lock()
	db.badIPs[ip] = reason
	db.mu.Unlock()

	// Append to permanent file
	f, err := os.OpenFile(filepath.Join(db.dbPath, "permanent.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	fmt.Fprintf(f, "%s # %s [%s]\n", ip, reason, time.Now().Format("2006-01-02"))
}

// Count returns the total number of IPs in the database.
func (db *ThreatDB) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.badIPs) + len(db.badNets)
}

// UpdateFeeds downloads fresh threat intelligence feeds.
// Should be called once per day (by the deep scanner).
func (db *ThreatDB) UpdateFeeds() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Only update once per day
	if time.Since(db.lastUpdate) < 20*time.Hour {
		return nil
	}

	client := &http.Client{Timeout: 30 * time.Second}
	totalIPs := 0
	totalNets := 0

	for _, feed := range threatFeeds {
		ips, nets, err := downloadFeed(client, feed.url, feed.name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "threatdb: error downloading %s: %v\n", feed.name, err)
			continue
		}
		for _, ip := range ips {
			db.badIPs[ip] = feed.name
		}
		db.badNets = append(db.badNets, nets...)
		totalIPs += len(ips)
		totalNets += len(nets)

		// Cache to disk
		cachePath := filepath.Join(db.dbPath, feed.name+".txt")
		saveLines(cachePath, ips)
	}

	db.lastUpdate = time.Now()

	// Save timestamp
	_ = os.WriteFile(filepath.Join(db.dbPath, "last_update"),
		[]byte(db.lastUpdate.Format(time.RFC3339)), 0600)

	fmt.Fprintf(os.Stderr, "threatdb: updated %d IPs + %d CIDR ranges from %d feeds\n",
		totalIPs, totalNets, len(threatFeeds))

	return nil
}

// loadPermanentBlocklist loads the permanent local blocklist from disk.
func (db *ThreatDB) loadPermanentBlocklist() {
	path := filepath.Join(db.dbPath, "permanent.txt")
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip := strings.Fields(line)[0]
		if strings.Count(ip, ".") == 3 {
			db.badIPs[ip] = "permanent-blocklist"
		}
	}
}

// loadFeedCache loads cached feed data from disk.
func (db *ThreatDB) loadFeedCache() {
	// Check last update timestamp
	data, err := os.ReadFile(filepath.Join(db.dbPath, "last_update"))
	if err == nil {
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data))); err == nil {
			db.lastUpdate = t
		}
	}

	for _, feed := range threatFeeds {
		cachePath := filepath.Join(db.dbPath, feed.name+".txt")
		lines := loadLines(cachePath)
		for _, ip := range lines {
			db.badIPs[ip] = feed.name
		}
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

	// Limit read to 10MB
	limited := io.LimitReader(resp.Body, 10*1024*1024)
	scanner := bufio.NewScanner(limited)

	var ips []string
	var nets []*net.IPNet

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Some feeds have IP ; comment format
		if idx := strings.IndexAny(line, ";#"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Check if CIDR range
		if strings.Contains(line, "/") {
			_, cidr, err := net.ParseCIDR(line)
			if err == nil {
				nets = append(nets, cidr)
			}
			continue
		}

		// Plain IP
		ip := strings.Fields(line)[0]
		if net.ParseIP(ip) != nil {
			ips = append(ips, ip)
		}
	}

	return ips, nets, nil
}

func saveLines(path string, lines []string) {
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
	f, err := os.Open(path)
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
