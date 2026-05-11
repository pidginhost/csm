package challenge

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultMapPath is the webserver-readable Apache / LSWS RewriteMap.
// It lives under /run rather than state_path because state_path is mode
// 0700 and must stay private to CSM's bbolt database.
const DefaultMapPath = "/run/csm/challenge_ips.txt"

// challengeEntry stores the challenge metadata for a single IP.
type challengeEntry struct {
	ExpiresAt time.Time
	Reason    string
}

// ExpiredEntry is returned by ExpiredEntries for escalation.
type ExpiredEntry struct {
	IP     string
	Reason string
}

// IPList manages the set of IPs that should see challenge pages.
// Apache RewriteMap reads the file to redirect IPs to the challenge server.
type IPList struct {
	path string
	ips  map[string]challengeEntry
	mu   sync.Mutex
}

// NewIPList creates an IP list writer.
func NewIPList(statePath string) *IPList {
	return NewIPListWithMapPath(statePath, filepath.Join(statePath, "challenge_ips.txt"))
}

// NewIPListWithMapPath creates an IP list writer with an explicit
// webserver-facing map path.
func NewIPListWithMapPath(statePath, mapPath string) *IPList {
	if strings.TrimSpace(mapPath) == "" {
		mapPath = filepath.Join(statePath, "challenge_ips.txt")
	}
	l := &IPList{
		path: mapPath,
		ips:  make(map[string]challengeEntry),
	}
	l.flush()
	return l
}

// Add marks an IP for challenge with the given reason.
func (l *IPList) Add(ip string, reason string, duration time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ips[ip] = challengeEntry{
		ExpiresAt: time.Now().Add(duration),
		Reason:    reason,
	}
	l.flush()
}

// Remove stops challenging an IP (passed or manually removed).
func (l *IPList) Remove(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.ips, ip)
	l.flush()
}

// Contains returns true if the IP is currently on the challenge list.
func (l *IPList) Contains(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.ips[ip]
	return ok
}

// ExpiredEntries removes and returns all expired entries for escalation.
// The caller is expected to hard-block these IPs.
func (l *IPList) ExpiredEntries() []ExpiredEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	var expired []ExpiredEntry
	for ip, entry := range l.ips {
		if now.After(entry.ExpiresAt) {
			expired = append(expired, ExpiredEntry{IP: ip, Reason: entry.Reason})
			delete(l.ips, ip)
		}
	}
	if len(expired) > 0 {
		l.flush()
	}
	return expired
}

// CleanExpired removes expired entries without returning them.
// Use ExpiredEntries() instead when escalation is needed.
func (l *IPList) CleanExpired() {
	_ = l.ExpiredEntries()
}

// flush writes the IP list to disk in Apache RewriteMap txt format.
// Format: "IP challenge" per line.
func (l *IPList) flush() {
	var sb strings.Builder
	sb.WriteString("# CSM Challenge IP list - auto-generated, do not edit\n")
	sb.WriteString("# Format: IP challenge (for Apache RewriteMap)\n")
	for ip := range l.ips {
		fmt.Fprintf(&sb, "%s challenge\n", ip)
	}

	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return
	}
	tmpPath := l.path + ".tmp"
	// #nosec G306 -- Apache uses this file as a RewriteMap source; it has
	// to be readable by the webserver user. No sensitive data; only a
	// list of IPs that must re-solve the PoW challenge.
	if err := os.WriteFile(tmpPath, []byte(sb.String()), 0644); err != nil {
		return
	}
	_ = os.Rename(tmpPath, l.path)
}
