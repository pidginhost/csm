package challenge

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// IPList manages the set of IPs that should see challenge pages.
// Apache RewriteMap reads the file to redirect IPs to the challenge server.
type IPList struct {
	path string
	ips  map[string]time.Time // IP -> expires at
	mu   sync.Mutex
}

// NewIPList creates an IP list writer.
func NewIPList(statePath string) *IPList {
	return &IPList{
		path: filepath.Join(statePath, "challenge_ips.txt"),
		ips:  make(map[string]time.Time),
	}
}

// Add marks an IP for challenge. The IP will see the challenge page
// instead of being hard-blocked. Duration is how long to keep challenging.
func (l *IPList) Add(ip string, duration time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ips[ip] = time.Now().Add(duration)
	l.flush()
}

// Remove stops challenging an IP (either passed or expired).
func (l *IPList) Remove(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.ips, ip)
	l.flush()
}

// CleanExpired removes expired entries.
func (l *IPList) CleanExpired() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	changed := false
	for ip, expires := range l.ips {
		if now.After(expires) {
			delete(l.ips, ip)
			changed = true
		}
	}
	if changed {
		l.flush()
	}
}

// flush writes the IP list to disk in Apache RewriteMap txt format.
// Format: "IP challenge" per line.
func (l *IPList) flush() {
	var sb strings.Builder
	sb.WriteString("# CSM Challenge IP list — auto-generated, do not edit\n")
	sb.WriteString("# Format: IP challenge (for Apache RewriteMap)\n")
	for ip := range l.ips {
		fmt.Fprintf(&sb, "%s challenge\n", ip)
	}

	tmpPath := l.path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(sb.String()), 0644); err != nil {
		return
	}
	_ = os.Rename(tmpPath, l.path)
}
