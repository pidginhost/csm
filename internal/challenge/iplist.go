package challenge

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultMapPath is the webserver-readable Apache / LSWS RewriteMap.
// It lives under /run rather than state_path because state_path is mode
// 0700 and must stay private to CSM's bbolt database.
const DefaultMapPath = "/run/csm/challenge_ips.txt"

// DefaultNginxMapPath is the webserver-readable Nginx map include.
const DefaultNginxMapPath = "/run/csm/challenge_ips.nginx.map"

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
// Webserver integrations read its maps to redirect IPs to the challenge server.
type IPList struct {
	path        string
	nginxPath   string
	nginxReload func() error
	ips         map[string]challengeEntry
	mu          sync.Mutex
	gate        PortGate
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
	_ = l.flush()
	return l
}

// SetPortGate attaches a PortGate so every Add/Remove also opens or
// closes the kernel-level allow. Nil is a no-op (callers don't have to
// branch on whether the gate is configured). Safe to call before any
// Add/Remove; not safe to swap a non-nil gate for another at runtime.
func (l *IPList) SetPortGate(g PortGate) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gate = g
}

// SetNginxMap attaches a second map writer for Nginx stacks. The
// callback runs only when the rendered include content changes.
func (l *IPList) SetNginxMap(path string, reload func() error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultNginxMapPath
	}
	l.mu.Lock()
	l.nginxPath = path
	l.nginxReload = reload
	changed := l.flush()
	l.mu.Unlock()
	l.reloadNginx(changed, reload)
}

// Add marks an IP for challenge with the given reason.
func (l *IPList) Add(ip string, reason string, duration time.Duration) {
	l.mu.Lock()
	l.ips[ip] = challengeEntry{
		ExpiresAt: time.Now().Add(duration),
		Reason:    reason,
	}
	changed := l.flush()
	gate := l.gate
	reload := l.nginxReload
	l.mu.Unlock()

	if gate != nil {
		if err := gate.Allow(ip, duration); err != nil {
			fmt.Fprintf(os.Stderr, "challenge: port-gate allow %s: %v\n", ip, err)
		}
	}
	l.reloadNginx(changed, reload)
}

// Remove stops challenging an IP (passed or manually removed).
func (l *IPList) Remove(ip string) {
	l.mu.Lock()
	delete(l.ips, ip)
	changed := l.flush()
	gate := l.gate
	reload := l.nginxReload
	l.mu.Unlock()

	if gate != nil {
		if err := gate.Revoke(ip); err != nil {
			fmt.Fprintf(os.Stderr, "challenge: port-gate revoke %s: %v\n", ip, err)
		}
	}
	l.reloadNginx(changed, reload)
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
	now := time.Now()
	var expired []ExpiredEntry
	for ip, entry := range l.ips {
		if now.After(entry.ExpiresAt) {
			expired = append(expired, ExpiredEntry{IP: ip, Reason: entry.Reason})
			delete(l.ips, ip)
		}
	}
	var changed bool
	if len(expired) > 0 {
		changed = l.flush()
	}
	reload := l.nginxReload
	l.mu.Unlock()
	l.reloadNginx(changed, reload)
	return expired
}

// CleanExpired removes expired entries without returning them.
// Use ExpiredEntries() instead when escalation is needed.
func (l *IPList) CleanExpired() {
	_ = l.ExpiredEntries()
}

// flush writes the IP list to disk in each configured webserver format.
// The caller must hold l.mu. It returns true when the Nginx include
// changed and needs a reload.
func (l *IPList) flush() bool {
	ips := sortedIPKeys(l.ips)

	var sb strings.Builder
	sb.WriteString("# CSM Challenge IP list - auto-generated, do not edit\n")
	sb.WriteString("# Format: IP challenge (for Apache RewriteMap)\n")
	for _, ip := range ips {
		fmt.Fprintf(&sb, "%s challenge\n", ip)
	}
	if err := writeMapFile(l.path, []byte(sb.String())); err != nil {
		return false
	}

	if strings.TrimSpace(l.nginxPath) == "" {
		return false
	}

	var nginx strings.Builder
	nginx.WriteString("# CSM Challenge IP list - auto-generated, do not edit\n")
	nginx.WriteString("# Format: IP 1; (for Nginx map include)\n")
	for _, ip := range ips {
		fmt.Fprintf(&nginx, "%s 1;\n", ip)
	}
	changed, err := writeMapFileIfChanged(l.nginxPath, []byte(nginx.String()))
	return err == nil && changed
}

func sortedIPKeys(ips map[string]challengeEntry) []string {
	keys := make([]string, 0, len(ips))
	for ip := range ips {
		keys = append(keys, ip)
	}
	sort.Strings(keys)
	return keys
}

func writeMapFileIfChanged(path string, data []byte) (bool, error) {
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, data) {
		return false, nil
	}
	return true, writeMapFile(path, data)
}

func writeMapFile(path string, data []byte) error {
	// /run/csm must be world-readable so the webserver user
	// (www-data / nobody / lsws) can stat + read the map underneath.
	// The directory holds no sensitive data; only CSM-owned IP files
	// live inside.
	//
	// MkdirAll respects the process umask, so on cPanel/CloudLinux
	// hosts where csm.service inherits umask 027 the directory ends
	// up at 0o750 and the webserver gets EACCES on the RewriteMap.
	// Explicit Chmod after creation forces the mode the integration
	// requires regardless of umask.
	mapDir := filepath.Dir(path)
	// #nosec G301 -- world-readable rationale above.
	if err := os.MkdirAll(mapDir, 0o755); err != nil {
		return err
	}
	// #nosec G302 -- same world-readable rationale; needed for the
	// webserver user to stat into the directory and read the map.
	if err := os.Chmod(mapDir, 0o755); err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	// #nosec G306 -- webservers read this map file directly. It has to
	// be readable by the webserver user. No sensitive data; only a list
	// of IPs that must re-solve the PoW challenge.
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func (l *IPList) reloadNginx(changed bool, reload func() error) {
	if !changed || reload == nil {
		return
	}
	if err := reload(); err != nil {
		fmt.Fprintf(os.Stderr, "challenge: nginx reload after map update: %v\n", err)
	}
}
