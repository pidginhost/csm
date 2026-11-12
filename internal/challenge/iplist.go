package challenge

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/atomicio"
)

// DefaultMapPath is the webserver-readable Apache / LSWS RewriteMap.
// It lives in the service's cache directory rather than state_path
// (mode 0700, private to CSM's bbolt database) or the runtime directory:
// Apache and LSWS validate a txt: RewriteMap at config-parse time and Nginx
// fails on a missing include, so the maps are part of the webserver's
// configuration and must exist while CSM is stopped -- package upgrades,
// restores, reboots. systemd deletes the runtime directory on every stop
// and keeps the cache directory.
const DefaultMapPath = "/var/cache/csm/challenge_ips.txt"

// DefaultNginxMapPath is the webserver-readable Nginx map include.
const DefaultNginxMapPath = "/var/cache/csm/challenge_ips.nginx.map"

// challengeEntry stores the challenge metadata for a single IP.
type challengeEntry struct {
	FindingID string
	// Check routed the address here; a timeout block names it when there
	// is no root.
	Check         string
	ExpiresAt     time.Time
	Reason        string
	NonEscalating bool
	// Root is the admission evidence the challenge answered; the zero
	// value when it had none.
	Root admission.Evidence
}

// ExpiredEntry is returned by ExpiredEntries for escalation. Root is the
// admission evidence its challenge answered, for the timeout to answer
// again.
type ExpiredEntry struct {
	FindingID string
	Check     string
	IP        string
	Reason    string
	Root      admission.Evidence
}

// PassStore keeps challenge passes across restarts.
type PassStore interface {
	PutChallengePass(ip string, at time.Time) error
	// ChallengePasses returns the passes recorded after cutoff.
	ChallengePasses(cutoff time.Time) (map[string]time.Time, error)
}

const (
	// passEscalationGrace is how long a pass spares an address the timeout
	// block. The bypass cookie waves a returning browser through for as long,
	// so a timeout inside it means the visitor left, not that it failed.
	passEscalationGrace = verifyCookieTTL
	// passMemory is how long a pass is remembered. Login, XML-RPC and
	// enumeration counts read each site's last log lines, which on a quiet
	// site can be days old; an address's lines from before its pass stop
	// counting while the pass is remembered.
	// shortcut: lines older than this still count again, upgrade if quiet sites keep week-old lines in their window.
	passMemory = 7 * 24 * time.Hour
)

// IPList manages the set of IPs that should see challenge pages.
// Webserver integrations read its maps to redirect IPs to the challenge server.
type IPList struct {
	path        string
	nginxPath   string
	nginxReload func() error
	ips         map[string]challengeEntry
	// passes holds when each address last passed a challenge.
	passes    map[string]time.Time
	passStore PassStore
	mu        sync.Mutex
	gate      PortGate
}

// NewIPList creates an IP list writer for the webserver-facing map at
// mapPath and clears any entries a previous run left in it.
func NewIPList(mapPath string) *IPList {
	l := &IPList{
		path:   mapPath,
		ips:    make(map[string]challengeEntry),
		passes: make(map[string]time.Time),
	}
	_ = l.flush()
	return l
}

// SetPassStore persists future passes to ps and restores the ones it still
// remembers. On a read error the earlier passes stay unknown; the list and
// future passes still work.
func (l *IPList) SetPassStore(ps PassStore) error {
	cutoff := time.Now().Add(-passMemory)
	known, err := ps.ChallengePasses(cutoff)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.passStore = ps
	for ip, at := range known {
		if at.After(cutoff) && at.After(l.passes[ip]) {
			l.passes[ip] = at
		}
	}
	return err
}

// Passes returns when each address last passed, for passes still remembered.
func (l *IPList) Passes() map[string]time.Time {
	cutoff := time.Now().Add(-passMemory)
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]time.Time, len(l.passes))
	for ip, at := range l.passes {
		if at.After(cutoff) {
			out[ip] = at
		}
	}
	return out
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
	l.add(ip, reason, duration, false, "", "", admission.Evidence{})
}

// AddNonEscalating marks an IP for challenge without timeout-to-block escalation.
func (l *IPList) AddNonEscalating(ip string, reason string, duration time.Duration) {
	l.add(ip, reason, duration, true, "", "", admission.Evidence{})
}

// AddWithFindingID preserves the originating audit identity for timeout
// escalation. It does not change challenge duration or escalation policy.
func (l *IPList) AddWithFindingID(ip, reason string, duration time.Duration, findingID string) {
	l.add(ip, reason, duration, false, findingID, "", admission.Evidence{})
}

// AddWithRoot also keeps the check that routed the address and the
// admission evidence the challenge answered, so a timeout escalation answers
// the same observation again rather than a new one. root may be zero.
func (l *IPList) AddWithRoot(ip, reason string, duration time.Duration, findingID, check string, root admission.Evidence) {
	l.add(ip, reason, duration, false, findingID, check, root)
}

func (l *IPList) add(ip string, reason string, duration time.Duration, nonEscalating bool, findingID, check string, root admission.Evidence) {
	l.mu.Lock()
	l.ips[ip] = challengeEntry{
		ExpiresAt:     time.Now().Add(duration),
		Reason:        reason,
		NonEscalating: nonEscalating,
		FindingID:     findingID,
		Check:         check,
		Root:          root,
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

// Remove stops challenging an IP without recording a pass.
func (l *IPList) Remove(ip string) { l.remove(ip, time.Time{}) }

// MarkPassed takes a challenged address off the list and remembers the pass.
// It reports false when the address was not listed, so concurrent completions
// of one challenge count once.
func (l *IPList) MarkPassed(ip string) bool { return l.remove(ip, time.Now()) }

func (l *IPList) remove(ip string, passedAt time.Time) bool {
	l.mu.Lock()
	if _, listed := l.ips[ip]; !listed {
		l.mu.Unlock()
		return false
	}
	delete(l.ips, ip)
	if !passedAt.IsZero() {
		l.passes[ip] = passedAt
	}
	changed := l.flush()
	gate := l.gate
	reload := l.nginxReload
	store := l.passStore
	l.mu.Unlock()

	// Only revoke the kernel gate for an IP that was actually on the list: the
	// gate element is created alongside the entry (Add -> Allow), so an IP that
	// was never listed has no element to delete. Without this guard, verified
	// crawlers -- which bypass the gate and call Remove on every request -- make
	// the gate delete a nonexistent element and log an ENOENT error each time.
	if gate != nil {
		if err := gate.Revoke(ip); err != nil {
			fmt.Fprintf(os.Stderr, "challenge: port-gate revoke %s: %v\n", ip, err)
		}
	}
	l.reloadNginx(changed, reload)
	if !passedAt.IsZero() && store != nil {
		if err := store.PutChallengePass(ip, passedAt); err != nil {
			fmt.Fprintf(os.Stderr, "challenge: keep pass of %s: %v\n", ip, err)
		}
	}
	return true
}

// Contains returns true if the IP is currently on the challenge list.
func (l *IPList) Contains(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.ips[ip]
	return ok
}

// Count returns the number of IPs currently waiting on a challenge.
func (l *IPList) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.ips)
}

// ExpiredEntries removes expired entries and returns those eligible for escalation.
// The caller is expected to hard-block returned IPs. An address that passed
// within passEscalationGrace is not returned: it proved a browser and left.
func (l *IPList) ExpiredEntries() []ExpiredEntry {
	l.mu.Lock()
	now := time.Now()
	graceStart := now.Add(-passEscalationGrace)
	forgetBefore := now.Add(-passMemory)
	for ip, at := range l.passes {
		if !at.After(forgetBefore) {
			delete(l.passes, ip)
		}
	}
	var expired []ExpiredEntry
	removed := false
	for ip, entry := range l.ips {
		if now.After(entry.ExpiresAt) {
			if !entry.NonEscalating && !l.passes[ip].After(graceStart) {
				expired = append(expired, ExpiredEntry{IP: ip, Reason: entry.Reason, FindingID: entry.FindingID, Check: entry.Check, Root: entry.Root})
			}
			delete(l.ips, ip)
			removed = true
		}
	}
	var changed bool
	if removed {
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
	// #nosec G304 -- path is the daemon-owned challenge map under /var/cache/csm
	// (DefaultNginxMapPath or operator-set via SetNginxMap), never
	// attacker-controlled. Read only to diff the rendered map and skip
	// rewrite when content is unchanged.
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, data) {
		return false, nil
	}
	return true, writeMapFile(path, data)
}

func ensureMapDir(path string) error {
	// /var/cache/csm must be world-readable so the webserver user
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
	return nil
}

// EnsureMapFile creates a readable empty map when path is absent and leaves
// existing map contents intact. Apache validates txt: RewriteMap sources even
// when challenge mode is disabled, before an IPList would otherwise create the
// file.
func EnsureMapFile(path string) error {
	if err := ensureMapDir(path); err != nil {
		return err
	}
	// #nosec G302 G304 G703 -- path is the daemon-owned, webserver-readable challenge map.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return statErr
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("challenge map %s is not a regular file", path)
		}
		// #nosec G302 -- Apache/LSWS must be able to read the daemon-owned map.
		return os.Chmod(path, 0o644)
	}
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(path)
	}
	// OpenFile respects umask, so force the public read bits Apache needs.
	// #nosec G302 -- Apache/LSWS must be able to read the daemon-owned map.
	if err := f.Chmod(0o644); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func writeMapFile(path string, data []byte) error {
	if err := ensureMapDir(path); err != nil {
		return err
	}
	// #nosec G306 -- webservers read this daemon-owned IP map directly.
	return atomicio.AtomicWrite(path, 0o644, data)
}

func (l *IPList) reloadNginx(changed bool, reload func() error) {
	if !changed || reload == nil {
		return
	}
	if err := reload(); err != nil {
		fmt.Fprintf(os.Stderr, "challenge: nginx reload after map update: %v\n", err)
	}
}
