package daemon

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/platform"
)

// Real-time access log handler for detecting wp-login.php brute force and
// xmlrpc.php abuse. Watches the LiteSpeed/Apache Combined Log Format access
// log and tracks per-IP POST counts using a sliding time window.
//
// Emits the same check names as the periodic CheckWPBruteForce
// (wp_login_bruteforce, xmlrpc_abuse) so the existing auto-block pipeline
// handles them automatically.

const (
	// Sliding window for counting requests per IP.
	accessLogWindow = 5 * time.Minute

	// Thresholds within the window. Lower than periodic checks because
	// we're watching in real-time and want fast response.
	accessLogWPLoginThreshold = 10
	accessLogXMLRPCThreshold  = 15

	// Eviction: how often to prune expired trackers.
	accessLogEvictInterval = 5 * time.Minute

	// Cooldown after an IP is flagged: don't re-alert for this long.
	// Prevents alert spam while auto-block processes the finding.
	accessLogBlockCooldown = 30 * time.Minute
)

// accessLogTracker tracks POST timestamps per endpoint for a single IP.
type accessLogTracker struct {
	mu                sync.Mutex
	wpLoginTimes      []time.Time
	xmlrpcTimes       []time.Time
	adminPanelTimes   []time.Time
	wpLoginAlerted    bool
	xmlrpcAlerted     bool
	adminPanelAlerted bool
	lastSeen          time.Time
	generation        uint64
	evicting          bool
}

// accessLogTrackers holds per-IP state. sync.Map for concurrent handler access.
var accessLogTrackers sync.Map // key: IP string → value: *accessLogTracker

// accessLogTrackerCount approximates the live entry count in
// accessLogTrackers. sync.Map exposes no Len(); maintaining a side
// counter is the canonical workaround. Used to trigger eager
// eviction during a DDoS burst, where the 5-min timer alone would
// let the map grow into the hundreds of thousands of unique IPs
// before the next prune.
var (
	accessLogTrackerCount   atomic.Int64
	accessLogEagerEvictTrip = make(chan struct{}, 1)
)

// accessLogEvictSoftCap is the live-entry threshold above which the
// hot path nudges the eviction goroutine to run sooner than the
// 5-min ticker. Picked to be well below typical memory limits even
// at the worst per-tracker size (~256 bytes) so a 100k entry
// burst stays under 32 MB.
const (
	accessLogEvictSoftCap       int64 = 50000
	accessLogEvictTargetPercent int64 = 95
)

type accessLogEvictionCandidate struct {
	key        string
	tracker    *accessLogTracker
	lastSeen   time.Time
	generation uint64
}

// discoverAccessLogPath returns the first access log path that exists,
// consulting the platform detector for OS/web-server specific candidates.
func discoverAccessLogPath() string {
	info := platform.Detect()
	for _, p := range info.AccessLogPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// parseAccessLogBruteForce is the LogLineHandler for the Apache/LiteSpeed
// Combined Log Format access log. It parses each line, tracks per-IP POST
// counts to wp-login.php and xmlrpc.php, and emits findings when thresholds
// are crossed.
func parseAccessLogBruteForce(line string, cfg *config.Config) []alert.Finding {
	// Fast reject: only care about POST requests to known attack targets.
	if !strings.Contains(line, "POST") {
		return nil
	}

	ip, method, path, ok := accessLogIPMethodPath(line)
	if !ok {
		return nil
	}

	// Skip infra IPs and loopback.
	if ip == "127.0.0.1" || ip == "::1" || isInfraIPDaemon(ip, cfg.InfraIPs) {
		return nil
	}

	if method != "POST" {
		return nil
	}

	isWPLogin := strings.Contains(path, "wp-login.php")
	isXMLRPC := strings.Contains(path, "xmlrpc.php")
	isAdminPanel := isAdminPanelPath(path)

	if !isWPLogin && !isXMLRPC && !isAdminPanel {
		return nil
	}

	now := time.Now()
	tracker := loadAccessLogTracker(ip, now)
	defer tracker.mu.Unlock()

	tracker.lastSeen = now
	tracker.generation++
	cutoff := now.Add(-accessLogWindow)

	var results []alert.Finding

	// Once a per-tier alert has fired, skip pruneAndAppend until cooldown
	// clears the `alerted` flag. The slice would otherwise grow on every
	// event during a sustained burst (potentially tens of thousands of
	// entries for a 5-min window at 100 rps), wasting CPU on prune passes
	// whose result is never consumed: the `alerted` flag already prevents
	// re-alerts, and the eviction loop trims the slice on its own schedule.
	//
	// Safety: evictAccessLogState resets `alerted` once `lastSeen` is older
	// than `cooldownCutoff` (30 min of silence by default). By that point
	// the same eviction call has also pruned the slice to empty (window is
	// 5 min, so any remaining timestamp is far past cutoff), so the next
	// matching event correctly starts a fresh count from 1.
	if isWPLogin && !tracker.wpLoginAlerted {
		tracker.wpLoginTimes = pruneAndAppend(tracker.wpLoginTimes, cutoff, now)

		if len(tracker.wpLoginTimes) >= accessLogWPLoginThreshold {
			tracker.wpLoginAlerted = true
			results = append(results, alert.Finding{
				Severity:  alert.Critical,
				Check:     "wp_login_bruteforce",
				Message:   fmt.Sprintf("WordPress login brute force from %s: %d POSTs in %v (real-time)", ip, len(tracker.wpLoginTimes), accessLogWindow),
				Details:   "Real-time detection: high rate of POST requests to wp-login.php",
				Timestamp: now,
				SourceIP:  ip,
			})
		}
	}

	if isXMLRPC && !tracker.xmlrpcAlerted {
		tracker.xmlrpcTimes = pruneAndAppend(tracker.xmlrpcTimes, cutoff, now)

		if len(tracker.xmlrpcTimes) >= accessLogXMLRPCThreshold {
			tracker.xmlrpcAlerted = true
			results = append(results, alert.Finding{
				Severity:  alert.Critical,
				Check:     "xmlrpc_abuse",
				Message:   fmt.Sprintf("XML-RPC abuse from %s: %d POSTs in %v (real-time)", ip, len(tracker.xmlrpcTimes), accessLogWindow),
				Details:   "Real-time detection: high rate of POST requests to xmlrpc.php (brute force or amplification)",
				Timestamp: now,
				SourceIP:  ip,
			})
		}
	}

	if isAdminPanel && !tracker.adminPanelAlerted {
		tracker.adminPanelTimes = pruneAndAppend(tracker.adminPanelTimes, cutoff, now)
		if len(tracker.adminPanelTimes) >= accessLogWPLoginThreshold {
			tracker.adminPanelAlerted = true
			results = append(results, alert.Finding{
				Severity:  alert.Critical,
				Check:     "admin_panel_bruteforce",
				Message:   fmt.Sprintf("Admin panel brute force from %s: %d POSTs in %v (real-time)", ip, len(tracker.adminPanelTimes), accessLogWindow),
				Details:   "Real-time detection: high rate of POST requests to common admin panel login paths (phpMyAdmin / Joomla)",
				Timestamp: now,
				SourceIP:  ip,
			})
		}
	}

	return results
}

func loadAccessLogTracker(ip string, now time.Time) *accessLogTracker {
	for {
		val, loaded := accessLogTrackers.LoadOrStore(ip, &accessLogTracker{lastSeen: now})
		tracker := val.(*accessLogTracker)
		if !loaded && accessLogTrackerCount.Add(1) > accessLogEvictSoftCap {
			signalAccessLogEagerEviction()
		}

		tracker.mu.Lock()
		if !tracker.evicting {
			return tracker
		}
		tracker.mu.Unlock()

		if accessLogTrackers.CompareAndDelete(ip, tracker) {
			decrementAccessLogTrackerCount()
		}
	}
}

func signalAccessLogEagerEviction() {
	select {
	case accessLogEagerEvictTrip <- struct{}{}:
	default:
	}
}

// pruneAndAppend removes entries older than cutoff and appends now.
func pruneAndAppend(times []time.Time, cutoff, now time.Time) []time.Time {
	recent := times[:0]
	for _, t := range times {
		if !t.Before(cutoff) {
			recent = append(recent, t)
		}
	}
	return append(recent, now)
}

// StartAccessLogEviction starts a background goroutine that prunes expired
// tracker entries to prevent unbounded memory growth. Same pattern as
// StartModSecEviction.
func StartAccessLogEviction(stopCh <-chan struct{}) {
	obs.Go("accesslog-eviction", func() {
		ticker := time.NewTicker(accessLogEvictInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case now := <-ticker.C:
				evictAccessLogState(now)
			case <-accessLogEagerEvictTrip:
				// Soft-cap signal from the hot path. Run an
				// immediate eviction so a DDoS burst of unique
				// IPs cannot grow the tracker map past memory
				// budget before the next 5-min tick.
				evictAccessLogState(time.Now())
			}
		}
	})
}

func evictAccessLogState(now time.Time) {
	evictAccessLogStateWithCap(now, accessLogEvictSoftCap)
}

func evictAccessLogStateWithCap(now time.Time, cap int64) {
	cutoff := now.Add(-accessLogWindow)
	cooldownCutoff := now.Add(-accessLogBlockCooldown)
	candidates := make([]accessLogEvictionCandidate, 0)

	accessLogTrackers.Range(func(key, value any) bool {
		ip := key.(string)
		tracker := value.(*accessLogTracker)
		tracker.mu.Lock()
		if tracker.evicting {
			tracker.mu.Unlock()
			return true
		}

		// Prune old timestamps.
		tracker.wpLoginTimes = pruneSlice(tracker.wpLoginTimes, cutoff)
		tracker.xmlrpcTimes = pruneSlice(tracker.xmlrpcTimes, cutoff)
		tracker.adminPanelTimes = pruneSlice(tracker.adminPanelTimes, cutoff)

		// Reset alerted flags after cooldown so the IP can be re-detected
		// if it comes back after the block expires.
		if tracker.wpLoginAlerted && tracker.lastSeen.Before(cooldownCutoff) {
			tracker.wpLoginAlerted = false
		}
		if tracker.xmlrpcAlerted && tracker.lastSeen.Before(cooldownCutoff) {
			tracker.xmlrpcAlerted = false
		}
		if tracker.adminPanelAlerted && tracker.lastSeen.Before(cooldownCutoff) {
			tracker.adminPanelAlerted = false
		}

		empty := len(tracker.wpLoginTimes) == 0 && len(tracker.xmlrpcTimes) == 0 &&
			len(tracker.adminPanelTimes) == 0 && tracker.lastSeen.Before(cooldownCutoff)

		if empty {
			deleteAccessLogTrackerLocked(ip, tracker)
		} else {
			candidates = append(candidates, accessLogEvictionCandidate{
				key:        ip,
				tracker:    tracker,
				lastSeen:   tracker.lastSeen,
				generation: tracker.generation,
			})
		}
		tracker.mu.Unlock()
		return true
	})

	enforceAccessLogTrackerCap(candidates, cap)
}

func enforceAccessLogTrackerCap(candidates []accessLogEvictionCandidate, cap int64) {
	if cap <= 0 || accessLogTrackerCount.Load() <= cap {
		return
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].lastSeen.Before(candidates[j].lastSeen)
	})

	target := cap * accessLogEvictTargetPercent / 100
	for _, candidate := range candidates {
		if accessLogTrackerCount.Load() <= target {
			return
		}

		tracker := candidate.tracker
		tracker.mu.Lock()
		if !tracker.evicting &&
			tracker.generation == candidate.generation &&
			tracker.lastSeen.Equal(candidate.lastSeen) {
			deleteAccessLogTrackerLocked(candidate.key, tracker)
		}
		tracker.mu.Unlock()
	}
}

func deleteAccessLogTrackerLocked(key string, tracker *accessLogTracker) bool {
	tracker.evicting = true
	if accessLogTrackers.CompareAndDelete(key, tracker) {
		decrementAccessLogTrackerCount()
		return true
	}
	return false
}

func decrementAccessLogTrackerCount() {
	for {
		current := accessLogTrackerCount.Load()
		if current <= 0 {
			return
		}
		if accessLogTrackerCount.CompareAndSwap(current, current-1) {
			return
		}
	}
}

// accessLogIPMethodPath extracts client IP, request method, and request path
// from an Apache/LiteSpeed Combined Log Format line without allocating a
// string slice. Hot path: each domlog line that survives the "POST" prefilter
// hits this. strings.Fields allocates len(fields)+1 strings per call; this
// scanner only returns sub-strings that share the input's backing array.
func accessLogIPMethodPath(line string) (ip, method, path string, ok bool) {
	var fields [7]string
	n := len(line)
	i := 0
	for f := 0; f < 7; f++ {
		for i < n && isAccessLogSpace(line[i]) {
			i++
		}
		if i >= n {
			return "", "", "", false
		}
		start := i
		for i < n && !isAccessLogSpace(line[i]) {
			i++
		}
		fields[f] = line[start:i]
	}
	method = fields[5]
	if len(method) > 0 && method[0] == '"' {
		method = method[1:]
	}
	if l := len(method); l > 0 && method[l-1] == '"' {
		method = method[:l-1]
	}
	return fields[0], method, fields[6], true
}

func isAccessLogSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// isAdminPanelPath returns true for high-confidence non-WP admin panel login
// paths suitable for hard-block auto-response. Drupal /user/login, Tomcat
// /manager/html, generic /admin/login.php, /mysql/ are intentionally EXCLUDED
// because they're either too generic (FP risk on shared hosting) or use a
// different attack shape (Basic auth vs. POST forms). See spec Component 5
// for the full rationale.
func isAdminPanelPath(path string) bool {
	return strings.Contains(path, "/phpmyadmin/index.php") ||
		strings.Contains(path, "/pma/index.php") ||
		strings.Contains(path, "/phpMyAdmin/index.php") ||
		strings.Contains(path, "/administrator/index.php")
}

func pruneSlice(times []time.Time, cutoff time.Time) []time.Time {
	recent := times[:0]
	for _, t := range times {
		if !t.Before(cutoff) {
			recent = append(recent, t)
		}
	}
	return recent
}
