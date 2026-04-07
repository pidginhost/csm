package daemon

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
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
	mu             sync.Mutex
	wpLoginTimes   []time.Time
	xmlrpcTimes    []time.Time
	wpLoginAlerted bool
	xmlrpcAlerted  bool
	lastSeen       time.Time
}

// accessLogTrackers holds per-IP state. sync.Map for concurrent handler access.
var accessLogTrackers sync.Map // key: IP string → value: *accessLogTracker

// accessLogPaths are the candidate paths for the Combined Log Format access log
// on cPanel servers (LiteSpeed and Apache both write here).
var accessLogPaths = []string{
	"/usr/local/apache/logs/access_log",
	"/var/log/apache2/access_log",
	"/etc/apache2/logs/access_log",
}

// discoverAccessLogPath returns the first access log path that exists.
func discoverAccessLogPath() string {
	for _, p := range accessLogPaths {
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

	fields := strings.Fields(line)
	if len(fields) < 7 {
		return nil
	}

	ip := fields[0]

	// Skip infra IPs and loopback.
	if ip == "127.0.0.1" || ip == "::1" || isInfraIPDaemon(ip, cfg.InfraIPs) {
		return nil
	}

	method := strings.Trim(fields[5], "\"")
	if method != "POST" {
		return nil
	}

	path := fields[6]

	isWPLogin := strings.Contains(path, "wp-login.php")
	isXMLRPC := strings.Contains(path, "xmlrpc.php")

	if !isWPLogin && !isXMLRPC {
		return nil
	}

	now := time.Now()
	val, _ := accessLogTrackers.LoadOrStore(ip, &accessLogTracker{})
	tracker := val.(*accessLogTracker)

	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	tracker.lastSeen = now
	cutoff := now.Add(-accessLogWindow)

	var results []alert.Finding

	if isWPLogin {
		// Append and prune in one pass.
		tracker.wpLoginTimes = pruneAndAppend(tracker.wpLoginTimes, cutoff, now)

		if len(tracker.wpLoginTimes) >= accessLogWPLoginThreshold && !tracker.wpLoginAlerted {
			tracker.wpLoginAlerted = true
			results = append(results, alert.Finding{
				Severity:  alert.Critical,
				Check:     "wp_login_bruteforce",
				Message:   fmt.Sprintf("WordPress login brute force from %s: %d POSTs in %v (real-time)", ip, len(tracker.wpLoginTimes), accessLogWindow),
				Details:   "Real-time detection: high rate of POST requests to wp-login.php",
				Timestamp: now,
			})
		}
	}

	if isXMLRPC {
		tracker.xmlrpcTimes = pruneAndAppend(tracker.xmlrpcTimes, cutoff, now)

		if len(tracker.xmlrpcTimes) >= accessLogXMLRPCThreshold && !tracker.xmlrpcAlerted {
			tracker.xmlrpcAlerted = true
			results = append(results, alert.Finding{
				Severity:  alert.Critical,
				Check:     "xmlrpc_abuse",
				Message:   fmt.Sprintf("XML-RPC abuse from %s: %d POSTs in %v (real-time)", ip, len(tracker.xmlrpcTimes), accessLogWindow),
				Details:   "Real-time detection: high rate of POST requests to xmlrpc.php (brute force or amplification)",
				Timestamp: now,
			})
		}
	}

	return results
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
	go func() {
		ticker := time.NewTicker(accessLogEvictInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case now := <-ticker.C:
				evictAccessLogState(now)
			}
		}
	}()
}

func evictAccessLogState(now time.Time) {
	cutoff := now.Add(-accessLogWindow)
	cooldownCutoff := now.Add(-accessLogBlockCooldown)

	accessLogTrackers.Range(func(key, value any) bool {
		tracker := value.(*accessLogTracker)
		tracker.mu.Lock()

		// Prune old timestamps.
		tracker.wpLoginTimes = pruneSlice(tracker.wpLoginTimes, cutoff)
		tracker.xmlrpcTimes = pruneSlice(tracker.xmlrpcTimes, cutoff)

		// Reset alerted flags after cooldown so the IP can be re-detected
		// if it comes back after the block expires.
		if tracker.wpLoginAlerted && tracker.lastSeen.Before(cooldownCutoff) {
			tracker.wpLoginAlerted = false
		}
		if tracker.xmlrpcAlerted && tracker.lastSeen.Before(cooldownCutoff) {
			tracker.xmlrpcAlerted = false
		}

		empty := len(tracker.wpLoginTimes) == 0 && len(tracker.xmlrpcTimes) == 0 &&
			tracker.lastSeen.Before(cooldownCutoff)

		tracker.mu.Unlock()

		if empty {
			accessLogTrackers.Delete(key)
		}
		return true
	})
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
