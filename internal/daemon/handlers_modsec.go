package daemon

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/store"
)

// modsecIPCounter tracks deny timestamps for a single IP.
type modsecIPCounter struct {
	mu        sync.Mutex
	times     []time.Time
	escalated bool // set once escalation fires - prevents repeated findings per window
}

var (
	modsecDedup      sync.Map // key: "IP:ruleID" → value: time.Time
	modsecCSMCounter sync.Map // key: IP → value: *modsecIPCounter
)

const (
	modsecDedupTTL       = 60 * time.Second
	modsecEscalationWin  = 10 * time.Minute
	modsecEscalationHits = 3
	modsecEvictInterval  = 10 * time.Minute
)

// parseModSecLogLine parses a ModSecurity log line from Apache or LiteSpeed
// error logs and returns findings for blocked requests or warnings.
func parseModSecLogLine(line string, cfg *config.Config) []alert.Finding {
	// Fast reject: not a ModSecurity line.
	if !strings.Contains(line, "ModSecurity:") && !strings.Contains(line, "[MODSEC]") {
		return nil
	}

	isLiteSpeed := strings.Contains(line, "[MODSEC]")

	var ip, ruleID, msg, hostname, uri string

	if isLiteSpeed {
		ip = extractLiteSpeedIP(line)
		ruleID = extractModSecField(line, `[id "`, `"]`)
		msg = extractModSecField(line, `[msg "`, `"]`)
		hostname = extractModSecField(line, `[hostname "`, `"]`)
		uri = extractModSecField(line, `[uri "`, `"]`)
	} else {
		// Apache format: [client IP] or [client IP:port]
		raw := extractModSecField(line, "[client ", "]")
		// Strip port if present (Apache 2.4 uses "IP:port").
		if idx := strings.LastIndex(raw, ":"); idx > 0 {
			// Make sure it's not an IPv6 address (contains multiple colons).
			if strings.Count(raw, ":") == 1 {
				raw = raw[:idx]
			}
		}
		ip = raw
		ruleID = extractModSecField(line, `[id "`, `"]`)
		msg = extractModSecField(line, `[msg "`, `"]`)
		hostname = extractModSecField(line, `[hostname "`, `"]`)
		uri = extractModSecField(line, `[uri "`, `"]`)
	}

	// Skip infra and loopback IPs - consistent with other realtime handlers
	// (handlers.go:22, autoblock.go:149). Prevents noisy findings and
	// false escalation from proxied or locally forwarded Apache traffic.
	if ip != "" && (isInfraIPDaemon(ip, cfg.InfraIPs) || ip == "127.0.0.1" || ip == "::1") {
		return nil
	}

	// Determine check name.
	check := "modsec_warning_realtime"
	if strings.Contains(line, "Access denied") {
		check = "modsec_block_realtime"
	} else if isLiteSpeed && strings.Contains(line, "triggered!") {
		check = "modsec_block_realtime"
	}

	// Determine severity from rule ID.
	// Individual blocks are informational - ModSecurity already denied the
	// request. Only the escalation finding (3+ from same IP) is CRITICAL
	// because it triggers auto-block at the firewall level.
	severity := alert.Warning
	if ruleNum, err := strconv.Atoi(ruleID); err == nil {
		switch {
		case ruleNum >= 900000 && ruleNum <= 900999:
			severity = alert.High // CSM custom rules - attack blocked, informational
		case ruleNum >= 910000:
			severity = alert.High // OWASP CRS
		}
	}

	// Build message.
	message := fmt.Sprintf("ModSecurity rule %s", ruleID)
	if check == "modsec_block_realtime" {
		message = fmt.Sprintf("ModSecurity blocked request: rule %s", ruleID)
	}
	if ip != "" {
		message += fmt.Sprintf(" from %s", ip)
	}
	if hostname != "" {
		message += fmt.Sprintf(" on %s", hostname)
	}
	if uri != "" {
		message += fmt.Sprintf(" uri=%s", uri)
	}
	if msg != "" {
		message += fmt.Sprintf(" - %s", msg)
	}

	// Store structured details so the web UI can extract fields consistently
	// regardless of whether the source was Apache or LiteSpeed format.
	details := fmt.Sprintf("Rule: %s\nMessage: %s\nHostname: %s\nURI: %s\nRaw: %s",
		ruleID, msg, hostname, uri, truncateDaemon(line, 300))

	return []alert.Finding{{
		Severity: severity,
		Check:    check,
		Message:  message,
		Details:  details,
	}}
}

// extractModSecField extracts the value between start and end delimiters.
// Returns empty string if delimiters are not found.
func extractModSecField(line, start, end string) string {
	idx := strings.Index(line, start)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(start):]
	endIdx := strings.Index(rest, end)
	if endIdx < 0 {
		return ""
	}
	return rest[:endIdx]
}

// extractLiteSpeedIP extracts the client IP from a LiteSpeed log line.
// Format: [IP:PORT-CONN#VHOST] e.g. [122.9.114.57:41920-13#APVH_*_server.example.com]
func extractLiteSpeedIP(line string) string {
	// Find the field that looks like [IP:PORT-CONN#VHOST]
	// It appears as a bracketed field containing # and a port separator.
	start := 0
	for {
		openBracket := strings.Index(line[start:], "[")
		if openBracket < 0 {
			return ""
		}
		openBracket += start
		closeBracket := strings.Index(line[openBracket:], "]")
		if closeBracket < 0 {
			return ""
		}
		closeBracket += openBracket

		field := line[openBracket+1 : closeBracket]

		// LiteSpeed connection field has # (for VHOST) and contains IP:PORT-CONN#
		if strings.Contains(field, "#") && strings.Contains(field, ":") && strings.Contains(field, "-") {
			// Extract IP part: everything before the first ':'
			colonIdx := strings.Index(field, ":")
			if colonIdx > 0 {
				ip := field[:colonIdx]
				// Validate it looks like an IP (has dots).
				if strings.Count(ip, ".") == 3 {
					return ip
				}
			}
		}
		start = closeBracket + 1
	}
}

// parseModSecLogLineDeduped wraps parseModSecLogLine with dedup and CSM-rule
// threshold escalation. It is the handler registered with the log watcher.
//
// Order of operations (critical for correctness):
//  1. Parse the raw line.
//  2. ALWAYS increment the CSM escalation counter (even if dedup will suppress).
//  3. Then check dedup - suppress the base finding if a duplicate, but still
//     return any escalation finding from step 2.
func parseModSecLogLineDeduped(line string, cfg *config.Config) []alert.Finding {
	raw := parseModSecLogLine(line, cfg)
	if len(raw) == 0 {
		return nil
	}
	f := raw[0]

	now := time.Now()
	var results []alert.Finding

	// --- Step 1: CSM escalation (before dedup) ---
	// Extract IP and rule ID directly from the raw log line - NOT from the
	// finding message, which could be manipulated via log injection.
	ip := extractModSecField(line, "[client ", "]")
	if ip == "" {
		ip = extractLiteSpeedIP(line)
	}
	// Strip port from Apache 2.4 format (IP:port)
	if strings.Count(ip, ":") == 1 {
		if idx := strings.LastIndex(ip, ":"); idx > 0 {
			ip = ip[:idx]
		}
	}
	ruleID := extractModSecField(line, `[id "`, `"]`)
	ruleNum, _ := strconv.Atoi(ruleID)
	isCSM := f.Check == "modsec_block_realtime" && ruleNum >= 900000 && ruleNum <= 900999

	// Record hit for per-rule stats (24h hourly buckets)
	if ruleNum >= 900000 && ruleNum <= 900999 {
		if sdb := store.Global(); sdb != nil {
			sdb.IncrModSecRuleHit(ruleNum, now)
		}
	}

	// Check if this rule is excluded from auto-block escalation.
	// Configurable via the Rules page in the web UI.
	noEscalate := false
	if db := store.Global(); db != nil {
		noEscalate = db.GetModSecNoEscalateRules()[ruleNum]
	}

	if isCSM && ip != "" && !noEscalate {
		if recordCSMDeny(ip, now) {
			results = append(results, alert.Finding{
				Severity: alert.Critical,
				Check:    "modsec_csm_block_escalation",
				Message:  fmt.Sprintf("CSM rule escalation: %d+ denies from %s within %v", modsecEscalationHits, ip, modsecEscalationWin),
				Details:  truncateDaemon(line, 400),
			})
		}
	}

	// --- Step 2: Dedup ---
	dedupKey := ip + ":" + ruleID
	if prev, loaded := modsecDedup.Load(dedupKey); loaded {
		if now.Sub(prev.(time.Time)) < modsecDedupTTL {
			// Suppress the base finding but still return any escalation.
			if len(results) > 0 {
				return results
			}
			return nil
		}
	}
	modsecDedup.Store(dedupKey, now)

	results = append(results, f)
	return results
}

// recordCSMDeny records a deny event for the given IP and returns true if the
// escalation threshold has been reached (>= modsecEscalationHits within the
// escalation window).
func recordCSMDeny(ip string, now time.Time) bool {
	val, _ := modsecCSMCounter.LoadOrStore(ip, &modsecIPCounter{})
	ctr := val.(*modsecIPCounter)

	ctr.mu.Lock()
	defer ctr.mu.Unlock()

	// Prune entries older than the escalation window.
	cutoff := now.Add(-modsecEscalationWin)
	recent := ctr.times[:0]
	for _, t := range ctr.times {
		if !t.Before(cutoff) {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	ctr.times = recent

	if len(recent) >= modsecEscalationHits && !ctr.escalated {
		ctr.escalated = true
		return true
	}
	return false
}

// StartModSecEviction starts a background goroutine that prunes expired dedup
// and counter entries every modsecEvictInterval to prevent unbounded memory
// growth. It returns when stopCh is closed.
func StartModSecEviction(stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(modsecEvictInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case now := <-ticker.C:
				evictModSecState(now)
			}
		}
	}()
}

// discoverModSecLogPath returns the path to the web server error log that
// CSM should tail for ModSecurity denies. Config override wins, then the
// first candidate from platform detection that actually exists.
func discoverModSecLogPath(cfg *config.Config) string {
	if cfg.ModSecErrorLog != "" {
		return cfg.ModSecErrorLog
	}
	return firstExistingPath(platform.Detect().ErrorLogPaths)
}

// firstExistingPath returns the first path in the list that exists on disk,
// or "" if none do. Pure function so tests can exercise it directly.
func firstExistingPath(candidates []string) string {
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// evictModSecState prunes expired entries from modsecDedup and modsecCSMCounter.
func evictModSecState(now time.Time) {
	// Prune dedup entries older than modsecDedupTTL.
	modsecDedup.Range(func(key, value any) bool {
		if now.Sub(value.(time.Time)) >= modsecDedupTTL {
			modsecDedup.Delete(key)
		}
		return true
	})

	// Prune counter entries.
	cutoff := now.Add(-modsecEscalationWin)
	modsecCSMCounter.Range(func(key, value any) bool {
		ctr := value.(*modsecIPCounter)
		ctr.mu.Lock()
		recent := ctr.times[:0]
		for _, t := range ctr.times {
			if !t.Before(cutoff) {
				recent = append(recent, t)
			}
		}
		ctr.times = recent
		empty := len(recent) == 0
		if len(recent) < modsecEscalationHits {
			ctr.escalated = false // reset cooldown when counter drops below threshold
		}
		ctr.mu.Unlock()

		if empty {
			modsecCSMCounter.Delete(key)
		}
		return true
	})
}
