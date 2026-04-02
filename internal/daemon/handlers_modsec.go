//go:build linux

package daemon

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
)

// modsecIPCounter tracks deny timestamps for a single IP.
type modsecIPCounter struct {
	mu    sync.Mutex
	times []time.Time
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

	// Skip infra IPs.
	if ip != "" && isInfraIPDaemon(ip, cfg.InfraIPs) {
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
	severity := alert.Warning
	if ruleNum, err := strconv.Atoi(ruleID); err == nil {
		switch {
		case ruleNum >= 900000 && ruleNum <= 900999:
			severity = alert.Critical // CSM custom rules
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
		message += fmt.Sprintf(" — %s", msg)
	}

	return []alert.Finding{{
		Severity: severity,
		Check:    check,
		Message:  message,
		Details:  truncateDaemon(line, 400),
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
// Format: [IP:PORT-CONN#VHOST] e.g. [122.9.114.57:41920-13#APVH_*_cluster6.pidginhost.net]
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
//  3. Then check dedup — suppress the base finding if a duplicate, but still
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
	ip := extractIPFromFinding(f)
	ruleID := extractRuleIDFromFinding(f)
	ruleNum, _ := strconv.Atoi(ruleID)
	isCSM := f.Check == "modsec_block_realtime" && ruleNum >= 900000 && ruleNum <= 900999

	if isCSM && ip != "" {
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

	return len(recent) >= modsecEscalationHits
}

// extractIPFromFinding extracts the IP address from a finding's Message field.
// The message format is "... from IP ..." or "... from IP on ...".
func extractIPFromFinding(f alert.Finding) string {
	const marker = " from "
	idx := strings.Index(f.Message, marker)
	if idx < 0 {
		return ""
	}
	rest := f.Message[idx+len(marker):]
	// IP ends at space or end of string.
	if sp := strings.IndexByte(rest, ' '); sp >= 0 {
		return rest[:sp]
	}
	return rest
}

// extractRuleIDFromFinding extracts the rule ID from a finding's Message field.
// The message contains "rule NNNN" or "rule NNNN from".
func extractRuleIDFromFinding(f alert.Finding) string {
	const marker = "rule "
	idx := strings.Index(f.Message, marker)
	if idx < 0 {
		return ""
	}
	rest := f.Message[idx+len(marker):]
	if sp := strings.IndexByte(rest, ' '); sp >= 0 {
		return rest[:sp]
	}
	return rest
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
		ctr.mu.Unlock()

		if empty {
			modsecCSMCounter.Delete(key)
		}
		return true
	})
}
