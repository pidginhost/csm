package daemon

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/modsec"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/store"
)

// modsecDenyEvent is one ModSecurity event recorded in an IP's sliding window.
// Warnings (isBlock=false) are recorded only when high-confidence, to supply
// attack evidence to a later low-confidence anomaly-threshold deny in the same
// burst (anomaly-scoring WAFs log the specific attack rule as a warning, then
// deny on the points-threshold rule).
type modsecDenyEvent struct {
	t       time.Time
	rule    int
	conf    modsecConfidence
	isBlock bool
}

// modsecIPCounter tracks recent ModSecurity events for a single IP.
type modsecIPCounter struct {
	mu              sync.Mutex
	events          []modsecDenyEvent
	escalated       bool         // latched once escalation fires; reset when the window drains
	lowBurstEmitted bool         // latched once the low-confidence burst finding fires
	gapEmitted      map[int]bool // rule IDs that already raised a classifier-gap this window
}

// modsecEscalationOutcome reports what a single recorded event should produce.
type modsecEscalationOutcome struct {
	escalate      bool // fire the Critical auto-block escalation finding
	lowConfBurst  bool // fire the non-actioned low-confidence-burst visibility finding
	classifierGap bool // fire the non-actioned classifier-gap finding (new unknown rule)
}

var (
	modsecDedup      sync.Map // key: "IP:ruleID" → value: time.Time
	modsecBlockCount sync.Map // key: IP → value: *modsecIPCounter
)

const (
	modsecDedupTTL              = 60 * time.Second
	modsecEvictInterval         = 10 * time.Minute
	modsecDefaultEscalationWin  = 10 * time.Minute
	modsecDefaultEscalationHits = 3
)

// modsecEscalationParams returns the operator-tuned (hits, window) pair,
// falling back to the shipped defaults when either is unset or
// non-positive. nil cfg returns the defaults so test wiring without a
// config still behaves predictably.
func modsecEscalationParams(cfg *config.Config) (int, time.Duration) {
	hits := modsecDefaultEscalationHits
	win := modsecDefaultEscalationWin
	if cfg == nil {
		return hits, win
	}
	if cfg.Thresholds.ModSecEscalationHits > 0 {
		hits = cfg.Thresholds.ModSecEscalationHits
	}
	if cfg.Thresholds.ModSecEscalationWindowMin > 0 {
		win = time.Duration(cfg.Thresholds.ModSecEscalationWindowMin) * time.Minute
	}
	return hits, win
}

// modsecDefaultLowConfEscalationHits is the shipped low-confidence-only backstop:
// how many low-confidence policy/anomaly denies from one IP within the
// escalation window force a firewall escalation even with no attack signature.
// It closes the deliberate "only trip anomaly/content-type rules" bypass while
// staying far above any single legitimate checkout-retry pattern.
const modsecDefaultLowConfEscalationHits = 30

// modsecLowConfEscalationHits returns the operator-tuned backstop count,
// falling back to the shipped default when unset or non-positive. Raise it on
// hosts with high-volume legitimate apps that trip policy/anomaly rules in
// bulk; it is not meant to be disabled (that would reopen the bypass).
func modsecLowConfEscalationHits(cfg *config.Config) int {
	if cfg == nil {
		return modsecDefaultLowConfEscalationHits
	}
	if cfg.Thresholds.ModSecLowConfidenceEscalationHits > 0 {
		return cfg.Thresholds.ModSecLowConfidenceEscalationHits
	}
	return modsecDefaultLowConfEscalationHits
}

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
	//
	// Apache mod_security writes the action verbatim into the message, so
	// "Access denied" is a reliable block signal. LiteSpeed's mod_security
	// front-end writes every match as "triggered!" with no action context,
	// regardless of whether the rule's declared action denied the request
	// or merely incremented a counter. Without further context every match
	// would be counted as a deny, escalating to a 24-hour auto-block after
	// three pass-action triggers from the same IP. Consult the rule-action
	// registry built at daemon start: pass/log/allow rules produce a
	// warning, deny/drop/block produce a block, and an unknown rule ID in a
	// populated registry stays conservative. When the registry is empty, the
	// line remains a warning until a refresh loads rule actions.
	check := "modsec_warning_realtime"
	if strings.Contains(line, "Access denied") {
		check = "modsec_block_realtime"
	} else if isLiteSpeed && strings.Contains(line, "triggered!") {
		check = classifyLiteSpeedTrigger(ruleID)
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
		SourceIP: ip,
		Domain:   domainOrEmpty(hostname),
	}}
}

// domainOrEmpty returns hostname unless it parses as a bare IP address
// (v4 or v6, with or without surrounding brackets). Vhosts served on a
// raw IP would otherwise key the incident bucket on the IP literal,
// causing two unrelated victim sites that happen to be reachable over
// their public IPs to merge into a single bucket.
func domainOrEmpty(hostname string) string {
	if hostname == "" {
		return ""
	}
	probe := strings.TrimPrefix(hostname, "[")
	probe = strings.TrimSuffix(probe, "]")
	if net.ParseIP(probe) != nil {
		return ""
	}
	return hostname
}

// classifyLiteSpeedTrigger decides whether a LiteSpeed mod_security
// "triggered!" line represents a real deny (block_realtime) or merely an
// informational pass-action match (warning_realtime), based on the rule's
// declared action in the rule-action registry. A populated registry with an
// unknown rule defaults to block; a nil or empty registry cannot distinguish
// pass-action matches from denies, so ambiguous lines stay warnings until a
// refresh loads rule actions.
func classifyLiteSpeedTrigger(ruleID string) string {
	num, err := strconv.Atoi(ruleID)
	if err != nil {
		return "modsec_block_realtime"
	}
	reg := modsec.Global()
	// No rule-action knowledge available: the registry has not been built yet,
	// or the vendor rule tree was transiently empty (cPanel modsec_assemble
	// mid-rewrite, or a boot-time web-server mis-detection). We cannot tell a
	// pass-action scoring rule -- e.g. Comodo CWAF 210710 / 214930, which only
	// add anomaly points and never deny -- from a real deny. Defaulting every
	// "triggered" line to a block in this state false-escalates benign hits
	// into 24h auto-bans of real visitors. Explicit "Access denied" lines are
	// classified as blocks before this function is reached. LiteSpeed deny
	// rules that log only "triggered!" are degraded to warning during this
	// empty-registry window, but ambiguous lines must not auto-escalate while
	// the registry is unavailable.
	if reg == nil || reg.Len() == 0 {
		return "modsec_warning_realtime"
	}
	action, known := reg.Action(num)
	if !known {
		// Registry IS populated but this specific rule is unrecognised -- stay
		// conservative and treat it as a block so a genuinely unknown deny
		// rule still escalates.
		return "modsec_block_realtime"
	}
	if modsec.IsBlockingAction(action) {
		return "modsec_block_realtime"
	}
	return "modsec_warning_realtime"
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

// extractAllModSecFields returns every value delimited by start/end, joined by
// a space. ModSecurity lines carry repeated [tag "..."] fields; the confidence
// classifier needs all of them, not just the first.
func extractAllModSecFields(line, start, end string) string {
	var vals []string
	for {
		idx := strings.Index(line, start)
		if idx < 0 {
			break
		}
		rest := line[idx+len(start):]
		endIdx := strings.Index(rest, end)
		if endIdx < 0 {
			break
		}
		vals = append(vals, rest[:endIdx])
		line = rest[endIdx+len(end):]
	}
	return strings.Join(vals, " ")
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

// parseModSecLogLineDeduped wraps parseModSecLogLine with dedup and block
// threshold escalation. It is the handler registered with the log watcher.
//
// Order of operations (critical for correctness):
//  1. Parse the raw line.
//  2. ALWAYS increment the block escalation counter (even if dedup will suppress).
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

	// --- Step 1: block escalation (before dedup) ---
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
	isBlock := f.Check == "modsec_block_realtime"
	isCSM := isBlock && ruleNum >= 900000 && ruleNum <= 900999

	// Record hit for per-rule stats (24h hourly buckets)
	if ruleNum >= 900000 && ruleNum <= 900999 {
		if sdb := store.Global(); sdb != nil {
			sdb.IncrModSecRuleHit(ruleNum, now)
		}
	}

	// Classify the rule's attack confidence from its ID, message, tags, and
	// severity. This decides whether a deny may auto-escalate to a firewall ban
	// (high/unknown) or only feeds the low-confidence visibility/backstop path
	// (low). See docs/superpowers/specs/2026-06-27-modsec-escalation-fp-options.md.
	msg := extractModSecField(line, `[msg "`, `"]`)
	tags := extractAllModSecFields(line, `[tag "`, `"]`)
	conf := classifyModSecConfidence(ruleNum, msg, tags)

	// Operator override (Rules page): exclude a rule ID from escalation. Coarse
	// and dual-use-unsafe on its own; the classifier is the primary control.
	noEscalate := false
	if db := store.Global(); db != nil {
		noEscalate = db.GetModSecNoEscalateRules()[ruleNum]
	}

	// Feed the per-IP window with every blocking deny, plus high-confidence
	// warnings, which supply attack evidence to a later anomaly-threshold deny
	// in the same burst. Operator-excluded rules are not recorded at all.
	if ip != "" && ruleID != "" && !noEscalate && (isBlock || conf == modsecConfHigh) {
		hits, win := modsecEscalationParams(cfg)
		lowConfHits := modsecLowConfEscalationHits(cfg)
		outcome := recordModSecEvent(ip, now, ruleNum, conf, isBlock, hits, lowConfHits, win)
		switch {
		case outcome.escalate:
			check := "modsec_block_escalation"
			label := "ModSecurity"
			if isCSM {
				check = "modsec_csm_block_escalation"
				label = "CSM rule"
			}
			results = append(results, alert.Finding{
				Severity: alert.Critical,
				Check:    check,
				Message:  fmt.Sprintf("%s escalation: %d+ denies from %s within %v", label, hits, ip, win),
				Details:  truncateDaemon(line, 400),
				SourceIP: ip,
				Domain:   f.Domain,
			})
		case outcome.lowConfBurst:
			results = append(results, alert.Finding{
				Severity: alert.Warning,
				Check:    "modsec_low_confidence_burst",
				Message: fmt.Sprintf("ModSecurity low-confidence burst: %d+ policy/anomaly denies from %s within %v (no attack signature; not auto-blocked)",
					hits, ip, win),
				Details:  truncateDaemon(line, 400),
				SourceIP: ip,
				Domain:   f.Domain,
			})
		}
		if outcome.classifierGap {
			results = append(results, alert.Finding{
				Severity: alert.Warning,
				Check:    "modsec_classifier_gap",
				Message: fmt.Sprintf("ModSecurity rule %s from %s is an unclassified blocking rule (escalation-eligible; add it to the confidence table if it is a known policy/anomaly rule)",
					ruleID, ip),
				Details:  truncateDaemon(line, 400),
				SourceIP: ip,
				Domain:   f.Domain,
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

// recordModSecEvent records one ModSecurity event for an IP's sliding window
// and decides what it should produce. Confidence-gated:
//
//   - escalate (Critical auto-block) fires when total blocking denies reach
//     hits AND the window has high-confidence evidence or an unknown blocking
//     deny; OR when low-confidence-only denies reach the lowConfHits backstop.
//   - lowConfBurst (non-actioned visibility) fires when the hit count is reached
//     with only low-confidence evidence and the backstop is not yet met.
//   - classifierGap (non-actioned visibility) fires once per unknown rule ID per
//     window so new vendor packs are noticed instead of silently escalating.
//
// Repeating one high-confidence rule still escalates: diversity is never
// required when high-confidence evidence is present. hits/lowConfHits/window are
// operator knobs; callers pull defaults via modsecEscalationParams.
func recordModSecEvent(ip string, now time.Time, rule int, conf modsecConfidence, isBlock bool, hits, lowConfHits int, window time.Duration) modsecEscalationOutcome {
	val, _ := modsecBlockCount.LoadOrStore(ip, &modsecIPCounter{})
	ctr := val.(*modsecIPCounter)

	ctr.mu.Lock()
	defer ctr.mu.Unlock()

	// Prune entries older than the escalation window. If the window fully
	// drained, clear the per-window latches so a fresh burst can re-evaluate.
	cutoff := now.Add(-window)
	kept := ctr.events[:0]
	for _, e := range ctr.events {
		if !e.t.Before(cutoff) {
			kept = append(kept, e)
		}
	}
	ctr.events = kept
	if len(ctr.events) == 0 {
		ctr.escalated = false
		ctr.lowBurstEmitted = false
		ctr.gapEmitted = nil
	}
	ctr.events = append(ctr.events, modsecDenyEvent{t: now, rule: rule, conf: conf, isBlock: isBlock})

	// Aggregate the current window.
	var totalBlock, lowConfBlock int
	highEvidence := false
	unknownBlock := false
	for _, e := range ctr.events {
		if e.conf == modsecConfHigh {
			highEvidence = true
		}
		if !e.isBlock {
			continue
		}
		totalBlock++
		switch e.conf {
		case modsecConfLow:
			lowConfBlock++
		case modsecConfUnknown:
			unknownBlock = true
		}
	}

	var out modsecEscalationOutcome

	// Classifier gap: a new unknown blocking rule, reported once per window.
	if isBlock && conf == modsecConfUnknown {
		if ctr.gapEmitted == nil {
			ctr.gapEmitted = make(map[int]bool)
		}
		if !ctr.gapEmitted[rule] {
			ctr.gapEmitted[rule] = true
			out.classifierGap = true
		}
	}

	normalFire := totalBlock >= hits && (highEvidence || unknownBlock)
	backstopFire := !highEvidence && !unknownBlock && lowConfHits > 0 && lowConfBlock >= lowConfHits

	// Re-arm latches once the IP drops below the trigger that set them, so a
	// renewed burst escalates again (and refreshes the firewall ban). Without
	// this a low-and-slow source that keeps its window barely alive would
	// escalate only once, then never re-ban after the first 24h block expires.
	if !normalFire && !backstopFire {
		ctr.escalated = false
	}
	if totalBlock < hits {
		ctr.lowBurstEmitted = false
	}

	if ctr.escalated {
		return out
	}
	if normalFire || backstopFire {
		ctr.escalated = true
		out.escalate = true
		return out
	}

	// Low-confidence-only burst at the normal bar: visibility, never a ban.
	if totalBlock >= hits && !highEvidence && !unknownBlock && !ctr.lowBurstEmitted {
		ctr.lowBurstEmitted = true
		out.lowConfBurst = true
	}
	return out
}

// StartModSecEviction starts a background goroutine that prunes expired dedup
// and counter entries every modsecEvictInterval to prevent unbounded memory
// growth. It returns when stopCh is closed. cfgFn supplies the live
// thresholds at each tick so SIGHUP edits to the escalation window take
// effect without restarting the evictor.
func StartModSecEviction(stopCh <-chan struct{}, cfgFn func() *config.Config) {
	if cfgFn == nil {
		cfgFn = func() *config.Config { return nil }
	}
	obs.Go("modsec-eviction", func() {
		ticker := time.NewTicker(modsecEvictInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case now := <-ticker.C:
				hits, win := modsecEscalationParams(cfgFn())
				evictModSecState(now, hits, win)
			}
		}
	})
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

// evictModSecState prunes expired entries from modsecDedup and modsecBlockCount.
// hits and window mirror the live thresholds so the cooldown reset matches
// what recordModSecEvent would compute on the next event.
func evictModSecState(now time.Time, hits int, window time.Duration) {
	// Prune dedup entries older than modsecDedupTTL.
	modsecDedup.Range(func(key, value any) bool {
		if now.Sub(value.(time.Time)) >= modsecDedupTTL {
			modsecDedup.Delete(key)
		}
		return true
	})

	// Prune counter entries.
	cutoff := now.Add(-window)
	modsecBlockCount.Range(func(key, value any) bool {
		ctr := value.(*modsecIPCounter)
		ctr.mu.Lock()
		kept := ctr.events[:0]
		for _, e := range ctr.events {
			if !e.t.Before(cutoff) {
				kept = append(kept, e)
			}
		}
		ctr.events = kept
		empty := len(kept) == 0
		blockCount := 0
		for _, e := range kept {
			if e.isBlock {
				blockCount++
			}
		}
		if blockCount < hits {
			// Below the normal hit count: re-arm so a renewed burst can
			// escalate (and refresh the firewall ban) again.
			ctr.escalated = false
			ctr.lowBurstEmitted = false
		}
		if empty {
			ctr.gapEmitted = nil
		}
		ctr.mu.Unlock()

		if empty {
			modsecBlockCount.Delete(key)
		}
		return true
	})
}
