package webui

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

func (s *Server) handleModSec(w http.ResponseWriter, _ *http.Request) {
	s.renderTemplate(w, "modsec.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
}

// modsecBlockView is an aggregated view of blocks per IP+rule. Phase 8.4
// extends the response with first_seen / last_seen_iso (RFC3339), top_uris,
// domain_count, and sample_events so the workbench can drive the detail
// panel without a second round trip. The extra fields are additive; legacy
// field names keep their JSON keys.
type modsecBlockView struct {
	IP           string              `json:"ip"`
	RuleID       string              `json:"rule_id"`
	Description  string              `json:"description"`
	Domains      string              `json:"domains"`
	DomainList   []string            `json:"domain_list,omitempty"`
	DomainCount  int                 `json:"domain_count"`
	Hits         int                 `json:"hits"`
	LastSeen     string              `json:"last_seen"`
	FirstSeen    string              `json:"first_seen"`
	LastSeenISO  string              `json:"last_seen_iso"`
	TopURIs      []string            `json:"top_uris"`
	SampleEvents []modsecSampleEvent `json:"sample_events"`
	Escalated    bool                `json:"escalated"`
}

// modsecSampleEvent is a compact per-IP event included in the grouped
// blocks response so the UI can show recent activity without a second
// call to /api/v1/modsec/events.
type modsecSampleEvent struct {
	Time     string `json:"time"`
	RuleID   string `json:"rule_id"`
	Hostname string `json:"hostname"`
	URI      string `json:"uri"`
	Severity string `json:"severity"`
}

// modsecEventView is a single ModSecurity event. Time is a date-less
// "15:04:05" kept for compact display; TimeISO is the full RFC3339 instant the
// UI renders in the operator's timezone and sorts on.
type modsecEventView struct {
	Time     string `json:"time"`
	TimeISO  string `json:"time_iso"`
	IP       string `json:"ip"`
	RuleID   string `json:"rule_id"`
	Hostname string `json:"hostname"`
	URI      string `json:"uri"`
	Severity string `json:"severity"`
}

// apiModSecStats returns 24h summary stats for ModSecurity blocks.
func (s *Server) apiModSecStats(w http.ResponseWriter, _ *http.Request) {
	findings := deduplicateModSecFindings(s.modsecFindings24h())

	uniqueIPs := make(map[string]bool)
	ruleCounts := make(map[string]int)
	escalated := 0

	for _, f := range findings {
		ip := extractModSecIP(f)
		if ip != "" {
			uniqueIPs[ip] = true
		}
		rule := extractModSecRule(f)
		if rule != "" {
			ruleCounts[rule]++
		}
		if isModSecEscalation(f.Check) {
			escalated++
		}
	}

	topRule := "--"
	topCount := 0
	for rule, count := range ruleCounts {
		if count > topCount {
			topCount = count
			topRule = rule
		}
	}

	writeJSON(w, map[string]interface{}{
		"total":      len(findings),
		"unique_ips": len(uniqueIPs),
		"escalated":  escalated,
		"top_rule":   topRule,
	})
}

const (
	// modsecFindingsScanCap bounds the 24h history read before per-IP
	// aggregation starts. The aggregate map has its own cap below, but
	// the handler still needs a findings cap for hosts seeing one or two
	// hot IP+rule pairs millions of times.
	modsecFindingsScanCap = 10000

	// modsecBlocksMaxAggregates caps the IP+rule aggregation map so a host
	// with millions of unique ModSec rule hits cannot OOM the daemon by
	// asking for /api/v1/modsec/blocks. Existing aggregates keep updating
	// after the cap is reached; new IP+rule keys past the cap are dropped
	// silently with the X-CSM-Truncated response header set so monitoring
	// can flag the condition. Default sized for ~50 MB peak: 50000 entries
	// times a few hundred bytes per aggregate.
	modsecBlocksMaxAggregates = 50000
)

// apiModSecBlocks returns aggregated blocks per IP+rule for the last 24h.
func (s *Server) apiModSecBlocks(w http.ResponseWriter, _ *http.Request) {
	findings, truncated := s.modsecFindings24hWithTruncation()
	findings = deduplicateModSecFindings(findings)

	type blockAgg struct {
		ip          string
		ruleID      string
		description string
		domains     map[string]bool
		uriCounts   map[string]int
		hits        int
		firstSeen   time.Time
		lastSeen    time.Time
		escalated   bool
		samples     []modsecSampleEvent // newest-first, capped at 3
	}

	byBlock := make(map[string]*blockAgg)
	escalatedIPs := make(map[string]bool)

	blockKey := func(ip, rule string) string {
		return ip + "\x00" + rule
	}

	for _, f := range findings {
		if isModSecEscalation(f.Check) {
			ip := extractModSecIP(f)
			if ip != "" {
				escalatedIPs[ip] = true
			}
			continue
		}

		ip := extractModSecIP(f)
		if ip == "" {
			continue
		}

		rule := extractModSecRule(f)
		desc := extractModSecDescription(f)
		domain := extractModSecHostname(f)
		uri := extractModSecURI(f)

		key := blockKey(ip, rule)
		agg, ok := byBlock[key]
		if !ok {
			if len(byBlock) >= modsecBlocksMaxAggregates {
				truncated = true
				continue
			}
			agg = &blockAgg{
				ip:          ip,
				ruleID:      rule,
				description: desc,
				domains:     make(map[string]bool),
				uriCounts:   make(map[string]int),
				firstSeen:   f.Timestamp,
			}
			byBlock[key] = agg
		}
		agg.hits++
		if agg.firstSeen.IsZero() || f.Timestamp.Before(agg.firstSeen) {
			agg.firstSeen = f.Timestamp
		}
		if f.Timestamp.After(agg.lastSeen) {
			agg.lastSeen = f.Timestamp
			if rule != "" {
				agg.ruleID = rule
			}
			if desc != "" {
				agg.description = desc
			}
		}
		if agg.description == "" && desc != "" {
			agg.description = desc
		}
		// Skip server IPs and empty hostnames - only show actual domain names.
		// ModSecurity logs the server IP as hostname when the request doesn't
		// match a specific vhost (e.g. direct IP access, SNI mismatch).
		if domain != "" && !looksLikeIP(domain) {
			agg.domains[domain] = true
		}
		if uri != "" {
			agg.uriCounts[uri]++
		}
		if len(agg.samples) < 3 {
			agg.samples = append(agg.samples, modsecSampleEvent{
				Time:     f.Timestamp.UTC().Format(time.RFC3339),
				RuleID:   rule,
				Hostname: domain,
				URI:      uri,
				Severity: f.Severity.String(),
			})
		}
	}

	for ip := range escalatedIPs {
		hasBlock := false
		for _, agg := range byBlock {
			if agg.ip == ip {
				agg.escalated = true
				hasBlock = true
			}
		}
		if !hasBlock {
			if len(byBlock) >= modsecBlocksMaxAggregates {
				truncated = true
				continue
			}
			byBlock[blockKey(ip, "")] = &blockAgg{
				ip:        ip,
				escalated: true,
				domains:   make(map[string]bool),
				uriCounts: make(map[string]int),
			}
		}
	}

	var result []modsecBlockView
	for _, agg := range byBlock {
		if agg.hits == 0 && !agg.escalated {
			continue
		}
		var domainList []string
		for d := range agg.domains {
			domainList = append(domainList, d)
		}
		sort.Strings(domainList)
		domains := strings.Join(domainList, ", ")
		if len(domains) > 80 {
			domains = domains[:77] + "..."
		}

		lastSeen := ""
		lastSeenISO := ""
		if !agg.lastSeen.IsZero() {
			lastSeen = agg.lastSeen.Format("15:04:05")
			lastSeenISO = agg.lastSeen.UTC().Format(time.RFC3339)
		}
		firstSeenISO := ""
		if !agg.firstSeen.IsZero() {
			firstSeenISO = agg.firstSeen.UTC().Format(time.RFC3339)
		}
		topURIs := topKeysByCount(agg.uriCounts, 5)

		result = append(result, modsecBlockView{
			IP:           agg.ip,
			RuleID:       agg.ruleID,
			Description:  agg.description,
			Domains:      domains,
			DomainList:   domainList,
			DomainCount:  len(agg.domains),
			Hits:         agg.hits,
			LastSeen:     lastSeen,
			FirstSeen:    firstSeenISO,
			LastSeenISO:  lastSeenISO,
			TopURIs:      topURIs,
			SampleEvents: agg.samples,
			Escalated:    agg.escalated,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Hits != result[j].Hits {
			return result[i].Hits > result[j].Hits
		}
		if result[i].Escalated != result[j].Escalated {
			return result[i].Escalated
		}
		if result[i].LastSeenISO != result[j].LastSeenISO {
			return result[i].LastSeenISO > result[j].LastSeenISO
		}
		if result[i].IP != result[j].IP {
			return result[i].IP < result[j].IP
		}
		return result[i].RuleID < result[j].RuleID
	})

	if truncated {
		w.Header().Set("X-CSM-Truncated", "1")
	}
	writeJSON(w, result)
}

// apiModSecEvents returns the most recent individual ModSecurity events.
func (s *Server) apiModSecEvents(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	findings := deduplicateModSecFindings(s.modsecFindings24h())

	result := make([]modsecEventView, 0, limit)
	for _, f := range findings {
		if isModSecEscalation(f.Check) {
			continue
		}
		if len(result) >= limit {
			break
		}
		result = append(result, modsecEventView{
			Time:     f.Timestamp.Format("15:04:05"),
			TimeISO:  f.Timestamp.UTC().Format(time.RFC3339),
			IP:       extractModSecIP(f),
			RuleID:   extractModSecRule(f),
			Hostname: extractModSecHostname(f),
			URI:      extractModSecURI(f),
			Severity: f.Severity.String(),
		})
	}

	writeJSON(w, result)
}

// deduplicateModSecFindings merges Apache + LiteSpeed duplicate events.
// Both log the same block within the same second - keep one with merged fields.
func deduplicateModSecFindings(findings []alert.Finding) []alert.Finding {
	type dedupKey struct {
		second time.Time
		ip     string
		rule   string
	}
	seen := make(map[dedupKey]int) // key → index in result
	var result []alert.Finding

	for _, f := range findings {
		ip := extractModSecIP(f)
		rule := extractModSecRule(f)
		ts := f.Timestamp.UTC().Truncate(time.Second)
		key := dedupKey{second: ts, ip: ip, rule: rule}

		if idx, ok := seen[key]; ok {
			// Merge richer details into existing entry
			existing := &result[idx]
			if extractModSecHostname(f) != "" && extractModSecHostname(*existing) == "" {
				existing.Details = f.Details
			}
		} else {
			seen[key] = len(result)
			result = append(result, f)
		}
	}
	return result
}

func isModSecEscalation(check string) bool {
	return check == "modsec_block_escalation" || check == "modsec_csm_block_escalation"
}

// modsecFindings24h returns all modsec findings from the last 24 hours.
func (s *Server) modsecFindings24h() []alert.Finding {
	findings, _ := s.modsecFindings24hWithTruncation()
	return findings
}

func (s *Server) modsecFindings24hWithTruncation() ([]alert.Finding, bool) {
	db := store.Global()
	if db == nil {
		return nil, false
	}

	cutoff := time.Now().Add(-24 * time.Hour)
	findings := db.SearchHistorySince(cutoff, modsecFindingsScanCap+1, func(f alert.Finding) bool {
		return strings.HasPrefix(f.Check, "modsec_")
	})
	if len(findings) > modsecFindingsScanCap {
		return findings[:modsecFindingsScanCap], true
	}
	return findings, false
}

// --- Field extraction from finding Details ---
// Details format: "Rule: NNNN\nMessage: ...\nHostname: ...\nURI: ..."

func extractModSecIP(f alert.Finding) string {
	// Try from message: "... from IP on ..." or "... from IP ..."
	msg := f.Message
	if idx := strings.Index(msg, " from "); idx >= 0 {
		rest := msg[idx+6:]
		if sp := strings.IndexAny(rest, " \n"); sp >= 0 {
			rest = rest[:sp]
		}
		if len(rest) >= 7 && rest[0] >= '0' && rest[0] <= '9' && strings.Count(rest, ".") == 3 {
			return rest
		}
	}
	// Fallback: parse [client IP] from raw log line in Details
	if ip := extractBetween(f.Details, "[client ", "]"); ip != "" {
		// Strip port if present (Apache 2.4: "IP:port")
		if strings.Count(ip, ":") == 1 {
			if idx := strings.LastIndex(ip, ":"); idx > 0 {
				ip = ip[:idx]
			}
		}
		return ip
	}
	// Fallback: LiteSpeed format - IP in [IP:PORT-CONN#VHOST]
	for _, field := range strings.Fields(f.Details) {
		if strings.HasPrefix(field, "[") && strings.Contains(field, "#") {
			inner := strings.TrimPrefix(field, "[")
			if colonIdx := strings.Index(inner, ":"); colonIdx > 0 {
				ip := inner[:colonIdx]
				if len(ip) >= 7 && ip[0] >= '0' && ip[0] <= '9' {
					return ip
				}
			}
		}
	}
	return ""
}

func extractModSecRule(f alert.Finding) string {
	// Try structured format first
	if v := extractDetailField(f.Details, "Rule: "); v != "" {
		return v
	}
	// Fallback: parse [id "NNNN"] from raw log line in Details
	return extractBetween(f.Details, `[id "`, `"]`)
}

// csmRuleDescriptions provides fallback descriptions for CSM custom rules.
// LiteSpeed error logs omit the [msg "..."] field, so the log-extracted
// description is often empty. This map ensures the UI always shows a
// meaningful description for rules we define ourselves.
var csmRuleDescriptions = map[string]string{
	"900001": "Blocked LEVIATHAN CGI extension access",
	"900002": "Blocked LEVIATHAN directory access",
	"900003": "Blocked PHP execution in uploads directory",
	"900004": "Blocked PHP execution in languages directory",
	"900005": "Blocked direct wp-config.php access",
	"900007": "XML-RPC rate limit exceeded",
	"900008": "Blocked known webshell filename access",
	"900009": "Blocked GSocket User-Agent",
	"900100": "WP-Automatic SQLi (CVE-2024-27956)",
	"900101": "LayerSlider SQLi (CVE-2024-2879)",
	"900102": "Really Simple Security auth bypass (CVE-2024-10924)",
	"900103": "LiteSpeed Cache directory traversal (CVE-2024-4345)",
	"900104": "Ultimate Member SQLi (CVE-2024-1071)",
	"900105": "Backup Migration RCE (CVE-2023-6553)",
	"900106": "GiveWP object injection (CVE-2024-5932)",
	"900107": "WP File Manager arbitrary upload (CVE-2024-3400)",
	"900110": "PHP object injection attempt",
	"900111": "Blocked PHP in wp-content/upgrade",
	"900112": "WordPress user enumeration blocked",
	"900113": "wp-login brute force rate limit",
	"900114": "wp-login brute force rate limit",
	"900115": "Blocked .env file access",
	"900116": "Blocked scanner probe",
	"900120": "Blocked wp-coder preview endpoint",
	"900121": "Blocked wp-coder attributes endpoint",
	// Comodo WAF (CWAF) common rules. Rule IDs in the 21xxxx range are
	// from the Comodo vendor ruleset (e.g. /etc/apache2/conf.d/
	// modsec_vendor_configs/comodo_litespeed/), NOT from OWASP CRS.
	// They were previously mislabeled as "OWASP:" here.
	"210710": "Comodo WAF: HTTP Request Smuggling",
	"210381": "Comodo WAF: HTTP Request Smuggling",
	"214930": "Comodo WAF: Inbound anomaly score threshold exceeded",
	"214940": "Comodo WAF: Outbound anomaly score threshold exceeded",
	"218420": "Comodo WAF: Request content type restriction",
	// OWASP CRS common rules. IDs in the 9xxxxx range are the standard
	// OWASP CRS 3.x schema (920xxx protocol, 930xxx LFI, 941xxx XSS,
	// 942xxx SQLi).
	"920170": "OWASP: Validate GET/HEAD request",
	"920420": "OWASP: Request content type is not allowed by policy",
	"920600": "OWASP: Illegal Accept header",
	"930100": "OWASP: Path traversal attack",
	"930110": "OWASP: Path traversal attack",
	"930120": "OWASP: OS file access attempt",
	"941100": "OWASP: XSS attack detected via libinjection",
	"941160": "OWASP: XSS Filter - Category 1",
	"942100": "OWASP: SQL injection attack detected via libinjection",
}

func extractModSecDescription(f alert.Finding) string {
	if v := extractDetailField(f.Details, "Message: "); v != "" {
		return v
	}
	if v := extractBetween(f.Details, `[msg "`, `"]`); v != "" {
		return v
	}
	// Fallback: use static description for CSM custom rules when the log
	// format (e.g. LiteSpeed) doesn't include the [msg "..."] field.
	rule := extractModSecRule(f)
	if desc, ok := csmRuleDescriptions[rule]; ok {
		return desc
	}
	return ""
}

func extractModSecHostname(f alert.Finding) string {
	if v := extractDetailField(f.Details, "Hostname: "); v != "" {
		return v
	}
	return extractBetween(f.Details, `[hostname "`, `"]`)
}

func extractModSecURI(f alert.Finding) string {
	if v := extractDetailField(f.Details, "URI: "); v != "" {
		return v
	}
	return extractBetween(f.Details, `[uri "`, `"]`)
}

func extractDetailField(details, prefix string) string {
	for _, line := range strings.Split(details, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	return ""
}

// looksLikeIP returns true if the string looks like an IP address (not a domain).
func looksLikeIP(s string) bool {
	if len(s) < 7 {
		return false
	}
	for _, c := range s {
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return strings.Count(s, ".") == 3
}

// extractBetween extracts the value between start and end delimiters.
// Used as fallback for old findings where Details is the raw log line.
func extractBetween(s, start, end string) string {
	idx := strings.Index(s, start)
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(start):]
	endIdx := strings.Index(rest, end)
	if endIdx < 0 {
		return ""
	}
	return rest[:endIdx]
}
