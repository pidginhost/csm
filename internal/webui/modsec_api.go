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

// modsecBlockView is an aggregated view of blocks per IP+rule.
type modsecBlockView struct {
	IP          string `json:"ip"`
	RuleID      string `json:"rule_id"`
	Description string `json:"description"`
	Domains     string `json:"domains"`
	Hits        int    `json:"hits"`
	LastSeen    string `json:"last_seen"`
	Escalated   bool   `json:"escalated"`
}

// modsecEventView is a single ModSecurity event.
type modsecEventView struct {
	Time     string `json:"time"`
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
		if f.Check == "modsec_csm_block_escalation" {
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

// apiModSecBlocks returns aggregated blocks per IP+rule for the last 24h.
func (s *Server) apiModSecBlocks(w http.ResponseWriter, _ *http.Request) {
	findings := deduplicateModSecFindings(s.modsecFindings24h())

	// Aggregate by IP
	type ipAgg struct {
		ruleID      string
		description string
		domains     map[string]bool
		hits        int
		lastSeen    time.Time
		escalated   bool
	}

	byIP := make(map[string]*ipAgg)

	for _, f := range findings {
		if f.Check == "modsec_csm_block_escalation" {
			// Mark IP as escalated
			ip := extractModSecIP(f)
			if ip != "" {
				if agg, ok := byIP[ip]; ok {
					agg.escalated = true
				} else {
					byIP[ip] = &ipAgg{escalated: true, domains: make(map[string]bool)}
				}
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

		agg, ok := byIP[ip]
		if !ok {
			agg = &ipAgg{
				ruleID:      rule,
				description: desc,
				domains:     make(map[string]bool),
			}
			byIP[ip] = agg
		}
		agg.hits++
		if f.Timestamp.After(agg.lastSeen) {
			agg.lastSeen = f.Timestamp
			// Update rule/desc to the most recent
			if rule != "" {
				agg.ruleID = rule
			}
			if desc != "" {
				agg.description = desc
			}
		}
		// Skip server IPs and empty hostnames - only show actual domain names.
		// ModSecurity logs the server IP as hostname when the request doesn't
		// match a specific vhost (e.g. direct IP access, SNI mismatch).
		if domain != "" && !looksLikeIP(domain) {
			agg.domains[domain] = true
		}
	}

	var result []modsecBlockView
	for ip, agg := range byIP {
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
		if !agg.lastSeen.IsZero() {
			lastSeen = agg.lastSeen.Format("15:04:05")
		}

		result = append(result, modsecBlockView{
			IP:          ip,
			RuleID:      agg.ruleID,
			Description: agg.description,
			Domains:     domains,
			Hits:        agg.hits,
			LastSeen:    lastSeen,
			Escalated:   agg.escalated,
		})
	}

	// Sort by hits descending
	sort.Slice(result, func(i, j int) bool {
		return result[i].Hits > result[j].Hits
	})

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

	// Collect from the tail (newest entries) to avoid reversing the entire slice
	start := len(findings) - limit
	if start < 0 {
		start = 0
	}
	result := make([]modsecEventView, 0, limit)
	for i := len(findings) - 1; i >= start; i-- {
		f := findings[i]
		if f.Check == "modsec_csm_block_escalation" {
			continue
		}
		if len(result) >= limit {
			break
		}
		result = append(result, modsecEventView{
			Time:     f.Timestamp.Format("15:04:05"),
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
		second string
		ip     string
		rule   string
	}
	seen := make(map[dedupKey]int) // key → index in result
	var result []alert.Finding

	for _, f := range findings {
		ip := extractModSecIP(f)
		rule := extractModSecRule(f)
		ts := f.Timestamp.Format("15:04:05")
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

// modsecFindings24h returns all modsec findings from the last 24 hours.
func (s *Server) modsecFindings24h() []alert.Finding {
	db := store.Global()
	if db == nil {
		return nil
	}

	// ReadHistoryFiltered expects "YYYY-MM-DD" for the from parameter.
	// Use yesterday's date to ensure we cover the full 24h window.
	cutoff := time.Now().Add(-24 * time.Hour)
	all, _ := db.ReadHistoryFiltered(10000, 0, cutoff.Format("2006-01-02"), "", -1, "modsec_")

	// Further filter to exact 24h window (from prefix is date-level granularity)
	var filtered []alert.Finding
	for _, f := range all {
		if f.Timestamp.After(cutoff) {
			filtered = append(filtered, f)
		}
	}
	return filtered
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
