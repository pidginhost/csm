package webui

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

var reIPReputation = regexp.MustCompile(`Known malicious IP accessing server: (\S+) \((.+)\)`)

// apiStatus returns daemon status and uptime.
func (s *Server) apiStatus(w http.ResponseWriter, _ *http.Request) {
	s.scanMu.Lock()
	scanning := s.scanRunning
	s.scanMu.Unlock()

	status := map[string]interface{}{
		"hostname":       s.cfg.Hostname,
		"uptime":         time.Since(s.startTime).String(),
		"started_at":     s.startTime.Format(time.RFC3339),
		"rules_loaded":   s.sigCount,
		"scan_running":   scanning,
		"last_scan_time": s.store.LatestScanTime().Format(time.RFC3339),
	}
	writeJSON(w, status)
}

// apiFindings returns current scan results - "what's wrong right now."
func (s *Server) apiFindings(w http.ResponseWriter, _ *http.Request) {
	latest := s.store.LatestFindings()

	type entryView struct {
		Severity  int    `json:"severity"`
		Check     string `json:"check"`
		Message   string `json:"message"`
		Details   string `json:"details,omitempty"`
		Time      string `json:"time"`
		FirstSeen string `json:"first_seen"`
		LastSeen  string `json:"last_seen"`
		HasFix    bool   `json:"has_fix"`
	}

	suppressions := s.store.LoadSuppressions()
	var result []entryView
	for _, f := range latest {
		if f.Check == "auto_response" || f.Check == "auto_block" || f.Check == "check_timeout" || f.Check == "health" {
			continue
		}
		// Skip suppressed findings
		if s.store.IsSuppressed(f, suppressions) {
			continue
		}
		firstSeen := f.Timestamp
		lastSeen := f.Timestamp
		if entry, ok := s.store.EntryForKey(f.Key()); ok {
			firstSeen = entry.FirstSeen
			lastSeen = entry.LastSeen
		}
		result = append(result, entryView{
			Severity:  int(f.Severity),
			Check:     f.Check,
			Message:   f.Message,
			Details:   f.Details,
			Time:      f.Timestamp.Format(time.RFC3339),
			FirstSeen: firstSeen.Format(time.RFC3339),
			LastSeen:  lastSeen.Format(time.RFC3339),
			HasFix:    checks.HasFix(f.Check),
		})
	}
	writeJSON(w, result)
}

// enrichedFinding is the JSON response type for the enriched findings endpoint.
type enrichedFinding struct {
	Key       string `json:"key"`
	Severity  string `json:"severity"`
	SevClass  string `json:"sev_class"`
	Check     string `json:"check"`
	Message   string `json:"message"`
	FilePath  string `json:"file_path,omitempty"`
	Account   string `json:"account,omitempty"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	HasFix    bool   `json:"has_fix"`
	FixDesc   string `json:"fix_desc,omitempty"`
}

// dedupIPReputation groups ip_reputation findings by IP, merging sources and
// promoting to the highest severity. Non-ip_reputation findings pass through unchanged.
func dedupIPReputation(items []enrichedFinding) []enrichedFinding {
	type ipGroup struct {
		entry   enrichedFinding
		sources []string
	}
	ipGroups := make(map[string]*ipGroup)
	var ipOrder []string
	var result []enrichedFinding

	for _, item := range items {
		if item.Check != "ip_reputation" {
			result = append(result, item)
			continue
		}
		m := reIPReputation.FindStringSubmatch(item.Message)
		if m == nil {
			result = append(result, item)
			continue
		}
		ip, source := m[1], m[2]
		if g, ok := ipGroups[ip]; ok {
			g.sources = append(g.sources, source)
			if item.FirstSeen < g.entry.FirstSeen {
				g.entry.FirstSeen = item.FirstSeen
			}
			if item.LastSeen > g.entry.LastSeen {
				g.entry.LastSeen = item.LastSeen
			}
			if severityRank(item.Severity) > severityRank(g.entry.Severity) {
				g.entry.Severity = item.Severity
				g.entry.SevClass = item.SevClass
			}
		} else {
			ipGroups[ip] = &ipGroup{
				entry:   item,
				sources: []string{source},
			}
			ipOrder = append(ipOrder, ip)
		}
	}
	for _, ip := range ipOrder {
		g := ipGroups[ip]
		g.entry.Message = fmt.Sprintf("Known malicious IP accessing server: %s (%s)", ip, strings.Join(g.sources, ", "))
		result = append(result, g.entry)
	}
	return result
}

// apiFindingsEnriched returns findings with IP dedup, account extraction, and severity counts.
func (s *Server) apiFindingsEnriched(w http.ResponseWriter, _ *http.Request) {
	latest := s.store.LatestFindings()
	suppressions := s.store.LoadSuppressions()

	items := make([]enrichedFinding, 0)
	for _, f := range latest {
		if f.Check == "auto_response" || f.Check == "auto_block" || f.Check == "check_timeout" || f.Check == "health" {
			continue
		}
		if s.store.IsSuppressed(f, suppressions) {
			continue
		}
		firstSeen := f.Timestamp
		lastSeen := f.Timestamp
		if entry, ok := s.store.EntryForKey(f.Key()); ok {
			firstSeen = entry.FirstSeen
			lastSeen = entry.LastSeen
		}
		items = append(items, enrichedFinding{
			Key:       f.Key(),
			Severity:  severityLabel(f.Severity),
			SevClass:  severityClass(f.Severity),
			Check:     f.Check,
			Message:   f.Message,
			FilePath:  f.FilePath,
			Account:   extractAccountFromFinding(f),
			FirstSeen: firstSeen.Format(time.RFC3339),
			LastSeen:  lastSeen.Format(time.RFC3339),
			HasFix:    checks.HasFix(f.Check),
			FixDesc:   checks.FixDescription(f.Check, f.Message, f.FilePath),
		})
	}

	items = dedupIPReputation(items)

	var critCount, highCount, warnCount int
	for _, item := range items {
		switch item.Severity {
		case "CRITICAL":
			critCount++
		case "HIGH":
			highCount++
		default:
			warnCount++
		}
	}

	checkTypeSet := make(map[string]bool)
	accountSet := make(map[string]bool)
	for _, item := range items {
		checkTypeSet[item.Check] = true
		if item.Account != "" {
			accountSet[item.Account] = true
		}
	}
	checkTypes := make([]string, 0, len(checkTypeSet))
	for ct := range checkTypeSet {
		checkTypes = append(checkTypes, ct)
	}
	sort.Strings(checkTypes)
	accounts := make([]string, 0, len(accountSet))
	for a := range accountSet {
		accounts = append(accounts, a)
	}
	sort.Strings(accounts)

	writeJSON(w, map[string]interface{}{
		"findings":       items,
		"check_types":    checkTypes,
		"accounts":       accounts,
		"critical_count": critCount,
		"high_count":     highCount,
		"warning_count":  warnCount,
		"total":          len(items),
	})
}

// apiHistory returns paginated history from history.jsonl.
// Supports optional filtering via "from", "to" (YYYY-MM-DD), and "severity" (0/1/2) query params.
func (s *Server) apiHistory(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	if limit > 5000 {
		limit = 5000
	}
	offset := queryInt(r, "offset", 0)

	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	sevStr := r.URL.Query().Get("severity")

	searchStr := r.URL.Query().Get("search")

	checksStr := r.URL.Query().Get("checks")
	var checksFilter map[string]bool
	if checksStr != "" {
		checksFilter = make(map[string]bool)
		for _, c := range strings.Split(checksStr, ",") {
			c = strings.TrimSpace(c)
			if c != "" {
				checksFilter[c] = true
			}
		}
	}

	// If no filters, use simple paginated read
	if fromStr == "" && toStr == "" && sevStr == "" && searchStr == "" && checksStr == "" {
		findings, total := s.store.ReadHistory(limit, offset)
		writeJSON(w, map[string]interface{}{
			"findings": findings,
			"total":    total,
			"limit":    limit,
			"offset":   offset,
		})
		return
	}

	// With filters: read all history, filter, then paginate
	var fromDate, toDate time.Time
	if fromStr != "" {
		fromDate, _ = time.ParseInLocation("2006-01-02", fromStr, time.Local)
	}
	if toStr != "" {
		toDate, _ = time.ParseInLocation("2006-01-02", toStr, time.Local)
		toDate = toDate.Add(24*time.Hour - time.Second)
	}
	sevFilter := -1
	if sevStr != "" {
		sevFilter = queryInt(r, "severity", -1)
	}
	searchLower := strings.ToLower(searchStr)

	allFindings, _ := s.store.ReadHistory(5000, 0)
	var filtered []alert.Finding
	for _, f := range allFindings {
		if !fromDate.IsZero() && f.Timestamp.Before(fromDate) {
			continue
		}
		if !toDate.IsZero() && f.Timestamp.After(toDate) {
			continue
		}
		if sevFilter >= 0 && int(f.Severity) != sevFilter {
			continue
		}
		if searchStr != "" {
			if !strings.Contains(strings.ToLower(f.Check), searchLower) &&
				!strings.Contains(strings.ToLower(f.Message), searchLower) &&
				!strings.Contains(strings.ToLower(f.Details), searchLower) {
				continue
			}
		}
		if checksFilter != nil && !checksFilter[f.Check] {
			continue
		}
		filtered = append(filtered, f)
	}

	total := len(filtered)
	// Apply offset and limit
	if offset > len(filtered) {
		filtered = nil
	} else {
		filtered = filtered[offset:]
		if len(filtered) > limit {
			filtered = filtered[:limit]
		}
	}

	writeJSON(w, map[string]interface{}{
		"findings": filtered,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
	})
}

const quarantineDir = "/opt/csm/quarantine"

// apiQuarantine lists quarantined files with metadata.
func (s *Server) apiQuarantine(w http.ResponseWriter, _ *http.Request) {

	type quarantineEntry struct {
		ID           string `json:"id"`
		OriginalPath string `json:"original_path"`
		Size         int64  `json:"size"`
		QuarantineAt string `json:"quarantined_at"`
		Reason       string `json:"reason"`
	}

	var entries []quarantineEntry

	// Scan both root quarantine dir and pre_clean subdirectory
	rootMetas := listMetaFiles(quarantineDir)
	preCleanMetas := listMetaFiles(filepath.Join(quarantineDir, "pre_clean"))
	metaFiles := rootMetas
	metaFiles = append(metaFiles, preCleanMetas...)
	for _, metaFile := range metaFiles {
		meta, err := readQuarantineMeta(metaFile)
		if err != nil {
			continue
		}

		entries = append(entries, quarantineEntry{
			ID:           quarantineEntryID(metaFile),
			OriginalPath: meta.OriginalPath,
			Size:         meta.Size,
			QuarantineAt: meta.QuarantineAt.Format(time.RFC3339),
			Reason:       meta.Reason,
		})
	}

	// Sort newest first
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].QuarantineAt > entries[j].QuarantineAt
	})

	writeJSON(w, entries)
}

// apiStats returns severity counts and per-check breakdown.
func (s *Server) apiStats(w http.ResponseWriter, _ *http.Request) {
	last24h := time.Now().Add(-24 * time.Hour)
	findings := s.store.ReadHistorySince(last24h)

	critical, high, warning := 0, 0, 0
	byCheck := make(map[string]int)

	for _, f := range findings {
		switch f.Severity {
		case alert.Critical:
			critical++
		case alert.High:
			high++
		case alert.Warning:
			warning++
		}
		byCheck[f.Check]++
	}

	// Find most recent critical finding for "time since last critical"
	// (findings are newest-first from ReadHistorySince)
	lastCriticalAgo := "None"
	for _, f := range findings {
		if f.Severity == alert.Critical {
			lastCriticalAgo = timeAgo(f.Timestamp)
			break
		}
	}

	// Compute accounts at risk: accounts with critical/high findings in 24h
	accountRisk := make(map[string]int) // account -> highest severity
	// Auto-response summary: count actions by type in 24h
	autoBlocked, autoQuarantined, autoKilled := 0, 0, 0
	// Top targeted accounts
	accountHits := make(map[string]int)
	// Brute force summary
	bruteForceIPs := make(map[string]int)   // IP -> total attempts
	bruteForceTypes := make(map[string]int) // "wp-login" / "xmlrpc" -> count

	for _, f := range findings {
		// Extract account from finding path/message
		acct := extractAccountFromFinding(f)
		if acct != "" {
			accountHits[acct]++
			sev := int(f.Severity)
			if prev, ok := accountRisk[acct]; !ok || sev > prev {
				accountRisk[acct] = sev
			}
		}
		// Count auto-response actions
		switch f.Check {
		case "auto_block":
			autoBlocked++
		case "auto_response":
			if strings.Contains(f.Message, "quarantin") {
				autoQuarantined++
			} else if strings.Contains(f.Message, "kill") || strings.Contains(f.Message, "Kill") {
				autoKilled++
			}
		case "wp_login_bruteforce":
			bruteForceTypes["wp-login"]++
			if ip := checks.ExtractIPFromFinding(f); ip != "" {
				bruteForceIPs[ip]++
			}
		case "xmlrpc_abuse":
			bruteForceTypes["xmlrpc"]++
			if ip := checks.ExtractIPFromFinding(f); ip != "" {
				bruteForceIPs[ip]++
			}
		case "modsec_csm_block_escalation":
			if strings.Contains(f.Message, "xmlrpc") || strings.Contains(f.Message, "900006") || strings.Contains(f.Message, "900007") {
				bruteForceTypes["xmlrpc-modsec"]++
			}
		}
	}

	// Accounts at risk: those with critical or high severity
	var atRisk []map[string]interface{}
	for acct, sev := range accountRisk {
		if sev >= int(alert.High) {
			atRisk = append(atRisk, map[string]interface{}{
				"account":  acct,
				"severity": sev,
				"findings": accountHits[acct],
			})
		}
	}
	// Sort by severity desc, then findings desc
	sort.Slice(atRisk, func(i, j int) bool {
		if atRisk[i]["severity"].(int) != atRisk[j]["severity"].(int) {
			return atRisk[i]["severity"].(int) > atRisk[j]["severity"].(int)
		}
		return atRisk[i]["findings"].(int) > atRisk[j]["findings"].(int)
	})
	if len(atRisk) > 50 {
		atRisk = atRisk[:50]
	}

	// Top targeted accounts (by finding count)
	type acctCount struct {
		Account string `json:"account"`
		Count   int    `json:"count"`
	}
	var topAccounts []acctCount
	for acct, count := range accountHits {
		topAccounts = append(topAccounts, acctCount{acct, count})
	}
	sort.Slice(topAccounts, func(i, j int) bool {
		return topAccounts[i].Count > topAccounts[j].Count
	})
	if len(topAccounts) > 5 {
		topAccounts = topAccounts[:5]
	}

	result := map[string]interface{}{
		"last_24h": map[string]interface{}{
			"critical": critical,
			"high":     high,
			"warning":  warning,
			"total":    critical + high + warning,
		},
		"by_check":          byCheck,
		"last_critical_ago": lastCriticalAgo,
		"accounts_at_risk":  atRisk,
		"auto_response": map[string]int{
			"blocked":     autoBlocked,
			"quarantined": autoQuarantined,
			"killed":      autoKilled,
		},
		"top_accounts": topAccounts,
		"brute_force":  buildBruteForceSummary(bruteForceIPs, bruteForceTypes),
	}
	writeJSON(w, result)
}

func buildBruteForceSummary(ips map[string]int, types map[string]int) map[string]interface{} {
	// Top attacker IPs
	type ipCount struct {
		IP    string `json:"ip"`
		Count int    `json:"count"`
	}
	var topIPs []ipCount
	for ip, count := range ips {
		topIPs = append(topIPs, ipCount{ip, count})
	}
	sort.Slice(topIPs, func(i, j int) bool {
		return topIPs[i].Count > topIPs[j].Count
	})
	if len(topIPs) > 10 {
		topIPs = topIPs[:10]
	}

	total := 0
	for _, v := range types {
		total += v
	}

	return map[string]interface{}{
		"total_attacks":  total,
		"unique_ips":     len(ips),
		"wp_login_count": types["wp-login"],
		"xmlrpc_count":   types["xmlrpc"] + types["xmlrpc-modsec"],
		"top_ips":        topIPs,
	}
}

// apiStatsTrend returns 30-day daily finding counts by severity.
// Uses efficient bbolt cursor seeking instead of loading all findings into memory.
func (s *Server) apiStatsTrend(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.store.AggregateByDay())
}

// apiStatsTimeline returns 24 hourly buckets for the findings timeline chart.
// Uses efficient bbolt cursor seeking instead of loading all findings into memory.
func (s *Server) apiStatsTimeline(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.store.AggregateByHour())
}

// apiHealth returns daemon health status.
func (s *Server) apiHealth(w http.ResponseWriter, _ *http.Request) {
	health := map[string]interface{}{
		"daemon_mode":    true,
		"uptime":         time.Since(s.startTime).String(),
		"uptime_seconds": int(time.Since(s.startTime).Seconds()),
		"rules_loaded":   s.sigCount,
		"fanotify":       s.fanotifyActive,
		"log_watchers":   s.logWatcherCount,
	}
	writeJSON(w, health)
}

// apiHistoryCSV exports history as CSV download.
func (s *Server) apiHistoryCSV(w http.ResponseWriter, _ *http.Request) {
	findings, _ := s.store.ReadHistory(5000, 0)

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=csm-history.csv")

	// CSV header
	fmt.Fprintf(w, "Timestamp,Severity,Check,Message,Details\n")
	for _, f := range findings {
		sev := "WARNING"
		switch f.Severity {
		case alert.Critical:
			sev = "CRITICAL"
		case alert.High:
			sev = "HIGH"
		}
		// Escape CSV fields
		msg := csvEscape(f.Message)
		details := csvEscape(f.Details)
		fmt.Fprintf(w, "%s,%s,%s,%s,%s\n",
			f.Timestamp.Format(time.RFC3339), sev, f.Check, msg, details)
	}
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

// apiFix applies a known remediation action for a finding.
// POST /api/v1/fix  body: {"check": "check_type", "message": "...", "details": "..."}
func (s *Server) apiFix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Check    string `json:"check"`
		Message  string `json:"message"`
		Details  string `json:"details"`
		FilePath string `json:"file_path"`
	}
	if err := decodeJSONBodyLimited(w, r, 64*1024, &req); err != nil || req.Check == "" || req.Message == "" {
		writeJSONError(w, "check and message are required", http.StatusBadRequest)
		return
	}

	if !checks.HasFix(req.Check) {
		writeJSONError(w, "no automated fix available for this check type", http.StatusBadRequest)
		return
	}

	result := checks.ApplyFix(req.Check, req.Message, req.Details, req.FilePath)

	// If fix succeeded, dismiss from both alert state and latest findings
	if result.Success {
		key := req.Check + ":" + req.Message
		s.store.DismissFinding(key)
		s.store.DismissLatestFinding(key)
		s.auditLog(r, "fix", req.Check, result.Action)
	}

	writeJSON(w, result)
}

// apiBulkFix applies fixes to multiple findings at once.
// POST /api/v1/fix-bulk  body: [{"check":"...", "message":"...", "details":"..."}, ...]
func (s *Server) apiBulkFix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqs []struct {
		Check    string `json:"check"`
		Message  string `json:"message"`
		Details  string `json:"details"`
		FilePath string `json:"file_path"`
	}
	if err := decodeJSONBodyLimited(w, r, 64*1024, &reqs); err != nil {
		writeJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	var results []checks.RemediationResult
	for _, req := range reqs {
		if !checks.HasFix(req.Check) {
			results = append(results, checks.RemediationResult{
				Error: fmt.Sprintf("no fix for %s", req.Check),
			})
			continue
		}
		result := checks.ApplyFix(req.Check, req.Message, req.Details, req.FilePath)
		if result.Success {
			key := req.Check + ":" + req.Message
			s.store.DismissFinding(key)
			s.store.DismissLatestFinding(key)
		}
		results = append(results, result)
	}

	succeeded := 0
	for _, r := range results {
		if r.Success {
			succeeded++
		}
	}

	writeJSON(w, map[string]interface{}{
		"results":   results,
		"total":     len(results),
		"succeeded": succeeded,
		"failed":    len(results) - succeeded,
	})
}

// apiFixPreview returns what a fix would do without applying it.
// GET /api/v1/fix-preview?check=...&message=...
// apiAccounts returns a list of cPanel account usernames for the scan dropdown.
//
//nolint:unused // registered via mux.Handle in server.go
func (s *Server) apiAccounts(w http.ResponseWriter, _ *http.Request) {
	entries, err := os.ReadDir("/home")
	if err != nil {
		writeJSON(w, []string{})
		return
	}

	var accounts []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Skip system/hidden directories
		if strings.HasPrefix(name, ".") || name == "virtfs" || name == "cPanelInstall" ||
			name == "cpanelsolr" || name == "lost+found" {
			continue
		}
		// Must have public_html to be a real cPanel account
		if _, err := os.Stat(filepath.Join("/home", name, "public_html")); err == nil {
			accounts = append(accounts, name)
		}
	}

	writeJSON(w, accounts)
}

// --- Action endpoints ---

// apiBlockIP blocks an IP via the firewall engine.
// POST /api/v1/block-ip  body: {"ip": "1.2.3.4", "reason": "..."}
func (s *Server) apiBlockIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP       string `json:"ip"`
		Reason   string `json:"reason"`
		Duration string `json:"duration"`
	}
	if err := decodeJSONBodyLimited(w, r, 64*1024, &req); err != nil {
		writeJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.IP == "" {
		writeJSONError(w, "IP is required", http.StatusBadRequest)
		return
	}
	if _, err := parseAndValidateIP(req.IP); err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		req.Reason = "Blocked via CSM Web UI"
	}

	dur := parseDuration(req.Duration)

	if s.blocker == nil {
		writeJSONError(w, "Firewall engine not available", http.StatusServiceUnavailable)
		return
	}
	if err := s.blocker.BlockIP(req.IP, req.Reason, dur); err != nil {
		writeJSONError(w, fmt.Sprintf("Block failed: %v", err), http.StatusInternalServerError)
		return
	}

	s.auditLog(r, "block_ip", req.IP, req.Reason)
	writeJSON(w, map[string]string{"status": "blocked", "ip": req.IP})
}

// apiUnblockIP removes an IP from the firewall + cphulk.
// POST /api/v1/unblock-ip  body: {"ip": "1.2.3.4"}
func (s *Server) apiUnblockIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := decodeJSONBodyLimited(w, r, 64*1024, &req); err != nil || req.IP == "" {
		writeJSONError(w, "IP is required", http.StatusBadRequest)
		return
	}

	if _, err := parseAndValidateIP(req.IP); err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if s.blocker == nil {
		writeJSONError(w, "Firewall engine not available", http.StatusServiceUnavailable)
		return
	}
	if err := s.blocker.UnblockIP(req.IP); err != nil {
		writeJSONError(w, fmt.Sprintf("Unblock failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Also flush from cphulk (cPanel brute force detector)
	flushCphulk(req.IP)

	s.auditLog(r, "unblock_ip", req.IP, "manual unblock via UI")
	writeJSON(w, map[string]string{"status": "unblocked", "ip": req.IP})
}

// apiUnblockBulk unblocks multiple IPs at once.
func (s *Server) apiUnblockBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IPs []string `json:"ips"`
	}
	if err := decodeJSONBodyLimited(w, r, 64*1024, &req); err != nil || len(req.IPs) == 0 {
		writeJSONError(w, "IPs array is required", http.StatusBadRequest)
		return
	}
	if len(req.IPs) > 100 {
		writeJSONError(w, "IPs must be 1-100 items", http.StatusBadRequest)
		return
	}
	if s.blocker == nil {
		writeJSONError(w, "Firewall engine not available", http.StatusServiceUnavailable)
		return
	}

	succeeded := 0
	for _, ip := range req.IPs {
		if _, err := parseAndValidateIP(ip); err != nil {
			continue
		}
		if err := s.blocker.UnblockIP(ip); err != nil {
			continue
		}
		flushCphulk(ip)
		s.auditLog(r, "unblock_ip", ip, "bulk unblock via UI")
		succeeded++
	}

	writeJSON(w, map[string]interface{}{
		"status":    "completed",
		"total":     len(req.IPs),
		"succeeded": succeeded,
	})
}

// blockedEntry is a raw blocked IP record from firewall state.
type blockedEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Source    string    `json:"source,omitempty"`
	BlockedAt time.Time `json:"blocked_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type blockedView struct {
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
	Source    string `json:"source"`
	BlockedAt string `json:"blocked_at"`
	ExpiresAt string `json:"expires_at"`
	ExpiresIn string `json:"expires_in"`
}

func formatBlockedView(b blockedEntry) (blockedView, bool) {
	if !b.ExpiresAt.IsZero() && time.Now().After(b.ExpiresAt) {
		return blockedView{}, false // expired
	}
	view := blockedView{
		IP:        b.IP,
		Reason:    b.Reason,
		Source:    b.Source,
		BlockedAt: b.BlockedAt.Format(time.RFC3339),
	}
	if view.Source == "" {
		view.Source = firewall.InferProvenance("block", b.Reason)
	}
	if !b.ExpiresAt.IsZero() {
		remaining := time.Until(b.ExpiresAt)
		view.ExpiresAt = b.ExpiresAt.Format(time.RFC3339)
		view.ExpiresIn = fmt.Sprintf("%dh%dm", int(remaining.Hours()), int(remaining.Minutes())%60)
	} else {
		view.ExpiresIn = "permanent"
	}
	return view, true
}

// apiBlockedIPs returns the list of currently blocked IPs.
// Uses bbolt store when available, falls back to flat files.
func (s *Server) apiBlockedIPs(w http.ResponseWriter, _ *http.Request) {
	var result []blockedView

	// Try bbolt store first.
	if sdb := store.Global(); sdb != nil {
		ss := sdb.LoadFirewallState()
		for _, entry := range ss.Blocked {
			b := blockedEntry{
				IP:        entry.IP,
				Reason:    entry.Reason,
				BlockedAt: entry.BlockedAt,
				ExpiresAt: entry.ExpiresAt,
			}
			if view, ok := formatBlockedView(b); ok {
				result = append(result, view)
			}
		}
		writeJSON(w, result)
		return
	}

	// Fallback: try firewall engine state.json
	fwFile := filepath.Join(s.cfg.StatePath, "firewall", "state.json")
	if fwData, err := os.ReadFile(fwFile); err == nil {
		var fwState struct {
			Blocked []blockedEntry `json:"blocked"`
		}
		if json.Unmarshal(fwData, &fwState) == nil {
			for _, b := range fwState.Blocked {
				if view, ok := formatBlockedView(b); ok {
					result = append(result, view)
				}
			}
			writeJSON(w, result)
			return
		}
	}

	// Fall back to blocked_ips.json (legacy)
	stateFile := filepath.Join(s.cfg.StatePath, "blocked_ips.json")
	data, err := os.ReadFile(stateFile)
	if err != nil {
		writeJSON(w, []interface{}{})
		return
	}

	var blockState struct {
		IPs []blockedEntry `json:"ips"`
	}
	if err := json.Unmarshal(data, &blockState); err != nil {
		writeJSON(w, []interface{}{})
		return
	}

	for _, b := range blockState.IPs {
		if view, ok := formatBlockedView(b); ok {
			result = append(result, view)
		}
	}
	writeJSON(w, result)
}

// apiDismissFinding marks a finding as baseline (acknowledged/dismissed).
// POST /api/v1/dismiss  body: {"key": "check:message"}
func (s *Server) apiDismissFinding(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Key string `json:"key"`
	}
	if err := decodeJSONBodyLimited(w, r, 16*1024, &req); err != nil || req.Key == "" {
		writeJSONError(w, "Key is required", http.StatusBadRequest)
		return
	}

	s.store.DismissFinding(req.Key)
	s.store.DismissLatestFinding(req.Key)
	s.auditLog(r, "dismiss", req.Key, "")
	writeJSON(w, map[string]string{"status": "dismissed", "key": req.Key})
}

// apiQuarantineRestore restores a quarantined file to its original location.
// POST /api/v1/quarantine-restore  body: {"id": "filename"}
func (s *Server) apiQuarantineRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := decodeJSONBodyLimited(w, r, 16*1024, &req); err != nil || req.ID == "" {
		writeJSONError(w, "ID is required", http.StatusBadRequest)
		return
	}

	entry, err := resolveQuarantineEntry(req.ID)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	metaData, err := os.ReadFile(entry.MetaPath)
	if err != nil {
		writeJSONError(w, "Quarantine entry not found", http.StatusNotFound)
		return
	}

	var meta struct {
		OriginalPath string `json:"original_path"`
		Owner        int    `json:"owner_uid"`
		Group        int    `json:"group_gid"`
		Mode         string `json:"mode"`
	}
	if unmarshalErr := json.Unmarshal(metaData, &meta); unmarshalErr != nil {
		writeJSONError(w, "Invalid metadata", http.StatusInternalServerError)
		return
	}

	restorePath, err := validateQuarantineRestorePath(meta.OriginalPath)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Ensure parent directory exists
	parentDir := filepath.Dir(restorePath)
	if mkdirErr := os.MkdirAll(parentDir, 0755); mkdirErr != nil {
		writeJSONError(w, fmt.Sprintf("Cannot create parent directory: %v", mkdirErr), http.StatusInternalServerError)
		return
	}

	// Check if quarantined item is a directory or file
	quarInfo, err := os.Stat(entry.ItemPath)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("Cannot stat quarantined file: %v", err), http.StatusInternalServerError)
		return
	}

	// Parse original mode from metadata (format: "-rw-r--r--" or "drwxr-xr-x")
	restoredMode := os.FileMode(0644)
	if meta.Mode != "" && len(meta.Mode) >= 10 {
		restoredMode = parseModeString(meta.Mode)
	}

	if quarInfo.IsDir() {
		if _, statErr := os.Lstat(restorePath); statErr == nil {
			writeJSONError(w, "Cannot restore - destination already exists", http.StatusConflict)
			return
		} else if !os.IsNotExist(statErr) {
			writeJSONError(w, fmt.Sprintf("Cannot inspect restore destination: %v", statErr), http.StatusInternalServerError)
			return
		}
		// Directory restore: use os.Rename (same device)
		if err := os.Rename(entry.ItemPath, restorePath); err != nil {
			writeJSONError(w, fmt.Sprintf("Cannot restore directory: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		// File restore: use O_EXCL to prevent overwriting an existing file
		src, readErr := os.Open(entry.ItemPath)
		if readErr != nil {
			writeJSONError(w, fmt.Sprintf("Cannot read quarantined file: %v", readErr), http.StatusInternalServerError)
			return
		}
		dst, createErr := os.OpenFile(restorePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, restoredMode)
		if createErr != nil {
			_ = src.Close()
			writeJSONError(w, fmt.Sprintf("Cannot restore - file already exists at original path: %v", createErr), http.StatusConflict)
			return
		}
		_, copyErr := io.Copy(dst, src)
		_ = src.Close()
		_ = dst.Close()
		if copyErr != nil {
			if err := os.Remove(restorePath); err != nil && !os.IsNotExist(err) {
				log.Printf("webui: failed to remove %s: %v", restorePath, err)
			}
			writeJSONError(w, fmt.Sprintf("Cannot write restored file: %v", copyErr), http.StatusInternalServerError)
			return
		}
		if err := os.Remove(entry.ItemPath); err != nil && !os.IsNotExist(err) {
			log.Printf("webui: failed to remove %s: %v", entry.ItemPath, err)
		}
	}

	// Restore ownership
	_ = syscall.Chown(restorePath, meta.Owner, meta.Group)
	// Restore mode explicitly (WriteFile may be affected by umask)
	_ = os.Chmod(restorePath, restoredMode)

	// Remove metadata sidecar
	if err := os.Remove(entry.MetaPath); err != nil && !os.IsNotExist(err) {
		log.Printf("webui: failed to remove %s: %v", entry.MetaPath, err)
	}

	s.auditLog(r, "restore", restorePath, "quarantine restore")
	writeJSON(w, map[string]string{
		"status":  "restored",
		"path":    restorePath,
		"warning": "File restored to original location. Re-scan recommended.",
	})
}

// apiQuarantinePreview returns the first 8KB of a quarantined file for inspection.
func (s *Server) apiQuarantinePreview(w http.ResponseWriter, r *http.Request) {
	entry, err := resolveQuarantineEntry(r.URL.Query().Get("id"))
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	info, err := os.Stat(entry.ItemPath)
	if err != nil {
		writeJSONError(w, "not found", http.StatusNotFound)
		return
	}
	if info.IsDir() {
		writeJSON(w, map[string]interface{}{
			"id": entry.ID, "is_dir": true,
			"preview": "[directory - content preview not available]",
		})
		return
	}
	f, err := os.Open(entry.ItemPath)
	if err != nil {
		writeJSONError(w, "cannot read file", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	buf := make([]byte, 8192)
	n, _ := f.Read(buf)
	writeJSON(w, map[string]interface{}{
		"id":         entry.ID,
		"preview":    string(buf[:n]),
		"truncated":  info.Size() > 8192,
		"total_size": info.Size(),
	})
}

// apiQuarantineBulkDelete permanently removes quarantined files and their metadata.
func (s *Server) apiQuarantineBulkDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := decodeJSONBodyLimited(w, r, 64*1024, &req); err != nil {
		writeJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > 100 {
		writeJSONError(w, "IDs must be 1-100 items", http.StatusBadRequest)
		return
	}

	count := 0
	for _, id := range req.IDs {
		entry, err := resolveQuarantineEntry(id)
		if err != nil {
			continue
		}
		if _, statErr := os.Lstat(entry.ItemPath); statErr == nil {
			if err := os.RemoveAll(entry.ItemPath); err == nil {
				count++
			}
		} else if !os.IsNotExist(statErr) {
			continue
		}
		if err := os.Remove(entry.MetaPath); err != nil && !os.IsNotExist(err) {
			log.Printf("webui: failed to remove quarantine meta %s: %v", entry.MetaPath, err)
		}
	}
	s.auditLog(r, "quarantine_bulk_delete", fmt.Sprintf("%d files", count), "")
	writeJSON(w, map[string]interface{}{"ok": true, "count": count})
}

// apiTestAlert sends a test finding through all configured alert channels.
func (s *Server) apiTestAlert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	testFinding := []alert.Finding{{
		Severity:  alert.Warning,
		Check:     "test_alert",
		Message:   "Test alert from CSM Web UI",
		Details:   fmt.Sprintf("Sent by admin at %s", time.Now().Format("2006-01-02 15:04:05")),
		Timestamp: time.Now(),
	}}
	err := alert.Dispatch(s.cfg, testFinding)
	if err != nil {
		writeJSON(w, map[string]interface{}{"status": "error", "error": err.Error()})
		return
	}
	s.auditLog(r, "test_alert", "notification", "sent test alert")
	writeJSON(w, map[string]interface{}{"status": "sent"})
}

// apiScanAccount runs an on-demand scan for a single cPanel account.
// POST /api/v1/scan-account  body: {"account": "username"}
func (s *Server) apiScanAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Account string `json:"account"`
	}
	if err := decodeJSONBodyLimited(w, r, 32*1024, &req); err != nil || req.Account == "" {
		writeJSONError(w, "Account name is required", http.StatusBadRequest)
		return
	}

	if err := validateAccountName(req.Account); err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Rate limit: only one scan at a time
	if !s.acquireScan() {
		writeJSONError(w, "A scan is already in progress. Please wait.", http.StatusTooManyRequests)
		return
	}
	defer s.releaseScan()

	// Extend the write deadline for this long-running request.
	// Account scans can take several minutes; the default WriteTimeout (300s)
	// causes ERR_HTTP2_PROTOCOL_ERROR in browsers when it fires mid-stream.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Minute))

	start := time.Now()
	findings := checks.RunAccountScan(s.cfg, s.store, req.Account)
	elapsed := time.Since(start).Round(time.Millisecond)

	result := map[string]interface{}{
		"account": req.Account,
		"count":   len(findings),
		"elapsed": elapsed.String(),
	}
	writeJSON(w, result)
}

// parseModeString converts a permission string like "-rw-r--r--" to os.FileMode.
func parseModeString(s string) os.FileMode {
	if len(s) < 10 {
		return 0644
	}
	var mode os.FileMode
	perms := s[len(s)-9:] // last 9 chars: "rwxr-xr-x"
	bits := []os.FileMode{
		0400, 0200, 0100, // owner r/w/x
		0040, 0020, 0010, // group r/w/x
		0004, 0002, 0001, // other r/w/x
	}
	for i, b := range bits {
		if i < len(perms) && perms[i] != '-' {
			mode |= b
		}
	}
	if mode == 0 {
		mode = 0644 // fallback
	}
	return mode
}

// flushCphulk removes brute-force login history for an IP from cPanel's cphulk.
func flushCphulk(ip string) {
	_, _ = exec.Command("whmapi1", "flush_cphulk_login_history_for_ips", "ip="+ip).Output()
}

// apiExport returns a JSON bundle of exportable state.
func (s *Server) apiExport(w http.ResponseWriter, _ *http.Request) {
	// Collect suppressions
	suppressions := s.store.LoadSuppressions()
	if suppressions == nil {
		suppressions = []state.SuppressionRule{}
	}

	// Collect whitelist
	var whitelist []checks.WhitelistIP
	if tdb := checks.GetThreatDB(); tdb != nil {
		whitelist = tdb.WhitelistedIPs()
	}
	if whitelist == nil {
		whitelist = []checks.WhitelistIP{}
	}

	bundle := map[string]interface{}{
		"exported_at":  time.Now().Format(time.RFC3339),
		"hostname":     s.cfg.Hostname,
		"suppressions": suppressions,
		"whitelist":    whitelist,
	}

	w.Header().Set("Content-Disposition", "attachment; filename=csm-state-export.json")
	writeJSON(w, bundle)
}

// apiImport merges an exported state bundle into the current state.
func (s *Server) apiImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var bundle struct {
		Suppressions []state.SuppressionRule `json:"suppressions"`
		Whitelist    []struct {
			IP string `json:"ip"`
		} `json:"whitelist"`
	}
	if err := decodeJSONBodyLimited(w, r, 512*1024, &bundle); err != nil {
		writeJSONError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	imported := 0

	// Merge suppressions (dedup by ID)
	if len(bundle.Suppressions) > 0 {
		existing := s.store.LoadSuppressions()
		existingIDs := make(map[string]bool)
		for _, rule := range existing {
			existingIDs[rule.ID] = true
		}
		for _, rule := range bundle.Suppressions {
			if !existingIDs[rule.ID] {
				existing = append(existing, rule)
				imported++
			}
		}
		if err := s.store.SaveSuppressions(existing); err != nil {
			writeJSONError(w, fmt.Sprintf("failed to save suppressions: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// Merge whitelist IPs
	if len(bundle.Whitelist) > 0 {
		if tdb := checks.GetThreatDB(); tdb != nil {
			existingWL := tdb.WhitelistedIPs()
			existingSet := make(map[string]bool)
			for _, w := range existingWL {
				existingSet[w.IP] = true
			}
			for _, entry := range bundle.Whitelist {
				if entry.IP != "" && !existingSet[entry.IP] {
					tdb.AddWhitelist(entry.IP)
					imported++
				}
			}
		}
	}

	s.auditLog(r, "import", "state", fmt.Sprintf("imported %d items", imported))
	writeJSON(w, map[string]interface{}{
		"status":   "imported",
		"imported": imported,
		"summary":  fmt.Sprintf("%d items imported", imported),
	})
}

// apiFindingDetail returns detail about a specific finding including related actions.
func (s *Server) apiFindingDetail(w http.ResponseWriter, r *http.Request) {
	check := r.URL.Query().Get("check")
	message := r.URL.Query().Get("message")
	if check == "" {
		writeJSONError(w, "check is required", http.StatusBadRequest)
		return
	}

	key := check + ":" + message

	// Get state entry for this finding (first/last seen)
	var firstSeen, lastSeen string
	if entry, ok := s.store.EntryForKey(key); ok {
		firstSeen = entry.FirstSeen.Format(time.RFC3339)
		lastSeen = entry.LastSeen.Format(time.RFC3339)
	}

	// Search audit log for related actions
	actions := s.searchAuditEntries(check, 20)

	// Search history for related findings (same check type, last 50)
	allHistory, _ := s.store.ReadHistory(2000, 0)
	type histEntry struct {
		Severity  int    `json:"severity"`
		Check     string `json:"check"`
		Message   string `json:"message"`
		Timestamp string `json:"timestamp"`
	}
	var related []histEntry
	for _, f := range allHistory {
		if len(related) >= 50 {
			break
		}
		if f.Check == check {
			related = append(related, histEntry{
				Severity:  int(f.Severity),
				Check:     f.Check,
				Message:   f.Message,
				Timestamp: f.Timestamp.Format(time.RFC3339),
			})
		}
	}

	writeJSON(w, map[string]interface{}{
		"check":      check,
		"message":    message,
		"first_seen": firstSeen,
		"last_seen":  lastSeen,
		"actions":    actions,
		"related":    related,
	})
}

// extractAccountFromFinding extracts a cPanel account name from a finding
// by checking the message, details, and file path for /home/{user}/ patterns
// or "Account: " / "user: " in the details field (used by login checks).
func extractAccountFromFinding(f alert.Finding) string {
	for _, s := range []string{f.Message, f.Details, f.FilePath} {
		if idx := strings.Index(s, "/home/"); idx >= 0 {
			rest := s[idx+6:]
			if end := strings.IndexByte(rest, '/'); end > 0 {
				return rest[:end]
			}
		}
	}
	for _, prefix := range []string{"Account: ", "user: "} {
		if idx := strings.Index(f.Details, prefix); idx >= 0 {
			rest := f.Details[idx+len(prefix):]
			end := strings.IndexAny(rest, " \n\t,")
			if end > 0 {
				return rest[:end]
			}
			if len(rest) > 0 {
				return rest
			}
		}
	}
	return ""
}

func writeJSONError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(data)
}

func queryInt(r *http.Request, key string, defaultVal int) int {
	val := r.URL.Query().Get(key)
	if val == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(val)
	if err != nil || n < 0 {
		return defaultVal
	}
	return n
}
