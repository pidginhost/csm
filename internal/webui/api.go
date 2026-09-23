package webui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

var reIPReputation = regexp.MustCompile(`Known malicious IP accessing server: (\S+) \((.+)\)`)

// apiStatus returns the daemon's full health snapshot as JSON. Backward
// compatible with prior callers: every field they consumed (hostname,
// uptime, started_at, rules_loaded, scan_running, last_scan_time) is
// still present, with new fields added alongside.
func (s *Server) apiStatus(w http.ResponseWriter, _ *http.Request) {
	provider := s.provider

	s.scanMu.Lock()
	scanning := s.scanRunning
	s.scanMu.Unlock()
	if s.scanInProgress != nil && s.scanInProgress() {
		scanning = true
	}

	if provider == nil {
		// No daemon-side provider installed (test harness). Fall back to
		// the legacy minimal payload so existing UI code keeps working.
		lastScan := ""
		if s.store != nil {
			lastScan = s.store.LatestScanTime().Format(time.RFC3339)
		}
		writeJSON(w, map[string]interface{}{
			"hostname":         s.cfg.Hostname,
			"uptime":           time.Since(s.startTime).String(),
			"started_at":       s.startTime.Format(time.RFC3339),
			"started_at_token": daemonStartToken(s.startTime),
			"rules_loaded":     s.signatureCount(),
			"scan_running":     scanning,
			"last_scan_time":   lastScan,
			"status":           "down",
		})
		return
	}

	snap := health.Build(provider, s.version, health.Capabilities())
	resp := map[string]interface{}{
		"hostname":         snap.Hostname,
		"version":          snap.Version,
		"uptime":           time.Duration(snap.UptimeSec * int64(time.Second)).String(),
		"uptime_sec":       snap.UptimeSec,
		"started_at":       snap.StartedAt.Format(time.RFC3339),
		"started_at_token": daemonStartToken(snap.StartedAt),
		"rules_loaded":     s.signatureCount(),
		"scan_running":     scanning,
		// last_scan_time is the legacy key kept for older clients
		// (cphulk dashboard, status_check.go). latest_scan mirrors the
		// health.Snapshot JSON tag and is the canonical name for new
		// clients. Drop last_scan_time once the legacy consumers move.
		"last_scan_time":         snap.LatestScan.Format(time.RFC3339),
		"latest_scan":            formatRFC3339OrEmpty(snap.LatestScan),
		"baseline_at":            formatRFC3339OrEmpty(snap.BaselineAt),
		"blocklist_size":         snap.BlocklistSize,
		"incidents_open":         snap.IncidentsOpen,
		"bpf_enforcement_active": snap.BPFEnforcementActive,
		"history_count":          snap.HistoryCount,
		"severities":             snap.Severities,
		"watchers":               snap.Watchers,
		"store_healthy":          snap.StoreHealthy,
		"store_size_mb":          snap.StoreSizeMB,
		"config_hash":            snap.ConfigHash,
		"binary_hash":            snap.BinaryHash,
		"capabilities":           snap.Capabilities,
		"dry_run_blocks":         snap.DryRunBlocks,
		"automation":             snap.Automation,
		"mode":                   snap.Mode,
		"status":                 snap.OverallStatus(),
	}

	// security_posture is the threat-aware badge signal, distinct from
	// "status" (which stays operational: is the daemon alive and attached).
	// A daemon can be operationally "ok" while sitting on open critical
	// incidents, so the dashboard pill must fold in incident severity rather
	// than report "Healthy" next to thousands of criticals.
	openBySev := map[string]int{}
	if s.incidentCorrelator != nil {
		openBySev = s.incidentCorrelator.OpenCountsBySeverity()
	}
	resp["incidents_open_by_severity"] = openBySev
	resp["security_posture"] = securityPosture(operationalProblems(s.signatureCount(), snap), openBySev["critical"], openBySev["high"])

	if !snap.Update.CheckedAt.IsZero() {
		resp["update"] = snap.Update
	}
	// Present only after the daemon has merged an active set; absence means
	// "not observed yet", not "clean".
	if snap.CorrelationAttribution != nil {
		resp["correlation_attribution"] = snap.CorrelationAttribution
	}
	if len(snap.Queues) != 0 {
		resp["queues"] = snap.Queues
	}
	if len(snap.WordPressVerification) != 0 {
		resp["wordpress_verification"] = snap.WordPressVerification
	}
	writeJSON(w, resp)
}

// operationalProblems counts daemon faults that should prevent a healthy
// posture even when there are no active high-severity incidents.
func operationalProblems(sigCount int, snap health.Snapshot) int {
	problems := 0
	if sigCount == 0 {
		problems++
	}
	if !snap.StoreHealthy {
		problems++
	}
	if !snap.AllWatchersAttached() {
		problems++
	}
	for _, q := range snap.Queues {
		if q.Status == "degraded" && !q.Advisory {
			problems++
			break
		}
	}
	return problems
}

// securityPosture collapses operational faults and active-incident severity
// into the dashboard badge tier:
//
//   - "critical" if any active critical incident exists, or the daemon has
//     multiple operational problems.
//   - "warning" if any active high incident exists, or exactly one operational
//     problem.
//   - "healthy" otherwise.
//
// Incident severity takes precedence over operational faults so a fully
// attached daemon still reads "critical" while critical incidents are active.
func securityPosture(opProblems, openCritical, openHigh int) string {
	if openCritical > 0 || opProblems >= 2 {
		return "critical"
	}
	if openHigh > 0 || opProblems == 1 {
		return "warning"
	}
	return "healthy"
}

func formatRFC3339OrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// apiCapabilities returns the static feature-flag list for this build.
func (s *Server) apiCapabilities(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]interface{}{
		"capabilities": health.Capabilities(),
		"version":      s.version,
	})
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
		if !operatorFacingCheck(f.Check) {
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
	writeAll(w, result)
}

// enrichedFinding is the JSON response type for the enriched findings endpoint.
type enrichedFinding struct {
	Key           string `json:"key"`
	Severity      string `json:"severity"`
	SevClass      string `json:"sev_class"`
	Check         string `json:"check"`
	Message       string `json:"message"`
	Details       string `json:"details,omitempty"`
	FilePath      string `json:"file_path,omitempty"`
	Account       string `json:"account,omitempty"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
	HasFix        bool   `json:"has_fix"`
	HasVerify     bool   `json:"has_verify"`
	FixDesc       string `json:"fix_desc,omitempty"`
	ContentSHA256 string `json:"content_sha256,omitempty"`
	// BlockIP is the attacker address an operator may block from this
	// finding; empty for checks that do not report one.
	BlockIP string `json:"block_ip,omitempty"`
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
		sort.Strings(g.sources)
		g.entry.Message = fmt.Sprintf("Known malicious IP accessing server: %s (%s)", ip, strings.Join(g.sources, ", "))
		result = append(result, g.entry)
	}
	return result
}

// apiFindingsEnriched returns findings with IP dedup, account extraction, and severity counts.
func (s *Server) apiFindingsEnriched(w http.ResponseWriter, r *http.Request) {
	latest := s.store.LatestFindings()
	suppressions := s.store.LoadSuppressions()

	items := make([]enrichedFinding, 0)
	for _, f := range latest {
		if !operatorFacingCheck(f.Check) {
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
			Key:           f.Key(),
			Severity:      severityLabel(f.Severity),
			SevClass:      severityClass(f.Severity),
			Check:         f.Check,
			Message:       f.Message,
			Details:       f.Details,
			FilePath:      f.FilePath,
			Account:       extractAccountFromFinding(f),
			FirstSeen:     firstSeen.Format(time.RFC3339),
			LastSeen:      lastSeen.Format(time.RFC3339),
			HasFix:        checks.HasFix(f.Check),
			HasVerify:     checks.CanVerify(f.Check),
			FixDesc:       checks.FixDescription(f.Check, f.Message, f.FilePath),
			ContentSHA256: f.ContentSHA256,
			BlockIP:       checks.ManualBlockIP(f),
		})
	}

	items = dedupIPReputation(items)
	version := enrichedFindingsVersion(items)
	if r.URL.Query().Get("fields") == "version" {
		writeJSON(w, map[string]interface{}{"version": version, "total": len(items)})
		return
	}

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

	extra := map[string]interface{}{
		"check_types":    checkTypes,
		"accounts":       accounts,
		"critical_count": critCount,
		"high_count":     highCount,
		"warning_count":  warnCount,
		"version":        version,
	}
	if limit := queryInt(r, "limit", 0); limit > 0 {
		sortEnrichedBySeverity(items)
		writeCapped(w, items, len(items), limit, extra)
		return
	}
	extra["total"] = len(items)
	writeItems(w, items, extra)
}

// sortEnrichedBySeverity orders findings most severe first, newest first
// within a severity, so a limited list keeps the ones that matter.
func sortEnrichedBySeverity(items []enrichedFinding) {
	rank := map[string]int{"CRITICAL": 3, "HIGH": 2}
	lastSeen := func(f enrichedFinding) time.Time {
		t, _ := time.Parse(time.RFC3339, f.LastSeen)
		return t
	}
	sort.SliceStable(items, func(i, j int) bool {
		if ri, rj := rank[items[i].Severity], rank[items[j].Severity]; ri != rj {
			return ri > rj
		}
		return lastSeen(items[i]).After(lastSeen(items[j]))
	})
}

// enrichedFindingsVersion changes when the listed findings or their
// severities do. A client that polls only to learn whether the list changed
// asks for ?fields=version and compares. ip_reputation rows are identified by
// their message, which carries the merged sources.
func enrichedFindingsVersion(items []enrichedFinding) string {
	ids := make([]string, 0, len(items))
	for _, f := range items {
		id := f.Key
		if f.Check == "ip_reputation" {
			id = f.Check + ":" + f.Message
		}
		ids = append(ids, id+"|"+f.Severity)
	}
	sort.Strings(ids)
	h := sha256.New()
	for _, id := range ids {
		h.Write([]byte(id))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// apiHistory returns paginated finding history.
// Supports optional filtering via "from", "to" (YYYY-MM-DD or RFC 3339), and "severity" (0/1/2) query params.
func (s *Server) apiHistory(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	if limit > 5000 {
		limit = 5000
	}
	offset := queryInt(r, "offset", 0)

	q, ok := parseHistoryQuery(w, r)
	if !ok {
		return
	}
	findings, total := s.readHistoryPage(q, limit, offset)
	writeItems(w, withAccountIP(findings), map[string]interface{}{
		"total":     total,
		"limit":     limit,
		"offset":    offset,
		"truncated": historyPageTruncated(total, offset, len(findings)),
	})
}

// historyQuery is the filter set /api/v1/history and its CSV export share.
type historyQuery struct {
	from, to, search string
	severity         int // -1 for any
	checks           map[string]bool
}

func (q historyQuery) filtered() bool {
	return q.from != "" || q.to != "" || q.severity >= 0 || q.search != "" || q.checks != nil
}

// parseHistoryQuery reads the history filters. An unreadable date is a 400,
// written here, and ok is false.
func parseHistoryQuery(w http.ResponseWriter, r *http.Request) (historyQuery, bool) {
	v := r.URL.Query()
	if _, _, ok := historyRangeQuery(w, v, time.Time{}, time.Time{}); !ok {
		return historyQuery{}, false
	}
	q := historyQuery{from: v.Get("from"), to: v.Get("to"), search: v.Get("search"), severity: -1}
	if v.Get("severity") != "" {
		q.severity = queryInt(r, "severity", -1)
	}
	if checksStr := v.Get("checks"); checksStr != "" {
		q.checks = make(map[string]bool)
		for _, c := range strings.Split(checksStr, ",") {
			if c = strings.TrimSpace(c); c != "" {
				q.checks[c] = true
			}
		}
	}
	return q, true
}

func (s *Server) readHistoryPage(q historyQuery, limit, offset int) ([]alert.Finding, int) {
	if !q.filtered() {
		return s.store.ReadHistory(limit, offset)
	}
	return s.store.ReadHistoryFilteredWithChecks(limit, offset, q.from, q.to, q.severity, q.search, q.checks)
}

// historyPageTruncated reports whether matches exist past the returned page.
// total counts every match, so a client can page on through offset.
func historyPageTruncated(total, offset, returned int) bool {
	return total > offset+returned
}

// historyFinding decorates a stored finding with the normalized account and
// remote IP so clients render structured fields instead of regex-scraping the
// human-readable message. The embedded Finding promotes its own JSON fields, so
// existing consumers see the same shape plus account/ip.
type historyFinding struct {
	alert.Finding
	Account string `json:"account,omitempty"`
	IP      string `json:"ip,omitempty"`
}

func withAccountIP(findings []alert.Finding) []historyFinding {
	out := make([]historyFinding, len(findings))
	for i, f := range findings {
		out[i] = historyFinding{Finding: f, Account: findingAccount(f), IP: findingIP(f)}
	}
	return out
}

// findingAccount returns the account/mailbox attribution for a finding,
// preferring structured fields over legacy text extraction so the value
// survives message wording changes.
func findingAccount(f alert.Finding) string {
	for _, account := range []string{f.Mailbox, f.TenantID, f.CPUser} {
		if account = strings.TrimSpace(account); account != "" {
			return account
		}
	}
	if acct := legacyEmailAccount(f); acct != "" {
		return acct
	}
	if acct := extractAccountFromFinding(f); acct != "" {
		return acct
	}
	return strings.TrimSpace(f.Domain)
}

func findingIP(f alert.Finding) string {
	if ip := strings.TrimSpace(f.SourceIP); ip != "" {
		return ip
	}
	if !isEmailHistoryCheck(f.Check) {
		return ""
	}
	for _, s := range []string{f.Message, f.Details} {
		if ip := firstIPToken(s); ip != "" {
			return ip
		}
	}
	return ""
}

func legacyEmailAccount(f alert.Finding) string {
	if !isEmailHistoryCheck(f.Check) {
		return ""
	}
	for _, source := range []string{f.Message, f.Details} {
		for _, prefix := range []string{"for ", "Account ", "account ", "Sender "} {
			if token := tokenAfter(source, prefix); strings.Contains(token, "@") {
				return token
			}
		}
		if token := tokenAfter(source, "set_id="); token != "" {
			return token
		}
		for _, prefix := range []string{"Domain ", "Domain: ", "domain ", "domain: "} {
			if token := tokenAfter(source, prefix); token != "" {
				return token
			}
		}
	}
	return ""
}

func isEmailHistoryCheck(check string) bool {
	return emailKindForCheck(check) != "" ||
		strings.HasPrefix(check, "email_") ||
		strings.HasPrefix(check, "mail_") ||
		strings.HasPrefix(check, "smtp_")
}

func tokenAfter(s, prefix string) string {
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(prefix):]
	if end := strings.IndexAny(rest, " \n\t,"); end >= 0 {
		rest = rest[:end]
	}
	return cleanHistoryToken(rest)
}

func cleanHistoryToken(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"'<>[]()`)
	s = strings.TrimRight(s, ".,;:")
	return s
}

func firstIPToken(s string) string {
	for _, raw := range strings.FieldsFunc(s, func(r rune) bool {
		if unicode.IsSpace(r) {
			return true
		}
		switch r {
		case ',', ';', '(', ')':
			return true
		default:
			return false
		}
	}) {
		if ip := normalizeHistoryIPToken(raw); ip != "" {
			return ip
		}
	}
	return ""
}

func normalizeHistoryIPToken(raw string) string {
	raw = strings.Trim(raw, `"'<>`)
	if ip := parseHistoryIP(raw); ip != "" {
		return ip
	}
	if eq := strings.LastIndexByte(raw, '='); eq >= 0 && eq < len(raw)-1 {
		if ip := normalizeHistoryIPToken(raw[eq+1:]); ip != "" {
			return ip
		}
	}

	candidate := strings.TrimRight(raw, ".,;:")
	if host, _, err := net.SplitHostPort(candidate); err == nil {
		if ip := parseHistoryIP(host); ip != "" {
			return ip
		}
	}
	if strings.HasPrefix(candidate, "[") {
		if end := strings.IndexByte(candidate, ']'); end > 1 {
			if ip := parseHistoryIP(candidate[1:end]); ip != "" {
				return ip
			}
		}
	}
	return parseHistoryIP(candidate)
}

func parseHistoryIP(raw string) string {
	raw = strings.TrimSpace(strings.Trim(raw, "[]"))
	if raw == "" {
		return ""
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		return addr.String()
	}
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		return prefix.String()
	}
	return ""
}

// var (not const) so tests can redirect to t.TempDir(). Production
// callers must not mutate at runtime.
var quarantineDir = "/opt/csm/quarantine"

// apiQuarantine lists quarantined files with metadata.
func (s *Server) apiQuarantine(w http.ResponseWriter, _ *http.Request) {

	type quarantineEntry struct {
		ID              string    `json:"id"`
		Kind            string    `json:"kind"`
		OriginalPath    string    `json:"original_path"`
		Size            int64     `json:"size"`
		QuarantineAt    string    `json:"quarantined_at"`
		Reason          string    `json:"reason"`
		LiveState       string    `json:"live_state"`
		OriginalModTime time.Time `json:"original_mtime,omitzero"`
		quarantinedAt   time.Time
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

		// Hide entries whose original has been restored byte-identical to
		// the archive: the archive is redundant and the UI should reflect
		// the live filesystem, not the quarantine history. Divergence
		// (missing, different size, different content) keeps the entry
		// visible -- the operator still has to reconcile it.
		archivePath := strings.TrimSuffix(metaFile, ".meta")
		liveState := quarantineLiveState(archivePath, meta.OriginalPath)
		if liveState == "restored_identical" {
			continue
		}
		kind := "quarantine"
		if strings.HasPrefix(quarantineEntryID(metaFile), preCleanQuarantineIDPrefix) {
			kind = "pre_clean"
		}

		var timestamp string
		if !meta.QuarantineAt.IsZero() {
			timestamp = meta.QuarantineAt.UTC().Format(time.RFC3339Nano)
		}
		entries = append(entries, quarantineEntry{
			ID:              quarantineEntryID(metaFile),
			Kind:            kind,
			OriginalPath:    meta.OriginalPath,
			Size:            meta.Size,
			QuarantineAt:    timestamp,
			Reason:          meta.Reason,
			LiveState:       liveState,
			OriginalModTime: meta.OriginalModTime,
			quarantinedAt:   meta.QuarantineAt,
		})
	}

	// Sort newest first
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].quarantinedAt.Equal(entries[j].quarantinedAt) {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].quarantinedAt.After(entries[j].quarantinedAt)
	})

	writeAll(w, entries)
}

// apiStats returns severity counts and per-check breakdown for the last 24
// hours. The summary is shared with the dashboard page and recomputed only
// when history changes.
func (s *Server) apiStats(w http.ResponseWriter, _ *http.Request) {
	sum := s.statsSummary24h()
	lastCriticalAgo, lastCriticalISO := "None", ""
	if !sum.lastCritical.IsZero() {
		lastCriticalAgo = timeAgo(sum.lastCritical)
		lastCriticalISO = sum.lastCritical.Format(time.RFC3339)
	}
	result := map[string]interface{}{
		"last_24h": map[string]interface{}{
			"critical": sum.critical,
			"high":     sum.high,
			"warning":  sum.warning,
			"total":    sum.critical + sum.high + sum.warning,
		},
		"by_check":          sum.byCheck,
		"last_critical_ago": lastCriticalAgo,
		"last_critical_iso": lastCriticalISO,
		"accounts_at_risk":  sum.atRisk,
		"auto_response": map[string]int{
			"blocked":     sum.autoBlocked,
			"quarantined": sum.autoQuarantined,
			"killed":      sum.autoKilled,
		},
		"top_accounts": sum.topAccounts,
		"brute_force":  sum.bruteForce,
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

// apiStatsTrend returns daily finding counts by severity for the trend
// chart. Accepts optional ?days=N (default 30, clamped to the store's
// retention window).
func (s *Server) apiStatsTrend(w http.ResponseWriter, r *http.Request) {
	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			days = n
		}
	}
	writeAll(w, s.store.AggregateByDayN(days))
}

// apiStatsTimeline returns 24 hourly buckets for the findings timeline chart.
// Uses efficient bbolt cursor seeking instead of loading all findings into memory.
func (s *Server) apiStatsTimeline(w http.ResponseWriter, _ *http.Request) {
	buckets, _ := s.timelineMemo.get(s.store.HistoryMark(), func() any {
		return s.store.AggregateByHour()
	}).([]store.HourBucket)
	writeAll(w, buckets)
}

// apiHealth returns daemon health status.
func (s *Server) apiHealth(w http.ResponseWriter, _ *http.Request) {
	health := map[string]interface{}{
		"daemon_mode":    true,
		"uptime":         time.Since(s.startTime).String(),
		"uptime_seconds": int(time.Since(s.startTime).Seconds()),
		"rules_loaded":   s.signatureCount(),
		"fanotify":       s.fanotifyRunning(),
		"log_watchers":   s.logWatchersRunning(),
	}
	writeJSON(w, health)
}

// historyCSVMax bounds one CSV export; the history filters narrow it to reach
// older entries.
const historyCSVMax = 5000

// apiHistoryCSV exports the newest history entries matching the History
// filters as a CSV download.
func (s *Server) apiHistoryCSV(w http.ResponseWriter, r *http.Request) {
	q, ok := parseHistoryQuery(w, r)
	if !ok {
		return
	}
	findings, _ := s.readHistoryPage(q, historyCSVMax, 0)

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

// csvEscape quotes a field for CSV and neutralises spreadsheet formula
// triggers. Finding text is attacker-chosen (a filename, a User-Agent, a
// mailbox): a field starting with "=", "+", "-", "@", a tab or a carriage
// return became a live formula when the export was opened in a spreadsheet.
// Such fields are prefixed with a single quote, the convention spreadsheets
// use to force text, and quoted so the prefix survives.
func csvEscape(s string) string {
	if s != "" && strings.ContainsAny(s[:1], "=+-@\t\r") {
		s = "'" + s
	}
	if strings.ContainsAny(s, ",\"\n\r'") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

// safeLogString renders a caller-controlled string into a log entry without
// allowing embedded CR/LF/control bytes to forge a separate log line.
func safeLogString(s string) string { return strconv.Quote(s) }

func daemonStartToken(start time.Time) string {
	return start.UTC().Format(time.RFC3339Nano)
}

func (s *Server) daemonStartToken() string {
	if s.provider != nil {
		return daemonStartToken(s.provider.StartedAt())
	}
	return daemonStartToken(s.startTime)
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
		Key      string `json:"key"`
	}
	if err := decodeJSONBodyLimited(w, r, 64*1024, &req); err != nil || req.Check == "" || req.Message == "" {
		writeJSONError(w, "check and message are required", http.StatusBadRequest)
		return
	}

	if !checks.HasFix(req.Check) {
		writeJSONError(w, "no automated fix available for this check type", http.StatusBadRequest)
		return
	}

	message, details, filePath, dismissKey, err := s.fixTargetFromStore(req.Key, req.Check, req.Message, req.Details, req.FilePath)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	result := s.applyFix(r.Context(), req.Check, message, details, filePath)

	// If fix succeeded, dismiss from both alert state and latest findings.
	if result.Success {
		s.store.DismissFinding(dismissKey)
		s.store.DismissLatestFinding(dismissKey)
		s.auditLog(r, "fix", req.Check, result.Action)
	}

	writeRemediation(w, result)
}

// apiVerifyFinding re-checks whether a finding's condition still holds against
// the live filesystem. It dismisses a resolved finding, lowers an inert
// replacement to Warning, or restores an earlier automatic demotion. This lets
// an operator confirm a manual fix immediately instead of waiting for the next
// scan, and is the "Re-check" action behind a finding row.
// POST /api/v1/verify-finding  body: {"check":"...","message":"...","details":"...","file_path":"...","key":"..."}
func (s *Server) apiVerifyFinding(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req verifyFindingRequest
	if err := decodeJSONBodyLimited(w, r, 64*1024, &req); err != nil || req.Check == "" || req.Message == "" {
		writeJSONError(w, "check and message are required", http.StatusBadRequest)
		return
	}

	in, key, stored, found := s.verifyFindingInput(req)
	in.Context = r.Context()
	response := verifyFindingResponse{OK: true, VerifyResult: s.verifyFinding(in)}
	switch {
	case response.Checked && response.Resolved:
		if key == "" {
			key = req.Check + ":" + req.Message
		}
		s.store.DismissFinding(key)
		s.store.DismissLatestFinding(key)
		s.auditLog(r, "verify-resolved", req.Check, response.Detail)
	// A severity change rewrites the stored finding, so it needs the exact
	// snapshot the verifier read; a request that could not be matched to one
	// leaves the finding alone rather than guessing which it meant.
	case found && checks.ShouldRestoreSeverity(stored, response.VerifyResult):
		if s.store.RestoreLatestFindingSeverity(stored) {
			response.SeverityChange = "restored"
			s.auditLog(r, "verify-restored", req.Check, response.Detail)
		}
	case found && checks.ShouldDemoteSeverity(stored, response.VerifyResult):
		if s.store.DemoteLatestFinding(stored, alert.Warning) {
			response.SeverityChange = "demoted"
			s.auditLog(r, "verify-demoted", req.Check, response.Detail)
		}
	}

	writeJSON(w, response)
}

// verifyFindingResponse distinguishes the verifier's recommendation from a
// state change the store actually accepted. Demote remains a verdict: it can be
// true for an already-demoted finding or after a concurrent scan replaced the
// snapshot, neither of which means this request changed the stored severity.
type verifyFindingResponse struct {
	OK bool `json:"ok"`
	checks.VerifyResult
	SeverityChange string `json:"severity_change,omitempty"`
}

type verifyFindingRequest struct {
	Check         string `json:"check"`
	Message       string `json:"message"`
	Details       string `json:"details"`
	FilePath      string `json:"file_path"`
	ContentSHA256 string `json:"content_sha256"`
	Key           string `json:"key"`
}

// verifyFindingInput builds the verifier input, and returns the stored finding
// it was built from so a caller applying a severity change can pass the exact
// snapshot the verifier saw.
func (s *Server) verifyFindingInput(req verifyFindingRequest) (checks.VerifyInput, string, alert.Finding, bool) {
	in := checks.VerifyInput{
		Check: req.Check, Message: req.Message, Details: req.Details,
		Path: req.FilePath,
	}
	f, ok := s.latestFindingForVerify(req.Key, req.Check, req.Message)
	if !ok {
		return in, req.Key, alert.Finding{}, false
	}
	in.Message = f.Message
	in.Details = f.Details
	in.Path = f.FilePath
	in.ContentSHA256 = f.ContentSHA256
	in.DetectLogic = f.DetectLogic
	return in, f.Key(), f, true
}

func (s *Server) latestFindingForVerify(key, check, message string) (alert.Finding, bool) {
	var matched alert.Finding
	found := false
	for _, f := range s.store.LatestFindings() {
		if f.Check != check || f.Message != message {
			continue
		}
		if key != "" {
			if f.Key() == key {
				return f, true
			}
			continue
		}
		if found {
			return alert.Finding{}, false
		}
		matched = f
		found = true
	}
	return matched, found
}

const bulkFixBodyMax = 64 * 1024

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
		Key      string `json:"key"`
	}
	if err := decodeJSONBodyLimited(w, r, bulkFixBodyMax, &reqs); err != nil {
		writeJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	results := make([]bulkFixItem, 0, len(reqs))
	for _, req := range reqs {
		if !checks.HasFix(req.Check) {
			results = append(results, bulkFixItem{Check: req.Check, Error: fmt.Sprintf("no fix for %s", req.Check)})
			continue
		}
		message, details, filePath, dismissKey, err := s.fixTargetFromStore(req.Key, req.Check, req.Message, req.Details, req.FilePath)
		if err != nil {
			results = append(results, bulkFixItem{Check: req.Check, Error: err.Error()})
			continue
		}
		result := s.applyFix(r.Context(), req.Check, message, details, filePath)
		if result.Success {
			s.store.DismissFinding(dismissKey)
			s.store.DismissLatestFinding(dismissKey)
			s.auditLog(r, "fix", req.Check, result.Action)
		}
		results = append(results, bulkFixItem{
			Check: req.Check, OK: result.Success, Action: result.Action,
			Description: result.Description, Error: result.Error, Reverted: result.Reverted,
		})
	}

	succeeded := 0
	for _, item := range results {
		if item.OK {
			succeeded++
		}
	}
	fields := map[string]interface{}{
		"results":   results,
		"total":     len(results),
		"succeeded": succeeded,
		"failed":    len(results) - succeeded,
	}
	if succeeded == 0 && len(results) > 0 {
		fields["error"] = "No fix applied"
		writeJSONStatus(w, http.StatusUnprocessableEntity, fields)
		return
	}
	writeOK(w, fields)
}

// bulkFixItem is one fix of a bulk request: which check, whether it applied,
// and what it did or why it did not.
type bulkFixItem struct {
	Check       string `json:"check"`
	OK          bool   `json:"ok"`
	Action      string `json:"action,omitempty"`
	Description string `json:"description,omitempty"`
	Error       string `json:"error,omitempty"`
	Reverted    bool   `json:"reverted,omitempty"`
}

// bulkItemFailure names one item of a batch that did not apply and why.
type bulkItemFailure struct {
	Item  string `json:"item"`
	Error string `json:"error"`
}

// apiAccounts returns the account names for the scan dropdown: the accounts a
// server-wide scan covers.
//
//nolint:unused // registered via mux.Handle in server.go
func (s *Server) apiAccounts(w http.ResponseWriter, _ *http.Request) {
	accounts, err := s.scanAccounts(s.liveCfg())
	if err != nil {
		writeJSONError(w, "Could not list accounts", http.StatusInternalServerError)
		return
	}
	writeAll(w, accounts)
}

// --- Action endpoints ---

// apiBlockIP blocks an IP via the firewall engine.
// POST /api/v1/block-ip  body: {"ip": "1.2.3.4", "reason": "..."}
func (s *Server) apiBlockIP(w http.ResponseWriter, r *http.Request) {
	s.threatActionMu.Lock()
	defer s.threatActionMu.Unlock()

	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP       string `json:"ip"`
		Reason   string `json:"reason"`
		Duration string `json:"duration"`
		// IncidentID, when set, notes the block on that incident so the
		// timeline shows an operator acted. Optional: the firewall action is
		// the point, the note is bookkeeping.
		IncidentID json.RawMessage `json:"incident_id"`
	}
	if err := decodeJSONBodyLimited(w, r, 64*1024, &req); err != nil {
		writeJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.IP == "" {
		writeJSONError(w, "IP is required", http.StatusBadRequest)
		return
	}
	parsedIP, err := parseAndValidateIP(req.IP)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Audit, incident and threat records key on the canonical spelling.
	req.IP = parsedIP.String()
	if req.Reason == "" {
		req.Reason = "Blocked via CSM Web UI"
	}

	dur, err := parseDuration(req.Duration)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if s.blocker == nil {
		writeJSONError(w, "Firewall engine not available", http.StatusServiceUnavailable)
		return
	}
	// Operator-initiated: bypass auto_response.dry_run gate.
	if err := blockIPForOperator(s.blocker, req.IP, req.Reason, dur); err != nil {
		writeJSONError(w, fmt.Sprintf("Block failed: %v", err), http.StatusInternalServerError)
		return
	}

	s.auditLog(r, "block_ip", req.IP, req.Reason)
	// A failure to annotate must not turn a successful block into an error:
	// the address is blocked either way, and a stale incident id is the
	// operator's tab being out of date, not a fault worth refusing.
	var incidentID string
	if json.Unmarshal(req.IncidentID, &incidentID) == nil && incidentID != "" && s.incidentCorrelator != nil {
		if err := s.incidentCorrelator.RecordOperatorBlock(incidentID, req.IP, dur); err != nil {
			log.Printf("webui: could not note an operator block on incident %s: %v",
				safeLogString(incidentID), err)
		}
	}
	resp := map[string]interface{}{"ip": req.IP}
	// The input chain accepts Cloudflare edges on 80/443 before the blocked
	// drop, so a block of a covered IP does not stop its web traffic.
	if cc, ok := s.blocker.(cloudflareChecker); ok && cc.CloudflareCovers(req.IP) {
		resp["warning"] = firewall.CloudflareCoverageWarning
	}
	writeOK(w, resp)
}

// apiUnblockIP removes an IP from the firewall + cphulk.
// POST /api/v1/unblock-ip  body: {"ip": "1.2.3.4"}
func (s *Server) apiUnblockIP(w http.ResponseWriter, r *http.Request) {
	s.threatActionMu.Lock()
	defer s.threatActionMu.Unlock()

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

	parsedIP, err := parseAndValidateIP(req.IP)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	req.IP = parsedIP.String()
	if s.blocker == nil {
		writeJSONError(w, "Firewall engine not available", http.StatusServiceUnavailable)
		return
	}
	if err := s.blocker.UnblockIP(req.IP); err != nil {
		writeJSONError(w, fmt.Sprintf("Unblock failed: %v", err), http.StatusInternalServerError)
		return
	}
	dropAutoBlockThreatRow(req.IP)

	// Also flush from cphulk (cPanel brute force detector); best effort,
	// the unblock is what was asked.
	_ = flushCphulk(req.IP)

	s.auditLog(r, "unblock_ip", req.IP, "manual unblock via UI")
	writeOK(w, map[string]interface{}{"ip": req.IP})
}

// apiUnblockBulk unblocks multiple IPs at once.
func (s *Server) apiUnblockBulk(w http.ResponseWriter, r *http.Request) {
	s.threatActionMu.Lock()
	defer s.threatActionMu.Unlock()

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
	// 500 fits the largest Blocks-table page size (250 plus All) so one UI
	// selection round-trips as a single request and a single undo token.
	if len(req.IPs) > 500 {
		writeJSONError(w, "IPs must be 1-500 items", http.StatusBadRequest)
		return
	}
	if s.blocker == nil {
		writeJSONError(w, "Firewall engine not available", http.StatusServiceUnavailable)
		return
	}

	priorBlocks := make(map[string]firewall.BlockedEntry)
	seen := make(map[string]bool, len(req.IPs))

	succeeded := 0
	unblocked := make([]string, 0, len(req.IPs))
	failed := []bulkItemFailure{}
	removedThreats := make([]undoThreatRow, 0, len(req.IPs))
	for _, ip := range req.IPs {
		parsed, err := parseAndValidateIP(ip)
		if err != nil {
			failed = append(failed, bulkItemFailure{Item: ip, Error: err.Error()})
			continue
		}
		ip = parsed.String()
		if seen[ip] {
			continue
		}
		seen[ip] = true

		before, err := s.unblockIPForUndo(ip)
		if err != nil {
			failed = append(failed, bulkItemFailure{Item: ip, Error: err.Error()})
			continue
		}
		if before != nil {
			priorBlocks[ip] = *before
		}
		if row, ok := captureUndoThreatRow(ip, true); ok {
			removedThreats = append(removedThreats, row)
		}
		dropAutoBlockThreatRow(ip)
		s.auditLog(r, "unblock_ip", ip, "bulk unblock via UI")
		unblocked = append(unblocked, ip)
		succeeded++
	}
	_ = flushCphulkIPs(unblocked) // best effort: the unblocks are what was asked

	var undoToken string
	if succeeded > 0 {
		undoToken = s.recordUndoEntry(r, "firewall_bulk_unblock", undoInverseFirewallUnblock,
			fmt.Sprintf("Unblocked %d IPs", succeeded),
			undoPayloadIPs{
				IPs:            unblocked,
				RestoreThreats: removedThreats,
				BlockSnapshot:  true,
				RestoreBlocks:  priorBlocks,
			})
	}

	fields := map[string]interface{}{
		"total":     len(req.IPs),
		"succeeded": succeeded,
		"failed":    failed,
	}
	if succeeded == 0 {
		fields["error"] = "No address was unblocked"
		writeJSONStatus(w, http.StatusUnprocessableEntity, fields)
		return
	}
	if undoToken != "" {
		fields["undo_token"] = undoToken
	}
	writeOK(w, fields)
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
func (s *Server) apiBlockedIPs(w http.ResponseWriter, _ *http.Request) {
	result := []blockedView{}

	fwFile := filepath.Join(s.cfg.StatePath, "firewall", "state.json")
	_, fwStatErr := os.Stat(fwFile) // #nosec G304 -- filepath.Join under operator-configured StatePath.
	fwState, fwErr := firewall.LoadState(s.cfg.StatePath)
	if fwErr != nil && fwStatErr == nil {
		// The engine state exists but cannot be read: an empty list would
		// tell the operator nothing is blocked.
		writeJSONError(w, "Firewall state unavailable", http.StatusInternalServerError)
		return
	}
	if fwErr == nil && fwState != nil {
		for _, entry := range fwState.Blocked {
			b := blockedEntry{
				IP:        entry.IP,
				Reason:    entry.Reason,
				Source:    entry.Source,
				BlockedAt: entry.BlockedAt,
				ExpiresAt: entry.ExpiresAt,
			}
			if view, ok := formatBlockedView(b); ok {
				result = append(result, view)
			}
		}
		// A present engine state file wins even when empty. blocked_ips.json
		// is only a legacy fallback when the engine file does not exist.
		if fwStatErr == nil || len(fwState.Blocked) > 0 {
			writeAll(w, result)
			return
		}
	}

	// Fall back to blocked_ips.json (legacy)
	stateFile := filepath.Join(s.cfg.StatePath, "blocked_ips.json")
	// #nosec G304 -- filepath.Join under operator-configured StatePath.
	data, err := os.ReadFile(stateFile)
	if os.IsNotExist(err) {
		writeAll(w, result)
		return
	}
	if err != nil {
		writeJSONError(w, "Firewall state unavailable", http.StatusInternalServerError)
		return
	}

	var blockState struct {
		IPs []blockedEntry `json:"ips"`
	}
	if err := json.Unmarshal(data, &blockState); err != nil {
		writeJSONError(w, "Firewall state unavailable", http.StatusInternalServerError)
		return
	}

	for _, b := range blockState.IPs {
		if view, ok := formatBlockedView(b); ok {
			result = append(result, view)
		}
	}
	writeAll(w, result)
}

// apiDismissFinding marks a finding as baseline (acknowledged/dismissed).
// POST /api/v1/dismiss  body: {"key": "check:message"}
// dismissBulkMax bounds one dismiss request. The whole request is one undo
// entry, so a larger selection must be narrowed rather than split.
const dismissBulkMax = 500

func (s *Server) apiDismissFinding(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Key  string   `json:"key"`
		Keys []string `json:"keys"`
	}
	if err := decodeJSONBodyLimited(w, r, 1<<20, &req); err != nil {
		writeJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	keys := req.Keys
	switch {
	case req.Key != "" && len(req.Keys) > 0:
		writeJSONError(w, "Send key or keys, not both", http.StatusBadRequest)
		return
	case req.Key != "":
		keys = []string{req.Key}
	case len(keys) == 0:
		writeJSONError(w, "Key is required", http.StatusBadRequest)
		return
	case len(keys) > dismissBulkMax:
		writeJSONError(w, fmt.Sprintf("At most %d findings per request", dismissBulkMax), http.StatusBadRequest)
		return
	}
	uniqueKeys := make([]string, 0, len(keys))
	seenKeys := make(map[string]bool, len(keys))
	for _, key := range keys {
		if key == "" {
			writeJSONError(w, "Key is required", http.StatusBadRequest)
			return
		}
		if !seenKeys[key] {
			seenKeys[key] = true
			uniqueKeys = append(uniqueKeys, key)
		}
	}
	keys = uniqueKeys

	undos := make([]state.DismissUndo, 0, len(keys))
	for _, key := range keys {
		undos = append(undos, s.store.DismissFindingWithUndo(key))
		s.auditLog(r, "dismiss", key, "")
	}
	resp := map[string]interface{}{"count": len(keys)}
	summary := fmt.Sprintf("Dismissed %d findings", len(keys))
	if len(keys) == 1 {
		resp["key"] = keys[0]
		check, _ := state.ParseKey(keys[0])
		summary = "Dismissed " + check + " finding"
	}
	if token := s.recordUndoEntry(r, "dismiss", undoInverseFindingUndismiss, summary,
		undoPayloadIPs{Dismissals: undos}); token != "" {
		resp["undo_token"] = token
	}
	writeOK(w, resp)
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

// quarantineBulkDeleteMax bounds the files one bulk-delete request removes.
// The UI sends larger selections as several requests of this size.
const quarantineBulkDeleteMax = 100

// apiQuarantineBulkDelete permanently removes quarantined files and their metadata.
// removeQuarantineItem deletes one quarantined file or directory. Tests
// replace it to exercise a deletion the filesystem refuses.
var removeQuarantineItem = os.RemoveAll

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
	if len(req.IDs) == 0 || len(req.IDs) > quarantineBulkDeleteMax {
		writeJSONError(w, fmt.Sprintf("IDs must be 1-%d items", quarantineBulkDeleteMax), http.StatusBadRequest)
		return
	}

	count := 0
	deleted := []string{}
	failed := []string{}
	for _, id := range req.IDs {
		entry, err := resolveQuarantineEntry(id)
		if err != nil || !quarantineEntryDeletable(entry) {
			failed = append(failed, id)
			continue
		}
		if _, statErr := os.Lstat(entry.ItemPath); statErr == nil {
			if err := removeQuarantineItem(entry.ItemPath); err != nil {
				// Keep the sidecar: the list is built from sidecars, so the
				// archive stays visible and the delete can be retried.
				log.Printf("webui: failed to delete quarantined %s: %v", safeLogString(entry.ItemPath), err)
				failed = append(failed, id)
				continue
			}
			count++
		} else if !os.IsNotExist(statErr) {
			failed = append(failed, id)
			continue
		}
		if err := os.Remove(entry.MetaPath); err != nil && !os.IsNotExist(err) {
			log.Printf("webui: failed to remove quarantine meta %s: %v", safeLogString(entry.MetaPath), err)
		}
		deleted = append(deleted, id)
	}
	details := "deleted: " + strings.Join(deleted, ", ")
	if len(failed) > 0 {
		details += "; failed: " + strings.Join(failed, ", ")
	}
	s.auditLog(r, "quarantine_bulk_delete", fmt.Sprintf("%d files", count), details)
	if len(deleted) == 0 {
		writeJSONStatus(w, http.StatusUnprocessableEntity, map[string]interface{}{
			"error": "No file was deleted", "count": 0, "failed": failed,
		})
		return
	}
	writeOK(w, map[string]interface{}{"count": count, "failed": failed})
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
	err := alert.Dispatch(s.liveCfg(), testFinding)
	if err != nil {
		// The request was fine; the alert channel behind the daemon failed.
		writeJSONError(w, "Alert delivery failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	s.auditLog(r, "test_alert", "notification", "sent test alert")
	writeOK(w, nil)
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
	// Account scans can take several minutes; the default WriteTimeout
	// causes ERR_HTTP2_PROTOCOL_ERROR in browsers when it fires mid-stream.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(longRequestTimeout))

	start := time.Now()
	findings := checks.RunAccountScan(s.liveCfg(), s.store, req.Account)
	elapsed := time.Since(start).Round(time.Millisecond)
	s.auditLog(r, "scan_account", req.Account, fmt.Sprintf("%d findings in %s", len(findings), elapsed))

	writeOK(w, map[string]interface{}{
		"account": req.Account,
		"count":   len(findings),
		"elapsed": elapsed.String(),
	})
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
	for _, flag := range s[:len(s)-9] {
		switch flag {
		case 'u':
			mode |= os.ModeSetuid
		case 'g':
			mode |= os.ModeSetgid
		case 't':
			mode |= os.ModeSticky
		}
	}
	return mode
}

// flushCphulk removes brute-force login history for an IP from cPanel's cphulk.
// Callers should pre-validate `ip` with parseAndValidateIP. This function
// re-validates as defense-in-depth so a future caller that forgets cannot
// expose a shell-execution surface even if exec.Command itself does not
// invoke a shell.
func flushCphulk(ip string) error {
	return flushCphulkIPs([]string{ip})
}

// flushCphulkIPs uses the WHM API's indexed array arguments so a bulk
// firewall action starts one whmapi1 process instead of one per address.
// It returns whmapi1's failure, including whmapi1 not being installed, so
// a caller reports the flush only when it ran.
func flushCphulkIPs(ips []string) error {
	args := []string{"flush_cphulk_login_history_for_ips"}
	valid := 0
	for _, ip := range ips {
		parsed, err := parseAndValidateIP(ip)
		if err != nil {
			continue
		}
		param := "ip"
		if valid > 0 {
			param = fmt.Sprintf("ip-%d", valid)
		}
		args = append(args, param+"="+parsed.String())
		valid++
	}
	if valid == 0 {
		return nil
	}
	// #nosec G204 -- whmapi1 is fixed and every argument value is parsed as
	// an IP above. exec.Command passes arguments directly without a shell.
	if _, err := exec.Command("whmapi1", args...).Output(); err != nil {
		return fmt.Errorf("whmapi1: %w", err)
	}
	return nil
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

	// The bundle is what /api/v1/export writes; the decoder refuses unknown
	// fields, so every field the export carries is named here.
	var bundle struct {
		ExportedAt   string                  `json:"exported_at"`
		Hostname     string                  `json:"hostname"`
		Suppressions []state.SuppressionRule `json:"suppressions"`
		Whitelist    []checks.WhitelistIP    `json:"whitelist"`
	}
	if err := decodeJSONBodyLimited(w, r, 512*1024, &bundle); err != nil {
		writeJSONError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	imported, skipped := 0, 0
	warning := ""

	// Merge suppressions (dedup by ID)
	if len(bundle.Suppressions) > 0 {
		err := s.store.UpdateSuppressions(func(existing []state.SuppressionRule) ([]state.SuppressionRule, error) {
			existingIDs := make(map[string]bool)
			for _, rule := range existing {
				existingIDs[rule.ID] = true
			}
			for _, rule := range bundle.Suppressions {
				// Same contract as a rule added through the UI: a check name
				// and a valid glob are required (otherwise the rule
				// suppresses nothing and only clutters the list), and every
				// rule needs an ID or it can never be deleted from the UI.
				if !suppressionCheckName.MatchString(rule.Check) {
					skipped++
					continue
				}
				if rule.PathPattern != "" {
					if _, err := filepath.Match(rule.PathPattern, ""); err != nil {
						skipped++
						continue
					}
				}
				if rule.ID == "" {
					rule.ID = newSuppressionID()
				}
				if rule.CreatedAt.IsZero() {
					rule.CreatedAt = time.Now()
				}
				if !existingIDs[rule.ID] {
					existingIDs[rule.ID] = true
					existing = append(existing, rule)
					imported++
				}
			}
			return existing, nil
		})
		if err != nil {
			writeJSONError(w, fmt.Sprintf("failed to save suppressions: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// Merge whitelist IPs
	if len(bundle.Whitelist) > 0 {
		tdb := checks.GetThreatDB()
		if tdb == nil {
			skipped += len(bundle.Whitelist)
			warning = "The threat database is not available; whitelist entries were not imported."
		} else {
			existingSet := make(map[string]bool)
			for _, w := range tdb.WhitelistedIPs() {
				existingSet[w.IP] = true
			}
			now := time.Now()
			for _, entry := range bundle.Whitelist {
				// Validate imported IPs like every interactive route does: an
				// unvalidated bundle could otherwise poison the threat DB /
				// firewall allow-list with malformed or attacker-chosen entries
				// (whitelisting bypasses blocking). Use the canonical form.
				ip, err := parseAndValidateIP(entry.IP)
				// Entries from the configuration file are managed there, and an
				// expired temporary entry has nothing left to import.
				if err != nil || entry.Configured || (entry.ExpiresAt != nil && !entry.ExpiresAt.After(now)) {
					skipped++
					continue
				}
				canonical := ip.String()
				if existingSet[canonical] {
					continue
				}
				// A temporary entry stays temporary, with its remaining time.
				if entry.ExpiresAt != nil {
					tdb.TempWhitelist(canonical, entry.ExpiresAt.Sub(now))
				} else {
					tdb.AddWhitelist(canonical)
				}
				existingSet[canonical] = true
				imported++
			}
		}
	}

	s.auditLog(r, "import", "state", fmt.Sprintf("imported %d items, skipped %d", imported, skipped))
	resp := map[string]interface{}{"imported": imported, "skipped": skipped}
	if warning != "" {
		resp["warning"] = warning
	}
	writeOK(w, resp)
}

// apiFindingDetail returns detail about a specific finding including related actions.
func (s *Server) apiFindingDetail(w http.ResponseWriter, r *http.Request) {
	check := r.URL.Query().Get("check")
	message := r.URL.Query().Get("message")
	if check == "" {
		writeJSONError(w, "check is required", http.StatusBadRequest)
		return
	}

	// Alert state is keyed by Finding.Key(), which folds in a hash of the
	// details (and the source IP for IP-keyed checks); "check:message" is
	// only the key of a finding with neither. Resolve the stored finding
	// first so findings with details get their first/last-seen times.
	key := check + ":" + message
	if f, ok := s.latestFindingForVerify(r.URL.Query().Get("key"), check, message); ok {
		key = f.Key()
	}

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

// extractAccountFromFinding returns the cPanel account a finding belongs to:
// the owner the check recorded (TenantID, or CPUser for mail relay), else a
// /home/{user}/ path in the message, details or file path, else "Account: "
// / "user: " in the details field (used by login checks).
func extractAccountFromFinding(f alert.Finding) string {
	for _, owner := range []string{f.TenantID, f.CPUser} {
		if owner = strings.TrimSpace(owner); owner != "" {
			return owner
		}
	}
	if f.FilePath == "" && (f.Check == "wp_core_unverified" || f.Check == "wp_plugin_inventory_unverified") {
		// Collapsed coverage warnings carry an account only when every
		// installation shares it. Their bounded path sample cannot establish
		// ownership, even when it happens to show just one account.
		return ""
	}
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
	writeJSONStatus(w, code, map[string]string{"error": message})
}

// writeJSON sends compact JSON: indentation added about a third to large
// lists such as findings and history, and nothing reads it but code.
func writeJSON(w http.ResponseWriter, data interface{}) {
	writeJSONStatus(w, http.StatusOK, data)
}

// writeJSONStatus sends data as JSON with the given status code.
func writeJSONStatus(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}

// writeItems answers a collection: {"items": [...]} plus extra, which holds
// "total" when the handler counted the matches, the paging keys and side
// data. A nil list goes out as [] so an empty collection is never null.
func writeItems[T any](w http.ResponseWriter, items []T, extra map[string]interface{}) {
	if items == nil {
		items = []T{}
	}
	body := make(map[string]interface{}, len(extra)+1)
	for k, v := range extra {
		body[k] = v
	}
	body["items"] = items
	writeJSON(w, body)
}

// writeAll answers a collection that holds every match, with their count.
func writeAll[T any](w http.ResponseWriter, items []T) {
	writeItems(w, items, map[string]interface{}{"total": len(items)})
}

// writeCapped answers a collection cut to limit items out of total matches.
func writeCapped[T any](w http.ResponseWriter, items []T, total, limit int, extra map[string]interface{}) {
	if extra == nil {
		extra = map[string]interface{}{}
	}
	if len(items) > limit {
		items = items[:limit]
	}
	extra["total"] = total
	extra["limit"] = limit
	extra["truncated"] = total > len(items)
	writeItems(w, items, extra)
}

// writeOK answers a successful action: "ok": true plus the action's fields.
func writeOK(w http.ResponseWriter, fields map[string]interface{}) {
	writeOKStatus(w, http.StatusOK, fields)
}

// writeOKStatus is writeOK with another 2xx status, such as 202 for work
// that continues after the response.
func writeOKStatus(w http.ResponseWriter, code int, fields map[string]interface{}) {
	body := make(map[string]interface{}, len(fields)+1)
	for k, v := range fields {
		body[k] = v
	}
	body["ok"] = true
	writeJSONStatus(w, code, body)
}

// writeRemediation answers one fix. A fix that did not apply is an error:
// 422 when the target was not eligible and left unchanged, 500 when applying
// it failed.
func writeRemediation(w http.ResponseWriter, res checks.RemediationResult) {
	if !res.Success {
		msg := res.Error
		if msg == "" {
			msg = "The fix did not apply"
		}
		code := http.StatusInternalServerError
		if res.Refused {
			code = http.StatusUnprocessableEntity
		}
		body := map[string]interface{}{"error": msg}
		if res.Action != "" {
			body["action"] = res.Action
		}
		writeJSONStatus(w, code, body)
		return
	}
	fields := map[string]interface{}{"action": res.Action, "description": res.Description}
	if res.Reverted {
		fields["reverted"] = true
	}
	writeOK(w, fields)
}

// writeRequestError answers a failure from middleware that guards both API
// and page routes: JSON under /api/, plain text elsewhere.
func writeRequestError(w http.ResponseWriter, r *http.Request, msg string, code int) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeJSONError(w, msg, code)
		return
	}
	http.Error(w, msg, code)
}

// apiNotFound answers every /api/ path no route matches. Without it the
// page catch-all served the dashboard HTML with 200 to API clients.
// Unauthenticated callers get 401, as for a real route.
func (s *Server) apiNotFound(w http.ResponseWriter, r *http.Request) {
	if !s.tokenHasScope(r, "read") {
		writeJSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSONError(w, "Not found", http.StatusNotFound)
}

// queryInt reads a non-negative integer query parameter. A missing, negative
// or non-numeric value gives defaultVal.
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
