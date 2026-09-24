package webui

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// emailGroupsScanCap is the hard upper bound on matching findings retained per
// /api/v1/email/groups call. Bounded reads keep the workbench cheap on
// hosts that store thousands of mail-related findings per day.
const emailGroupsScanCap = 5000

// emailGroupsDefaultLimit / Max bound the number of grouped rows returned
// to the operator UI. The plan caps the email first viewport at ~250 nodes
// so 200 is the highest useful ceiling.
const (
	emailGroupsDefaultLimit = 50
	emailGroupsMaxLimit     = 200
)

type emailGroup struct {
	Kind           string `json:"kind"`
	Severity       string `json:"severity"`
	level          alert.Severity
	Title          string       `json:"title"`
	Subject        string       `json:"subject"`
	Count          int          `json:"count"`
	FirstSeen      time.Time    `json:"first_seen"`
	LastSeen       time.Time    `json:"last_seen"`
	Summary        string       `json:"summary"`
	SampleFindings []apiFinding `json:"sample_findings"`
	IPs            []string     `json:"ips,omitempty"`
	TopIPs         []string     `json:"top_ips,omitempty"`
	Domains        []string     `json:"domains,omitempty"`
	MessageIDs     []string     `json:"message_ids,omitempty"`
}

type emailGroupsResponse struct {
	Groups    []emailGroup `json:"items"`
	Total     int          `json:"total"`
	Offset    int          `json:"offset"`
	Limit     int          `json:"limit"`
	From      time.Time    `json:"from"`
	To        time.Time    `json:"to"`
	Scanned   int          `json:"scanned"`
	Truncated bool         `json:"truncated"`
}

// emailKindForCheck maps an alert check name to its email-workbench group
// kind. Returns "" when the check is not part of the email surface and
// the finding should be skipped by /api/v1/email/groups.
func emailKindForCheck(check string) string {
	switch check {
	case "email_compromised_account",
		"email_credential_leak",
		"email_weak_password",
		"mail_account_compromised",
		"email_pipe_forwarder",
		"email_suspicious_forwarder":
		return "compromised_account"
	case "email_spam_outbreak",
		"email_rate_critical",
		"email_rate_warning",
		"email_php_relay_abuse",
		"email_php_relay_action_failed",
		"email_php_relay_rate_limit_hit",
		"email_cloud_relay_abuse":
		return "spam_outbreak"
	case "email_auth_failure_realtime",
		"email_suspicious_geo",
		"mail_bruteforce",
		"mail_bruteforce_suspected",
		"mail_subnet_spray",
		"mail_account_spray",
		"smtp_bruteforce",
		"smtp_subnet_spray",
		"smtp_account_spray",
		"smtp_probe_abuse":
		return "auth_failure"
	case "email_malware",
		"email_phishing_content",
		"email_av_degraded",
		"email_av_encrypted_archive",
		"email_av_timeout",
		"email_av_parse_error",
		"email_av_quarantine_error":
		return "malware"
	case "mail_per_account",
		"mail_queue",
		"mail_queue_unavailable",
		"email_defer_fail_governor",
		"exim_frozen_realtime":
		return "queue_alert"
	}
	return ""
}

// emailGroupKey is the dedup key used to merge findings into a single
// grouped action row. Different kinds prefer different identity fields:
// auth failures cluster by mailbox/IP, spam/malware/compromised by mailbox
// or domain, and queue alerts by check name.
func emailGroupKey(kind string, f alert.Finding) string {
	mailbox := strings.ToLower(strings.TrimSpace(f.Mailbox))
	domain := strings.ToLower(strings.TrimSpace(f.Domain))
	switch kind {
	case "auth_failure":
		if mailbox != "" {
			return "mailbox:" + mailbox
		}
		if f.SourceIP != "" {
			return "ip:" + f.SourceIP
		}
		if domain != "" {
			return "domain:" + domain
		}
		return "auth:unknown"
	case "queue_alert":
		return "queue:" + f.Check
	default:
		if mailbox != "" {
			return kind + ":mailbox:" + mailbox
		}
		if domain != "" {
			return kind + ":domain:" + domain
		}
		if f.SourceIP != "" {
			return kind + ":ip:" + f.SourceIP
		}
		// Fall back to message text so two distinct payloads with no
		// identity fields still produce two groups instead of collapsing.
		return kind + ":msg:" + strings.TrimSpace(f.Message)
	}
}

// emailGroupTitle renders the human-readable identifier for a grouped row.
// Prefers mailbox > domain > source IP > message text. Queue alerts have
// hard-coded labels because their finding text varies by host.
func emailGroupTitle(kind string, f alert.Finding) string {
	if kind == "queue_alert" {
		switch f.Check {
		case "mail_queue":
			return "Mail queue threshold"
		case "mail_queue_unavailable":
			return "Mail queue unavailable"
		case "mail_per_account":
			return "Per-account mail volume"
		case "exim_frozen_realtime":
			return "Frozen mail queue"
		}
	}
	if f.Mailbox != "" {
		return f.Mailbox
	}
	if f.Domain != "" {
		return f.Domain
	}
	if f.SourceIP != "" {
		return f.SourceIP
	}
	return strings.TrimSpace(f.Message)
}

// emailGroupSubject describes the identity dimension behind the group --
// "mailbox", "domain", "ip", or "queue" -- so the UI can pick the right
// detail-panel tabs without re-reading the raw findings.
func emailGroupSubject(kind string, f alert.Finding) string {
	if kind == "queue_alert" {
		return "queue"
	}
	if f.Mailbox != "" {
		return "mailbox"
	}
	if f.Domain != "" {
		return "domain"
	}
	if f.SourceIP != "" {
		return "ip"
	}
	return "unknown"
}

// buildEmailGroups walks the supplied findings (already bounded), merges
// matching findings into grouped rows, and returns the result sorted by
// severity (desc) then last-seen (desc). Pure function -- the HTTP
// handler is a thin wrapper so tests can drive grouping directly.
func buildEmailGroups(findings []alert.Finding, from, to time.Time, kindFilter string) []emailGroup {
	type aggregator struct {
		group     *emailGroup
		ipCounts  map[string]int
		domainSet map[string]struct{}
		msgIDSet  map[string]struct{}
		samples   []alert.Finding // newest-first
	}

	groups := make(map[string]*aggregator)
	order := make([]string, 0)

	for _, f := range findings {
		ts := f.Timestamp
		if !from.IsZero() && ts.Before(from) {
			continue
		}
		if !to.IsZero() && ts.After(to) {
			continue
		}
		kind := emailKindForCheck(f.Check)
		if kind == "" {
			continue
		}
		if kindFilter != "" && kindFilter != kind {
			continue
		}
		key := emailGroupKey(kind, f)
		agg, ok := groups[key]
		if !ok {
			agg = &aggregator{
				group: &emailGroup{
					Kind:      kind,
					level:     f.Severity,
					Title:     emailGroupTitle(kind, f),
					Subject:   emailGroupSubject(kind, f),
					FirstSeen: ts.UTC(),
					LastSeen:  ts.UTC(),
				},
				ipCounts:  make(map[string]int),
				domainSet: make(map[string]struct{}),
				msgIDSet:  make(map[string]struct{}),
			}
			groups[key] = agg
			order = append(order, key)
		}
		agg.group.Count++
		if f.Severity > agg.group.level {
			agg.group.level = f.Severity
		}
		if ts.Before(agg.group.FirstSeen) {
			agg.group.FirstSeen = ts.UTC()
		}
		if ts.After(agg.group.LastSeen) {
			agg.group.LastSeen = ts.UTC()
		}
		if f.SourceIP != "" {
			agg.ipCounts[f.SourceIP]++
		}
		if f.Domain != "" {
			agg.domainSet[strings.ToLower(f.Domain)] = struct{}{}
		}
		for _, id := range f.MsgIDs {
			if id != "" {
				agg.msgIDSet[id] = struct{}{}
			}
		}
		// Keep up to 3 most recent samples (assumes input is newest-first).
		if len(agg.samples) < 3 {
			agg.samples = append(agg.samples, f)
		}
	}

	out := make([]emailGroup, 0, len(order))
	for _, key := range order {
		agg := groups[key]
		g := agg.group
		// Compose summary text: count + identity + IP/domain hint.
		hint := ""
		if g.Kind == "auth_failure" && len(agg.ipCounts) > 0 {
			hint = " from " + plural(len(agg.ipCounts), "IP")
		} else if len(agg.domainSet) > 1 {
			hint = " across " + plural(len(agg.domainSet), "domain")
		}
		g.Summary = plural(g.Count, "event") + hint
		g.Severity = g.level.String()
		g.SampleFindings = toAPIFindings(agg.samples)
		if len(agg.ipCounts) > 0 {
			g.IPs = sortedKeys(agg.ipCounts)
			g.TopIPs = topKeysByCount(agg.ipCounts, 5)
		}
		if len(agg.domainSet) > 0 {
			g.Domains = sortedSetKeys(agg.domainSet)
		}
		if len(agg.msgIDSet) > 0 {
			g.MessageIDs = sortedSetKeys(agg.msgIDSet)
			if len(g.MessageIDs) > 10 {
				g.MessageIDs = g.MessageIDs[:10]
			}
		}
		out = append(out, *g)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].level != out[j].level {
			return out[i].level > out[j].level
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

func plural(n int, label string) string {
	if n == 1 {
		return "1 " + label
	}
	return itoa(n) + " " + label + "s"
}

func itoa(n int) string {
	// Avoid pulling strconv just for this hot path; keeps the helper inline.
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedSetKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// topKeysByCount returns up to k entries from m sorted by descending count
// (ties broken alphabetically) so the UI shows the dominant attackers
// first.
func topKeysByCount(m map[string]int, k int) []string {
	type entry struct {
		key   string
		count int
	}
	entries := make([]entry, 0, len(m))
	for key, c := range m {
		entries = append(entries, entry{key, c})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].count != entries[j].count {
			return entries[i].count > entries[j].count
		}
		return entries[i].key < entries[j].key
	})
	if k < len(entries) {
		entries = entries[:k]
	}
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.key
	}
	return out
}

// historyRangeQuery reads the from and to parameters the history endpoints
// share, with the meaning store.ParseHistoryBound gives them: to is
// exclusive. A missing bound takes its default. An unreadable one is a 400,
// written here, and ok is false.
func historyRangeQuery(w http.ResponseWriter, q url.Values, defFrom, defTo time.Time) (from, to time.Time, ok bool) {
	from, err := store.ParseHistoryBound(q.Get("from"), false)
	if err != nil {
		writeJSONError(w, "Invalid from: use YYYY-MM-DD or an RFC 3339 time", http.StatusBadRequest)
		return from, to, false
	}
	to, err = store.ParseHistoryBound(q.Get("to"), true)
	if err != nil {
		writeJSONError(w, "Invalid to: use YYYY-MM-DD or an RFC 3339 time", http.StatusBadRequest)
		return from, to, false
	}
	if from.IsZero() {
		from = defFrom
	}
	if to.IsZero() {
		to = defTo
	}
	return from, to, true
}

// apiEmailGroups handles GET /api/v1/email/groups. Returns server-side
// grouped action rows for the email workbench. Read-scope tokens may
// call this endpoint -- it does not mutate state.
func (s *Server) apiEmailGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()

	limit := queryInt(r, "limit", emailGroupsDefaultLimit)
	if limit <= 0 || limit > emailGroupsMaxLimit {
		limit = emailGroupsDefaultLimit
	}

	now := time.Now()
	from, to, ok := historyRangeQuery(w, q, now.Add(-24*time.Hour), now)
	if !ok {
		return
	}
	if to.Before(from) {
		from, to = to, from
	}

	kindFilter := q.Get("kind")
	writeJSON(w, s.emailMemo("groups?"+q.Encode(), func() any {
		return s.buildEmailGroupsResponse(from, to, kindFilter, limit)
	}))
}

func (s *Server) buildEmailGroupsResponse(from, to time.Time, kindFilter string, limit int) emailGroupsResponse {
	var findings []alert.Finding
	if s.store != nil {
		// Filter while walking history so unrelated findings, or findings
		// newer than the requested range, never use up the scan budget.
		findings = s.store.SearchHistorySince(from, emailGroupsScanCap+1, func(f alert.Finding) bool {
			if !f.Timestamp.Before(to) {
				return false
			}
			kind := emailKindForCheck(f.Check)
			return kind != "" && (kindFilter == "" || kind == kindFilter)
		})
	}
	truncated := false
	if len(findings) > emailGroupsScanCap {
		findings = findings[:emailGroupsScanCap]
		truncated = true
	}
	scanned := len(findings)

	groups := buildEmailGroups(findings, from, to, kindFilter)
	total := len(groups)
	if len(groups) > limit {
		truncated = true
		groups = groups[:limit]
	}

	return emailGroupsResponse{
		Groups:    groups,
		Total:     total,
		Limit:     limit,
		From:      from.UTC(),
		To:        to.UTC(),
		Scanned:   scanned,
		Truncated: truncated,
	}
}

// emailMemo reuses an email workbench result for the same query while
// history is unchanged; the page polls these every minute.
func (s *Server) emailMemo(key string, compute func() any) any {
	if s.store == nil {
		return compute()
	}
	return s.emailMemos.memo(key).get(s.store.HistoryMark(), compute)
}
