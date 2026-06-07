package webui

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// emailGroupsScanCap is the hard upper bound on findings inspected per
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
	Kind           string          `json:"kind"`
	Severity       int             `json:"severity"`
	Title          string          `json:"title"`
	Subject        string          `json:"subject"`
	Count          int             `json:"count"`
	FirstSeen      string          `json:"first_seen"`
	LastSeen       string          `json:"last_seen"`
	Summary        string          `json:"summary"`
	SampleFindings []alert.Finding `json:"sample_findings"`
	IPs            []string        `json:"ips,omitempty"`
	TopIPs         []string        `json:"top_ips,omitempty"`
	Domains        []string        `json:"domains,omitempty"`
	MessageIDs     []string        `json:"message_ids,omitempty"`
}

type emailGroupsResponse struct {
	Groups    []emailGroup `json:"groups"`
	From      string       `json:"from"`
	To        string       `json:"to"`
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
		"email_av_timeout",
		"email_av_parse_error",
		"email_av_quarantine_error":
		return "malware"
	case "mail_per_account",
		"mail_queue",
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
					Severity:  int(f.Severity),
					Title:     emailGroupTitle(kind, f),
					Subject:   emailGroupSubject(kind, f),
					FirstSeen: ts.UTC().Format(time.RFC3339),
					LastSeen:  ts.UTC().Format(time.RFC3339),
				},
				ipCounts:  make(map[string]int),
				domainSet: make(map[string]struct{}),
				msgIDSet:  make(map[string]struct{}),
			}
			groups[key] = agg
			order = append(order, key)
		}
		agg.group.Count++
		if int(f.Severity) > agg.group.Severity {
			agg.group.Severity = int(f.Severity)
		}
		ftsStr := ts.UTC().Format(time.RFC3339)
		if ftsStr < agg.group.FirstSeen {
			agg.group.FirstSeen = ftsStr
		}
		if ftsStr > agg.group.LastSeen {
			agg.group.LastSeen = ftsStr
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
		g.SampleFindings = agg.samples
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
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].LastSeen > out[j].LastSeen
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

// parseEmailGroupDate accepts RFC3339 or YYYY-MM-DD; returns the default
// when the input is empty or unparseable. Date-only upper bounds include
// the whole local day, matching /api/v1/history.
func parseEmailGroupDate(s string, def time.Time, endOfDay bool) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
		if endOfDay {
			return t.Add(24*time.Hour - time.Nanosecond)
		}
		return t
	}
	return def
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
	from := parseEmailGroupDate(q.Get("from"), now.Add(-24*time.Hour), false)
	to := parseEmailGroupDate(q.Get("to"), now, true)
	if to.Before(from) {
		from, to = to, from
	}

	var findings []alert.Finding
	if s.store != nil {
		findings = s.store.ReadHistorySince(from)
	}
	scanned := len(findings)
	truncated := false
	if scanned > emailGroupsScanCap {
		findings = findings[:emailGroupsScanCap]
		scanned = emailGroupsScanCap
		truncated = true
	}

	groups := buildEmailGroups(findings, from, to, q.Get("kind"))
	if len(groups) > limit {
		groups = groups[:limit]
	}

	writeJSON(w, emailGroupsResponse{
		Groups:    groups,
		From:      from.UTC().Format(time.RFC3339),
		To:        to.UTC().Format(time.RFC3339),
		Scanned:   scanned,
		Truncated: truncated,
	})
}
