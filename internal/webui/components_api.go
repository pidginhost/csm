package webui

import (
	"net/http"
	"sort"
	"time"
)

// componentsProvider is the optional capability surface the daemon
// exposes for /api/v1/components. Tests and the API-only fallback path
// can omit it; the handler degrades to attached/unknown.
type componentsProvider interface {
	WatcherStatuses() map[string]bool
	WatcherChangedAt() map[string]time.Time
}

// componentRow is the JSON shape returned per watcher.
type componentRow struct {
	Name           string `json:"name"`
	Label          string `json:"label"`
	Status         string `json:"status"` // "ok" | "degraded" | "idle" | "unknown"
	Attached       bool   `json:"attached"`
	ChangedAtISO   string `json:"changed_at_iso,omitempty"`
	ChangedAgo     string `json:"changed_ago,omitempty"`
	LastEventISO   string `json:"last_event_iso,omitempty"`
	LastEventAgo   string `json:"last_event_ago,omitempty"`
	LastEventCheck string `json:"last_event_check,omitempty"`
}

// componentLabels maps the short watcher name to the operator-facing label.
// Watchers not in the map render with their raw key.
var componentLabels = map[string]string{
	"fanotify":          "Fanotify (filesystem)",
	"audit":             "Auditd",
	"modsec":            "ModSecurity audit",
	"afalg":             "AF_ALG kernel monitor",
	"phprelay":          "PHP relay watcher",
	"maillog":           "Mail log",
	"email_av_spool":    "Email AV spool",
	"pamlistener":       "PAM listener",
	"connection":        "Connection tracker",
	"exec":              "Exec monitor",
	"sensitive":         "Sensitive file monitor",
	"accesslog":         "Access log",
	"dovecot_log":       "Dovecot log",
	"exim_mainlog":      "Exim mainlog",
	"cpanel_access_log": "cPanel access log",
}

// componentCheckOrigin maps a finding Check name back to the watcher that
// emits it. Only the entries with a clear single-source origin are listed;
// findings produced by periodic checks (filesystem scans, signature
// scans, threat intel correlation) intentionally have no entry so they do
// not advance a watcher's "last event" clock.
var componentCheckOrigin = map[string]string{
	"waf_attack_blocked":       "modsec",
	"waf_status":               "modsec",
	"waf_rules":                "modsec",
	"af_alg_socket":            "afalg",
	"af_alg_enforcement":       "afalg",
	"php_relay_outbound":       "phprelay",
	"php_relay_credential":     "phprelay",
	"mail_per_account":         "maillog",
	"mail_queue":               "maillog",
	"mailbox_takeover":         "maillog",
	"smtp_brute_force":         "maillog",
	"dovecot_login_bruteforce": "maillog",
	"webshell":                 "fanotify",
	"new_php_in_uploads":       "fanotify",
	"new_executable_in_config": "fanotify",
	"new_suspicious_php":       "fanotify",
	"new_webshell_file":        "fanotify",
	"obfuscated_php":           "fanotify",
	"suspicious_php_content":   "fanotify",
	"phishing_php":             "fanotify",
	"htaccess_handler_abuse":   "fanotify",
	"htaccess_injection":       "fanotify",
	"sensitive_file_modified":  "sensitive",
	"sensitive_file_read":      "sensitive",
	"backdoor_port_outbound":   "connection",
	"c2_connection":            "connection",
	"user_outbound_connection": "connection",
	"php_suspicious_execution": "exec",
	"pam_password_change":      "pamlistener",
	"pam_login_failure":        "pamlistener",
}

// apiComponents returns one row per registered watcher with its live
// state, time since last state change, and the most recent finding it
// emitted within a 7-day lookback. Drives the dashboard component
// matrix.
func (s *Server) apiComponents(w http.ResponseWriter, _ *http.Request) {
	cp, _ := s.provider.(componentsProvider)
	if cp == nil {
		writeJSON(w, []componentRow{})
		return
	}

	statuses := cp.WatcherStatuses()
	changed := cp.WatcherChangedAt()
	lastEvents := s.lastEventByWatcher(7 * 24 * time.Hour)

	rows := make([]componentRow, 0, len(statuses))
	for name, attached := range statuses {
		row := componentRow{
			Name:     name,
			Label:    componentLabel(name),
			Attached: attached,
		}
		if t, ok := changed[name]; ok && !t.IsZero() {
			row.ChangedAtISO = t.Format(time.RFC3339)
			row.ChangedAgo = timeAgo(t)
		}
		if ev, ok := lastEvents[name]; ok && !ev.at.IsZero() {
			row.LastEventISO = ev.at.Format(time.RFC3339)
			row.LastEventAgo = timeAgo(ev.at)
			row.LastEventCheck = ev.check
		}
		row.Status = componentStatus(attached, lastEvents[name].at)
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Status != rows[j].Status {
			return componentStatusRank(rows[i].Status) < componentStatusRank(rows[j].Status)
		}
		return rows[i].Label < rows[j].Label
	})

	writeJSON(w, rows)
}

type watcherEvent struct {
	at    time.Time
	check string
}

// lastEventByWatcher walks history within the lookback window and returns
// the most recent finding per known watcher key. Findings whose Check is
// not in componentCheckOrigin are skipped so periodic-scan output does
// not get attributed to a real-time watcher.
func (s *Server) lastEventByWatcher(window time.Duration) map[string]watcherEvent {
	out := map[string]watcherEvent{}
	if s.store == nil {
		return out
	}
	since := time.Now().Add(-window)
	for _, f := range s.store.ReadHistorySince(since) {
		watcher, ok := componentCheckOrigin[f.Check]
		if !ok {
			continue
		}
		if cur, exists := out[watcher]; exists && !cur.at.Before(f.Timestamp) {
			continue
		}
		out[watcher] = watcherEvent{at: f.Timestamp, check: f.Check}
	}
	// Also fold in the latest scan set so freshly-emitted findings appear
	// before they have rolled into history.
	for _, f := range s.store.LatestFindings() {
		watcher, ok := componentCheckOrigin[f.Check]
		if !ok {
			continue
		}
		if cur, exists := out[watcher]; exists && !cur.at.Before(f.Timestamp) {
			continue
		}
		out[watcher] = watcherEvent{at: f.Timestamp, check: f.Check}
	}
	return out
}

func componentLabel(name string) string {
	if l, ok := componentLabels[name]; ok {
		return l
	}
	return name
}

// componentStatus collapses the per-row state into a UI bucket.
//   - degraded: watcher detached (attempted setup, failed or fell off)
//   - ok:       attached AND has produced at least one event recently
//   - idle:     attached but no events recorded yet (or none in window)
//   - unknown:  not attached and no record either way (reserved)
func componentStatus(attached bool, lastEvent time.Time) string {
	if !attached {
		return "degraded"
	}
	if lastEvent.IsZero() {
		return "idle"
	}
	return "ok"
}

func componentStatusRank(status string) int {
	switch status {
	case "degraded":
		return 0
	case "idle":
		return 1
	case "ok":
		return 2
	default:
		return 3
	}
}
