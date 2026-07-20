package webui

import (
	"net/http"
	"sort"
	"time"

	"github.com/pidginhost/csm/internal/health"
)

// componentsProvider is the optional capability surface the daemon
// exposes for /api/v1/components. Tests and the API-only fallback path
// can omit it; the handler degrades to attached/unknown.
type componentsProvider interface {
	WatcherStatuses() map[string]bool
	WatcherChangedAt() map[string]time.Time
}

// componentsUpstreamProvider is the optional capability surface the
// daemon adds when it has per-watcher upstream probes wired. Returning
// nil / absent for a watcher means "no probe, do not flag deaf".
type componentsUpstreamProvider interface {
	WatcherUpstream() map[string]health.UpstreamResult
}

// componentRow is the JSON shape returned per watcher.
type componentRow struct {
	Name            string `json:"name"`
	Label           string `json:"label"`
	Status          string `json:"status"` // "ok" | "degraded" | "deaf" | "idle" | "unknown"
	Attached        bool   `json:"attached"`
	ChangedAtISO    string `json:"changed_at_iso,omitempty"`
	ChangedAgo      string `json:"changed_ago,omitempty"`
	LastEventISO    string `json:"last_event_iso,omitempty"`
	LastEventAgo    string `json:"last_event_ago,omitempty"`
	LastEventCheck  string `json:"last_event_check,omitempty"`
	UpstreamFresh   *bool  `json:"upstream_fresh,omitempty"`
	UpstreamReason  string `json:"upstream_reason,omitempty"`
	UpstreamSeenISO string `json:"upstream_seen_iso,omitempty"`
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
	"forwarder":         "Forwarder watcher",
	"pamlistener":       "PAM listener",
	"php_shield":        "PHP Shield event log",
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
// finding names reused by periodic or retroactive scans intentionally have
// no entry so they do not advance a watcher's "last event" clock.
var componentCheckOrigin = map[string]string{
	"cgi_backdoor_realtime":                      "fanotify",
	"cgi_suspicious_location_realtime":           "fanotify",
	"credential_log_realtime":                    "fanotify",
	"email_auth_failure_realtime":                "maillog",
	"email_av_degraded":                          "email_av_spool",
	"email_av_parse_error":                       "email_av_spool",
	"email_av_quarantine_error":                  "email_av_spool",
	"email_av_timeout":                           "email_av_spool",
	"email_compromised_account":                  "maillog",
	"email_credential_leak":                      "maillog",
	"email_dkim_failure":                         "maillog",
	"email_malware":                              "email_av_spool",
	"email_php_relay_action_dry_run":             "phprelay",
	"email_php_relay_action_failed":              "phprelay",
	"email_php_relay_action_skipped":             "phprelay",
	"email_php_relay_abuse":                      "phprelay",
	"email_php_relay_account_volume_capped":      "phprelay",
	"email_php_relay_cpanel_limit_unreadable":    "phprelay",
	"email_php_relay_disabled":                   "phprelay",
	"email_php_relay_inotify_overflow":           "phprelay",
	"email_php_relay_inotify_overflow_recovered": "phprelay",
	"email_php_relay_msgindex_persist_failed":    "phprelay",
	"email_php_relay_no_exim":                    "phprelay",
	"email_php_relay_overflow_scan_truncated":    "phprelay",
	"email_php_relay_path2b_disabled":            "phprelay",
	"email_php_relay_policies_reload":            "phprelay",
	"email_php_relay_rate_limit_hit":             "phprelay",
	"email_php_relay_sweep_failed":               "phprelay",
	"email_php_relay_watcher_failed":             "phprelay",
	"email_defer_fail_governor":                  "maillog",
	"email_rate_critical":                        "maillog",
	"email_rate_warning":                         "maillog",
	"email_spam_outbreak":                        "maillog",
	"email_spf_rejection":                        "maillog",
	"executable_in_config_realtime":              "fanotify",
	"executable_in_tmp_realtime":                 "fanotify",
	"exim_frozen_realtime":                       "maillog",
	"fanotify_overflow":                          "fanotify",
	"htaccess_injection_realtime":                "fanotify",
	"self_deleting_dropper_realtime":             "fanotify",
	"self_deleting_dropper_overflow":             "fanotify",
	"mail_account_compromised":                   "maillog",
	"mail_account_spray":                         "maillog",
	"mail_auth_backend_degraded":                 "maillog",
	"mail_bruteforce":                            "maillog",
	"mail_bruteforce_suspected":                  "maillog",
	"mail_log_source_unavailable":                "maillog",
	"mail_subnet_spray":                          "maillog",
	"modsec_block_escalation":                    "modsec",
	"modsec_block_realtime":                      "modsec",
	"modsec_classifier_gap":                      "modsec",
	"modsec_csm_block_escalation":                "modsec",
	"modsec_low_confidence_burst":                "modsec",
	"modsec_warning_realtime":                    "modsec",
	"obfuscated_php_realtime":                    "fanotify",
	"credential_stuffing":                        "pamlistener",
	"pam_bruteforce":                             "pamlistener",
	"pam_login":                                  "pamlistener",
	"phishing_kit_realtime":                      "fanotify",
	"phishing_realtime":                          "fanotify",
	"php_shield_block":                           "php_shield",
	"php_shield_eval":                            "php_shield",
	"php_shield_webshell":                        "php_shield",
	"php_config_realtime":                        "fanotify",
	"php_dropper_realtime":                       "fanotify",
	"php_in_sensitive_dir_realtime":              "fanotify",
	"php_in_uploads_realtime":                    "fanotify",
	"signature_match_realtime":                   "fanotify",
	"smtp_account_spray":                         "maillog",
	"smtp_bruteforce":                            "maillog",
	"smtp_probe_abuse":                           "maillog",
	"smtp_subnet_spray":                          "maillog",
	"webshell_content_realtime":                  "fanotify",
	"webshell_realtime":                          "fanotify",
	"yara_match_realtime":                        "fanotify",
	"yara_match_scheduled":                       "scheduled",
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
	var upstream map[string]health.UpstreamResult
	if up, ok := s.provider.(componentsUpstreamProvider); ok {
		upstream = up.WatcherUpstream()
	}

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
		var upstreamFresh *bool
		if up, ok := upstream[name]; ok {
			fresh := up.Fresh
			upstreamFresh = &fresh
			row.UpstreamFresh = upstreamFresh
			row.UpstreamReason = up.Reason
			if !up.LastActivity.IsZero() {
				row.UpstreamSeenISO = up.LastActivity.Format(time.RFC3339)
			}
		}
		row.Status = componentStatus(attached, lastEvents[name].at, upstreamFresh)
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
		if f.Timestamp.Before(since) {
			continue
		}
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
//   - deaf:     attached but the upstream feeding it has gone silent
//     (probe registered, returned Fresh=false). Operator action needed
//     before this watcher will ever produce events again.
//   - ok:       attached AND has produced at least one event recently
//   - idle:     attached, no events in window, and either no probe is
//     wired or the probe still confirms the upstream is alive
//   - unknown:  not attached and no record either way (reserved)
func componentStatus(attached bool, lastEvent time.Time, upstreamFresh *bool) string {
	if !attached {
		return "degraded"
	}
	if upstreamFresh != nil && !*upstreamFresh {
		return "deaf"
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
	case "deaf":
		return 1
	case "idle":
		return 2
	case "ok":
		return 3
	default:
		return 4
	}
}
