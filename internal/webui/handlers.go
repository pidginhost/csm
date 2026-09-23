package webui

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/checks"
)

func (s *Server) renderTemplate(w http.ResponseWriter, r *http.Request, name string, data interface{}) {
	base := s.templates[name]
	if base == nil {
		fmt.Fprintf(os.Stderr, "[webui] template %s missing\n", name)
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	// The CSRF token belongs to the browser session loading the page, so
	// each render binds it on a clone of the parsed template.
	tmpl, err := base.Clone()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[webui] template %s clone error: %v\n", name, err)
		http.Error(w, "template render error", http.StatusInternalServerError)
		return
	}
	token := s.csrfTokenFor(r)
	tmpl.Funcs(template.FuncMap{"csrfToken": func() string { return token }})
	// Render into a buffer first so an execution error can still surface as a
	// 500 — html/template streams directly to its writer, and once any byte
	// has been flushed the status header is locked in.
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		fmt.Fprintf(os.Stderr, "[webui] template %s error: %v\n", name, err)
		http.Error(w, "template render error", http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(buf.Bytes()); err != nil {
		fmt.Fprintf(os.Stderr, "[webui] template %s write error: %v\n", name, err)
	}
}

type dashboardData struct {
	Hostname        string
	Uptime          string
	Critical        int
	High            int
	Warning         int
	Total           int
	SigCount        int
	FanotifyActive  bool
	LogWatchers     int
	LastCriticalAgo string
	LastCriticalISO string // RFC3339 of most recent critical, "" if none (so relative time can tick client-side)
	RecentFindings  []historyEntry
}

type historyEntry struct {
	Severity     string
	SevClass     string
	Check        string
	Message      string
	Details      string
	Timestamp    string
	TimestampISO string // RFC3339 for JS comparison
	TimeAgo      string
	HasFix       bool
	FixDesc      string
	Key          string // canonical dedup key (matches alert.Finding.Key())
}

type quarantineData struct {
	Hostname string
	Files    []quarantineEntry
}

type quarantineEntry struct {
	ID           string
	OriginalPath string
	Size         int64
	QuarantineAt string
	Reason       string
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	sum := s.statsSummary24h()

	recent := make([]historyEntry, 0, len(sum.recent))
	for _, f := range sum.recent {
		recent = append(recent, historyEntry{
			Severity:     severityLabel(f.Severity),
			SevClass:     severityClass(f.Severity),
			Check:        f.Check,
			Message:      f.Message,
			Details:      f.Details,
			Timestamp:    f.Timestamp.Format("15:04:05"),
			TimestampISO: f.Timestamp.Format(time.RFC3339),
			TimeAgo:      timeAgo(f.Timestamp),
			HasFix:       checks.HasFix(f.Check),
			FixDesc:      checks.FixDescription(f.Check, f.Message, f.FilePath),
			Key:          f.Key(),
		})
	}

	lastCriticalAgo, lastCriticalISO := "None", ""
	if !sum.lastCritical.IsZero() {
		lastCriticalAgo = timeAgo(sum.lastCritical)
		lastCriticalISO = sum.lastCritical.Format(time.RFC3339)
	}

	data := dashboardData{
		Hostname:        s.cfg.Hostname,
		Uptime:          time.Since(s.startTime).Round(time.Second).String(),
		Critical:        sum.critical,
		High:            sum.high,
		Warning:         sum.warning,
		Total:           sum.critical + sum.high + sum.warning,
		SigCount:        s.signatureCount(),
		FanotifyActive:  s.fanotifyRunning(),
		LogWatchers:     s.logWatchersRunning(),
		LastCriticalAgo: lastCriticalAgo,
		LastCriticalISO: lastCriticalISO,
		RecentFindings:  recent,
	}
	s.renderTemplate(w, r, "dashboard.html", data)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	// Findings page is now JS-driven - enriched API provides data
	s.renderTemplate(w, r, "findings.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
}

func (s *Server) handleHistoryRedirect(w http.ResponseWriter, r *http.Request) {
	// History is now a tab on the findings page - redirect for backward compat
	target := "/findings?tab=history"
	if qs := r.URL.RawQuery; qs != "" {
		target = "/findings?tab=history&" + qs
	}
	// #nosec G710 -- target always starts with the fixed same-origin
	// /findings path; the incoming query can only add parameters.
	http.Redirect(w, r, target, http.StatusFound)
}

// handleBlockedRedirect sends the Firewall page's old address to the page.
func (s *Server) handleBlockedRedirect(w http.ResponseWriter, r *http.Request) {
	target := "/firewall"
	if qs := r.URL.RawQuery; qs != "" {
		target += "?" + qs
	}
	// #nosec G710 -- target always starts with the fixed same-origin
	// /firewall path; the incoming query can only add parameters.
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Server) handleQuarantine(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, r, "quarantine.html", quarantineData{
		Hostname: s.cfg.Hostname,
	})
}

func (s *Server) handleCleanupHistory(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, r, "cleanup-history.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
}

func (s *Server) handleFirewall(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, r, "firewall.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
}

func (s *Server) handleEmail(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, r, "email.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, r, "settings.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
}
