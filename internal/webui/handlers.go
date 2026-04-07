package webui

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

func (s *Server) renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	if err := s.templates[name].ExecuteTemplate(w, name, data); err != nil {
		fmt.Fprintf(os.Stderr, "[webui] template %s error: %v\n", name, err)
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

func (s *Server) handleDashboard(w http.ResponseWriter, _ *http.Request) {
	last24h := time.Now().Add(-24 * time.Hour)
	findings := s.store.ReadHistorySince(last24h)

	var recent []historyEntry
	critical, high, warning := 0, 0, 0

	for _, f := range findings {
		// Count all findings by severity
		switch f.Severity {
		case alert.Critical:
			critical++
		case alert.High:
			high++
		case alert.Warning:
			warning++
		}

		// Skip internal checks from the live feed
		if f.Check == "auto_response" || f.Check == "auto_block" || f.Check == "check_timeout" || f.Check == "health" {
			continue
		}

		if len(recent) < 10 {
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
				FixDesc:      checks.FixDescription(f.Check, f.Message),
			})
		}
	}

	// Find most recent critical finding (findings are newest-first)
	lastCriticalAgo := "None"
	for _, f := range findings {
		if f.Severity == alert.Critical {
			lastCriticalAgo = timeAgo(f.Timestamp)
			break
		}
	}

	data := dashboardData{
		Hostname:        s.cfg.Hostname,
		Uptime:          time.Since(s.startTime).Round(time.Second).String(),
		Critical:        critical,
		High:            high,
		Warning:         warning,
		Total:           critical + high + warning,
		SigCount:        s.sigCount,
		FanotifyActive:  s.fanotifyActive,
		LogWatchers:     s.logWatcherCount,
		LastCriticalAgo: lastCriticalAgo,
		RecentFindings:  recent,
	}
	s.renderTemplate(w, "dashboard.html", data)
}

func (s *Server) handleFindings(w http.ResponseWriter, _ *http.Request) {
	// Findings page is now JS-driven - enriched API provides data
	s.renderTemplate(w, "findings.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
}

func (s *Server) handleHistoryRedirect(w http.ResponseWriter, r *http.Request) {
	// History is now a tab on the findings page - redirect for backward compat
	target := "/findings?tab=history"
	if qs := r.URL.RawQuery; qs != "" {
		target = "/findings?tab=history&" + qs
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Server) handleQuarantine(w http.ResponseWriter, _ *http.Request) {
	s.renderTemplate(w, "quarantine.html", quarantineData{
		Hostname: s.cfg.Hostname,
	})
}

func (s *Server) handleFirewall(w http.ResponseWriter, _ *http.Request) {
	s.renderTemplate(w, "firewall.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
}

func (s *Server) handleEmail(w http.ResponseWriter, _ *http.Request) {
	s.renderTemplate(w, "email.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
}
