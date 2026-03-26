package webui

import (
	"net/http"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

type dashboardData struct {
	Hostname       string
	Uptime         string
	Critical       int
	High           int
	Warning        int
	Total          int
	WSClients      int
	SigCount       int
	AuthToken      string // for WebSocket JS connection
	RecentFindings []historyEntry
}

type findingsData struct {
	Hostname string
	Entries  []findingEntry
}

type findingEntry struct {
	Check     string
	Message   string
	FirstSeen string
	LastSeen  string
	Baseline  bool
}

type historyData struct {
	Hostname string
	Findings []historyEntry
	Page     int
	NextPage int
	PrevPage int
	HasNext  bool
	HasPrev  bool
}

type historyEntry struct {
	Severity  string
	SevClass  string
	Check     string
	Message   string
	Details   string
	Timestamp string
	TimeAgo   string
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
	findings, _ := s.store.ReadHistory(200, 0)

	critical, high, warning := 0, 0, 0
	last24h := time.Now().Add(-24 * time.Hour)
	var recent []historyEntry

	for _, f := range findings {
		if f.Timestamp.Before(last24h) {
			continue
		}
		switch f.Severity {
		case 2:
			critical++
		case 1:
			high++
		case 0:
			warning++
		}
		if len(recent) < 20 {
			recent = append(recent, historyEntry{
				Severity:  severityLabel(f.Severity),
				SevClass:  severityClass(f.Severity),
				Check:     f.Check,
				Message:   f.Message,
				Timestamp: f.Timestamp.Format("15:04:05"),
				TimeAgo:   timeAgo(f.Timestamp),
			})
		}
	}

	data := dashboardData{
		Hostname:       s.cfg.Hostname,
		Uptime:         time.Since(s.startTime).Round(time.Second).String(),
		Critical:       critical,
		High:           high,
		Warning:        warning,
		Total:          critical + high + warning,
		WSClients:      s.hub.ClientCount(),
		SigCount:       s.sigCount,
		AuthToken:      s.cfg.WebUI.AuthToken,
		RecentFindings: recent,
	}
	_ = s.templates.ExecuteTemplate(w, "dashboard.html", data)
}

func (s *Server) handleFindings(w http.ResponseWriter, _ *http.Request) {
	entries := s.store.Entries()

	var items []findingEntry
	for key, entry := range entries {
		if entry.IsBaseline {
			continue
		}
		check, message := state.ParseKey(key)
		items = append(items, findingEntry{
			Check:     check,
			Message:   message,
			FirstSeen: entry.FirstSeen.Format("2006-01-02 15:04"),
			LastSeen:  entry.LastSeen.Format("2006-01-02 15:04"),
			Baseline:  entry.IsBaseline,
		})
	}

	data := findingsData{
		Hostname: s.cfg.Hostname,
		Entries:  items,
	}
	_ = s.templates.ExecuteTemplate(w, "findings.html", data)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	page := queryInt(r, "page", 1)
	if page < 1 {
		page = 1
	}
	perPage := 50
	offset := (page - 1) * perPage

	findings, total := s.store.ReadHistory(perPage, offset)

	var items []historyEntry
	for _, f := range findings {
		items = append(items, historyEntry{
			Severity:  severityLabel(f.Severity),
			SevClass:  severityClass(f.Severity),
			Check:     f.Check,
			Message:   f.Message,
			Details:   f.Details,
			Timestamp: f.Timestamp.Format("2006-01-02 15:04:05"),
			TimeAgo:   timeAgo(f.Timestamp),
		})
	}

	data := historyData{
		Hostname: s.cfg.Hostname,
		Findings: items,
		Page:     page,
		NextPage: page + 1,
		PrevPage: page - 1,
		HasNext:  offset+perPage < total,
		HasPrev:  page > 1,
	}
	_ = s.templates.ExecuteTemplate(w, "history.html", data)
}

func (s *Server) handleQuarantine(w http.ResponseWriter, _ *http.Request) {
	// Reuse API logic but render as HTML
	_ = s.templates.ExecuteTemplate(w, "quarantine.html", quarantineData{
		Hostname: s.cfg.Hostname,
	})
}
