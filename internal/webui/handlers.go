package webui

import (
	"fmt"
	"net/http"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/checks"
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
	FanotifyActive bool
	RecentFindings []historyEntry
	TimelineBars   []timelineBar // 24 hourly bars for the timeline chart
}

type timelineBar struct {
	Hour     string // "14:00"
	Critical int
	High     int
	Warning  int
	Total    int
	Height   int // percentage height (0-100) for SVG rendering
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
	HasFix    bool
	FixDesc   string
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
	findings, _ := s.store.ReadHistory(500, 0)

	critical, high, warning := 0, 0, 0
	last24h := time.Now().Add(-24 * time.Hour)
	var recent []historyEntry

	// Timeline: 24 hourly buckets
	type hourBucket struct {
		critical, high, warning int
	}
	buckets := make(map[int]*hourBucket) // key: hours ago (0=current, 23=oldest)
	for i := 0; i < 24; i++ {
		buckets[i] = &hourBucket{}
	}

	for _, f := range findings {
		if f.Timestamp.Before(last24h) {
			continue
		}
		switch f.Severity {
		case alert.Critical:
			critical++
		case alert.High:
			high++
		case alert.Warning:
			warning++
		}

		// Timeline bucket
		hoursAgo := int(time.Since(f.Timestamp).Hours())
		if hoursAgo < 24 {
			b := buckets[hoursAgo]
			switch f.Severity {
			case alert.Critical:
				b.critical++
			case alert.High:
				b.high++
			case alert.Warning:
				b.warning++
			}
		}

		if len(recent) < 20 {
			recent = append(recent, historyEntry{
				Severity:  severityLabel(f.Severity),
				SevClass:  severityClass(f.Severity),
				Check:     f.Check,
				Message:   f.Message,
				Details:   f.Details,
				Timestamp: f.Timestamp.Format("15:04:05"),
				TimeAgo:   timeAgo(f.Timestamp),
			})
		}
	}

	// Build timeline bars (oldest to newest: 23h ago → 0h ago)
	maxTotal := 1
	for _, b := range buckets {
		total := b.critical + b.high + b.warning
		if total > maxTotal {
			maxTotal = total
		}
	}

	var bars []timelineBar
	now := time.Now()
	for i := 23; i >= 0; i-- {
		b := buckets[i]
		total := b.critical + b.high + b.warning
		height := 0
		if total > 0 {
			height = (total * 100) / maxTotal
			if height < 5 {
				height = 5 // minimum visible bar
			}
		}
		t := now.Add(-time.Duration(i) * time.Hour)
		bars = append(bars, timelineBar{
			Hour:     fmt.Sprintf("%02d:00", t.Hour()),
			Critical: b.critical,
			High:     b.high,
			Warning:  b.warning,
			Total:    total,
			Height:   height,
		})
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
		FanotifyActive: s.fanotifyActive,
		RecentFindings: recent,
		TimelineBars:   bars,
	}
	_ = s.templates["dashboard.html"].ExecuteTemplate(w, "dashboard.html", data)
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
			HasFix:    checks.HasFix(check),
			FixDesc:   checks.FixDescription(check, message),
		})
	}

	data := findingsData{
		Hostname: s.cfg.Hostname,
		Entries:  items,
	}
	_ = s.templates["findings.html"].ExecuteTemplate(w, "findings.html", data)
}

func (s *Server) handleHistory(w http.ResponseWriter, _ *http.Request) {
	// Load all recent history — client-side CSM.Table handles pagination
	findings, _ := s.store.ReadHistory(1000, 0)

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
	}
	_ = s.templates["history.html"].ExecuteTemplate(w, "history.html", data)
}

func (s *Server) handleQuarantine(w http.ResponseWriter, _ *http.Request) {
	_ = s.templates["quarantine.html"].ExecuteTemplate(w, "quarantine.html", quarantineData{
		Hostname: s.cfg.Hostname,
	})
}

func (s *Server) handleBlocked(w http.ResponseWriter, _ *http.Request) {
	_ = s.templates["blocked.html"].ExecuteTemplate(w, "blocked.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
}
