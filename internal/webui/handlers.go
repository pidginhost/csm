package webui

import (
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/checks"
)

// renderTemplate executes a named template and logs errors to stderr.
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
	LastCriticalAgo string
	RecentFindings  []historyEntry
	TimelineBars    []timelineBar // 24 hourly bars for the timeline chart
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
	Hostname   string
	Entries    []findingEntry
	CheckTypes []string // unique check types for filter dropdown
}

type findingEntry struct {
	Severity  string
	SevClass  string
	Check     string
	Message   string
	FilePath  string
	FirstSeen string
	LastSeen  string
	Baseline  bool
	HasFix    bool
	FixDesc   string
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
	findings, _ := s.store.ReadHistory(5000, 0)

	last24h := time.Now().Add(-24 * time.Hour)
	var recent []historyEntry

	// Timeline: 24 hourly buckets keyed by truncated clock hour
	type hourBucket struct {
		critical, high, warning int
	}
	now := time.Now()
	currentHour := now.Truncate(time.Hour)
	buckets := make(map[int]*hourBucket) // key: hours ago (0=current, 23=oldest)
	for i := 0; i < 24; i++ {
		buckets[i] = &hourBucket{}
	}

	for _, f := range findings {
		if f.Timestamp.Before(last24h) {
			continue
		}

		// Timeline bucket — use truncated clock hours for consistency with labels
		fHour := f.Timestamp.Truncate(time.Hour)
		hoursAgo := int(currentHour.Sub(fHour).Hours())
		if hoursAgo >= 0 && hoursAgo < 24 {
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

	// Build timeline bars (oldest to newest: 23h ago → 0h ago)
	maxTotal := 1
	for _, b := range buckets {
		total := b.critical + b.high + b.warning
		if total > maxTotal {
			maxTotal = total
		}
	}

	var bars []timelineBar
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
		t := currentHour.Add(-time.Duration(i) * time.Hour)
		bars = append(bars, timelineBar{
			Hour:     fmt.Sprintf("%02d:00", t.Hour()),
			Critical: b.critical,
			High:     b.high,
			Warning:  b.warning,
			Total:    total,
			Height:   height,
		})
	}

	// Find most recent critical finding
	lastCriticalAgo := "None"
	for _, f := range findings {
		if f.Severity == alert.Critical {
			lastCriticalAgo = timeAgo(f.Timestamp)
			break // findings are newest-first
		}
	}

	// Stats counters start at 0 — dashboard.js populates them via /api/v1/stats
	data := dashboardData{
		Hostname:        s.cfg.Hostname,
		Uptime:          time.Since(s.startTime).Round(time.Second).String(),
		Critical:        0,
		High:            0,
		Warning:         0,
		Total:           0,
		SigCount:        s.sigCount,
		FanotifyActive:  s.fanotifyActive,
		LastCriticalAgo: lastCriticalAgo,
		RecentFindings:  recent,
		TimelineBars:    bars,
	}
	s.renderTemplate(w, "dashboard.html", data)
}

func (s *Server) handleFindings(w http.ResponseWriter, _ *http.Request) {
	// Read from latest scan results — shows "what's wrong right now"
	// (not the alert dedup state, which only tracks what's been emailed)
	latest := s.store.LatestFindings()

	// Filter out auto_response actions, internal checks, and suppressed findings
	suppressions := s.store.LoadSuppressions()
	var items []findingEntry
	for _, f := range latest {
		// Skip auto-response action logs and internal check results
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
		items = append(items, findingEntry{
			Severity:  severityLabel(f.Severity),
			SevClass:  severityClass(f.Severity),
			Check:     f.Check,
			Message:   f.Message,
			FilePath:  f.FilePath,
			FirstSeen: firstSeen.Format("2006-01-02 15:04"),
			LastSeen:  lastSeen.Format("2006-01-02 15:04"),
			HasFix:    checks.HasFix(f.Check),
			FixDesc:   checks.FixDescription(f.Check, f.Message),
		})
	}

	// Collect unique check types for filter dropdown
	checkTypeMap := make(map[string]bool)
	for _, item := range items {
		checkTypeMap[item.Check] = true
	}
	var checkTypes []string
	for ct := range checkTypeMap {
		checkTypes = append(checkTypes, ct)
	}
	sort.Strings(checkTypes)

	data := findingsData{
		Hostname:   s.cfg.Hostname,
		Entries:    items,
		CheckTypes: checkTypes,
	}
	s.renderTemplate(w, "findings.html", data)
}

func (s *Server) handleHistory(w http.ResponseWriter, _ *http.Request) {
	// History page is now fully JS-driven — API provides paginated data
	s.renderTemplate(w, "history.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
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
