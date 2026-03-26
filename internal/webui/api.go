package webui

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

// apiStatus returns daemon status and uptime.
func (s *Server) apiStatus(w http.ResponseWriter, _ *http.Request) {
	status := map[string]interface{}{
		"hostname":     s.cfg.Hostname,
		"uptime":       time.Since(s.startTime).String(),
		"started_at":   s.startTime.Format(time.RFC3339),
		"ws_clients":   s.hub.ClientCount(),
		"rules_loaded": s.sigCount,
	}
	writeJSON(w, status)
}

// apiFindings returns current active state entries.
func (s *Server) apiFindings(w http.ResponseWriter, _ *http.Request) {
	entries := s.store.Entries()

	type entryView struct {
		Check     string `json:"check"`
		Message   string `json:"message"`
		FirstSeen string `json:"first_seen"`
		LastSeen  string `json:"last_seen"`
		Baseline  bool   `json:"is_baseline"`
	}

	var result []entryView
	for key, entry := range entries {
		check, message := state.ParseKey(key)
		result = append(result, entryView{
			Check:     check,
			Message:   message,
			FirstSeen: entry.FirstSeen.Format(time.RFC3339),
			LastSeen:  entry.LastSeen.Format(time.RFC3339),
			Baseline:  entry.IsBaseline,
		})
	}
	writeJSON(w, result)
}

// apiHistory returns paginated history from history.jsonl.
func (s *Server) apiHistory(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	offset := queryInt(r, "offset", 0)

	findings, total := s.store.ReadHistory(limit, offset)

	result := map[string]interface{}{
		"findings": findings,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
	}
	writeJSON(w, result)
}

// apiQuarantine lists quarantined files with metadata.
func (s *Server) apiQuarantine(w http.ResponseWriter, _ *http.Request) {
	const quarantineDir = "/opt/csm/quarantine"

	type quarantineEntry struct {
		ID           string `json:"id"`
		OriginalPath string `json:"original_path"`
		Size         int64  `json:"size"`
		QuarantineAt string `json:"quarantined_at"`
		Reason       string `json:"reason"`
	}

	var entries []quarantineEntry

	metaFiles, _ := filepath.Glob(filepath.Join(quarantineDir, "*.meta"))
	for _, metaFile := range metaFiles {
		data, err := os.ReadFile(metaFile)
		if err != nil {
			continue
		}

		var meta struct {
			OriginalPath string    `json:"original_path"`
			Size         int64     `json:"size"`
			QuarantineAt time.Time `json:"quarantine_at"`
			Reason       string    `json:"reason"`
		}
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}

		id := filepath.Base(metaFile)
		id = id[:len(id)-5] // remove .meta

		entries = append(entries, quarantineEntry{
			ID:           id,
			OriginalPath: meta.OriginalPath,
			Size:         meta.Size,
			QuarantineAt: meta.QuarantineAt.Format(time.RFC3339),
			Reason:       meta.Reason,
		})
	}

	writeJSON(w, entries)
}

// apiStats returns severity counts and per-check breakdown.
func (s *Server) apiStats(w http.ResponseWriter, _ *http.Request) {
	findings, _ := s.store.ReadHistory(500, 0)

	critical, high, warning := 0, 0, 0
	byCheck := make(map[string]int)
	last24h := time.Now().Add(-24 * time.Hour)

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
		byCheck[f.Check]++
	}

	result := map[string]interface{}{
		"last_24h": map[string]interface{}{
			"critical": critical,
			"high":     high,
			"warning":  warning,
			"total":    critical + high + warning,
		},
		"by_check": byCheck,
	}
	writeJSON(w, result)
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(data)
}

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
