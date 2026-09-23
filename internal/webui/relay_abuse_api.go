package webui

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

type relayAbuseResponse struct {
	Entries   []relayAbuseEntry `json:"items"`
	Total     int               `json:"total"`
	Limit     int               `json:"limit"`
	From      time.Time         `json:"from"`
	To        time.Time         `json:"to"`
	Truncated bool              `json:"truncated"`
}

type relayAbuseEntry struct {
	Path         string           `json:"path"`
	PathLabel    string           `json:"path_label"`
	Severity     int              `json:"severity"`
	SourceIP     string           `json:"source_ip,omitempty"`
	CPUser       string           `json:"cp_user,omitempty"`
	TriggerCount int              `json:"trigger_count"`
	DetectedAt   time.Time        `json:"detected_at"`
	Sites        []relaySiteEntry `json:"sites"`
	MsgSample    []string         `json:"msg_sample,omitempty"`
}

type relaySiteEntry struct {
	Site          string    `json:"site"`
	Script        string    `json:"script"`
	Hits          int       `json:"hits"`
	LastSeen      time.Time `json:"last_seen"`
	SampleSubject string    `json:"sample_subject,omitempty"`
}

const relayAbuseDefaultLimit = 20
const relayAbuseMaxLimit = 100

func relayPathLabel(path string) string {
	switch path {
	case "fanout":
		return "Spam outbreak (IP fanout)"
	case "volume":
		return "High volume script"
	case "header":
		return "Suspicious headers"
	case "volume_account":
		return "High volume account"
	case "":
		return "Unknown path"
	default:
		return path
	}
}

// apiEmailRelayAbuse handles GET /api/v1/email/relay-abuse. Read-only.
// Reads email_php_relay_abuse findings from persisted history (the realtime
// dispatch path does not populate LatestFindings).
func (s *Server) apiEmailRelayAbuse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()

	limit := queryInt(r, "limit", relayAbuseDefaultLimit)
	if limit <= 0 || limit > relayAbuseMaxLimit {
		limit = relayAbuseDefaultLimit
	}

	now := time.Now()
	from, to, ok := historyRangeQuery(w, q, now.Add(-24*time.Hour), now)
	if !ok {
		return
	}
	if to.Before(from) {
		from, to = to, from
	}

	writeJSON(w, s.emailMemo("relay?"+q.Encode(), func() any {
		return s.buildRelayAbuseResponse(from, to, limit)
	}))
}

func (s *Server) buildRelayAbuseResponse(from, to time.Time, limit int) relayAbuseResponse {
	resp := relayAbuseResponse{
		Entries: []relayAbuseEntry{},
		Limit:   limit,
		From:    from.UTC(),
		To:      to.UTC(),
	}
	if s.store == nil {
		return resp
	}

	// Filter while walking newest-first history and cap the matches, so
	// unrelated findings and findings newer than the range never hide a
	// match. Truncation covers both this budget and the result limit below.
	rows := s.store.SearchHistorySince(from, emailGroupsScanCap+1, func(f alert.Finding) bool {
		return f.Check == "email_php_relay_abuse" && f.Timestamp.Before(to)
	})
	if len(rows) > emailGroupsScanCap {
		rows = rows[:emailGroupsScanCap]
		resp.Truncated = true
	}
	resp.Total = len(rows)

	sort.SliceStable(rows, func(i, j int) bool {
		if !rows[i].Timestamp.Equal(rows[j].Timestamp) {
			return rows[i].Timestamp.After(rows[j].Timestamp)
		}
		if rows[i].Path != rows[j].Path {
			return rows[i].Path < rows[j].Path
		}
		if rows[i].SourceIP != rows[j].SourceIP {
			return rows[i].SourceIP < rows[j].SourceIP
		}
		return rows[i].CPUser < rows[j].CPUser
	})

	if len(rows) > limit {
		resp.Truncated = true
		rows = rows[:limit]
	}
	for _, f := range rows {
		resp.Entries = append(resp.Entries, toRelayAbuseEntry(f))
	}
	return resp
}

func toRelayAbuseEntry(f alert.Finding) relayAbuseEntry {
	e := relayAbuseEntry{
		Path:         f.Path,
		PathLabel:    relayPathLabel(f.Path),
		Severity:     int(f.Severity),
		SourceIP:     f.SourceIP,
		CPUser:       f.CPUser,
		TriggerCount: relayTriggerCount(f),
		DetectedAt:   f.Timestamp,
		Sites:        []relaySiteEntry{},
		MsgSample:    f.MsgIDs,
	}
	for _, h := range f.RelayBreakdown {
		site, script := splitScriptKey(h.ScriptKey)
		e.Sites = append(e.Sites, relaySiteEntry{
			Site:          site,
			Script:        script,
			Hits:          h.Hits,
			LastSeen:      h.LastSeen,
			SampleSubject: h.SampleSubject,
		})
	}
	return e
}

func relayTriggerCount(f alert.Finding) int {
	if f.RelayTotal > 0 {
		return f.RelayTotal
	}
	sum := 0
	for _, h := range f.RelayBreakdown {
		if h.Hits > 0 {
			sum += h.Hits
		}
	}
	if sum > 0 {
		return sum
	}
	return len(f.MsgIDs)
}

// splitScriptKey splits a "host:/path" script key into host and path. The key
// is built as host + ":" + path with path starting at "/", so the delimiter is
// the ":/" boundary. Splitting there (not the first colon) keeps host:port and
// IPv6-literal hosts intact. A key without ":/" yields ("", key) so the row
// still renders.
func splitScriptKey(k string) (site, script string) {
	if i := strings.Index(k, ":/"); i >= 0 {
		return k[:i], k[i+1:]
	}
	return "", k
}
