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
	Offset    int               `json:"offset"`
	Limit     int               `json:"limit"`
	From      time.Time         `json:"from"`
	To        time.Time         `json:"to"`
	Truncated bool              `json:"truncated"`
	// byAccount counts the events of the range that name an account, by
	// account and kind, before limit cuts the list.
	byAccount map[string]map[string]int
}

type relayAbuseEntry struct {
	Path         string           `json:"path"`
	PathLabel    string           `json:"path_label"`
	Severity     string           `json:"severity"`
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

// relayAbuseMemo names the history walk the relay-abuse list and the senders
// abuse count share. The limit only cuts the answer, so it is not part of the
// key.
const relayAbuseMemo = "relay-abuse"

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

	from, to, ok := emailRange(w, q, time.Now())
	if !ok {
		return
	}

	writeJSON(w, s.buildRelayAbuseResponse(from, to, limit))
}

func (s *Server) buildRelayAbuseResponse(from, to time.Time, limit int) relayAbuseResponse {
	resp := relayAbuseResponse{
		Entries:   []relayAbuseEntry{},
		Limit:     limit,
		From:      from.UTC(),
		To:        to.UTC(),
		byAccount: map[string]map[string]int{},
	}
	if s.store == nil {
		return resp
	}

	key := rangeMemoKey(relayAbuseMemo, from, to)
	snapshot := s.emailMemo(key, func() any {
		return s.relayAbuseHistory(from.Truncate(time.Minute), to.Truncate(time.Minute).Add(time.Minute))
	}).([]relayAbuseEntry)
	if len(snapshot) > emailGroupsScanCap {
		// A partial minute-wide snapshot may omit matches behind newer
		// findings outside the exact range. Apply its bounds during the
		// history walk instead, before spending the match budget.
		exactKey := key + "&exact-from=" + from.UTC().Format(time.RFC3339Nano) + "&exact-to=" + to.UTC().Format(time.RFC3339Nano)
		snapshot = s.emailMemo(exactKey, func() any {
			return s.relayAbuseHistory(from, to)
		}).([]relayAbuseEntry)
	}

	// Memoized rows are shared by concurrent requests. Filter into a new
	// slice before sorting, retaining each request's precise range.
	rows := make([]relayAbuseEntry, 0, len(snapshot))
	for _, row := range snapshot {
		if !row.DetectedAt.Before(from) && row.DetectedAt.Before(to) {
			rows = append(rows, row)
		}
	}
	if len(rows) > emailGroupsScanCap {
		rows = rows[:emailGroupsScanCap]
		resp.Truncated = true
	}
	resp.Total = len(rows)
	for _, row := range rows {
		if row.CPUser == "" {
			continue
		}
		kinds := resp.byAccount[row.CPUser]
		if kinds == nil {
			kinds = map[string]int{}
			resp.byAccount[row.CPUser] = kinds
		}
		kinds[row.PathLabel]++
	}

	sort.SliceStable(rows, func(i, j int) bool {
		if !rows[i].DetectedAt.Equal(rows[j].DetectedAt) {
			return rows[i].DetectedAt.After(rows[j].DetectedAt)
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
	resp.Entries = rows
	return resp
}

func (s *Server) relayAbuseHistory(from, to time.Time) []relayAbuseEntry {
	findings := s.store.SearchHistorySince(from, emailGroupsScanCap+1, func(f alert.Finding) bool {
		return f.Check == "email_php_relay_abuse" && f.Timestamp.Before(to)
	})
	rows := make([]relayAbuseEntry, 0, len(findings))
	for _, finding := range findings {
		rows = append(rows, toRelayAbuseEntry(finding))
	}
	return rows
}

func toRelayAbuseEntry(f alert.Finding) relayAbuseEntry {
	e := relayAbuseEntry{
		Path:         f.Path,
		PathLabel:    relayPathLabel(f.Path),
		Severity:     f.Severity.String(),
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
