package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const rspamdMaxHistoryBytes = 2 << 20

const (
	// rspamdPriorMass is Laplace-style smoothing added to the history
	// mass so small samples cannot saturate the score: one reject alone
	// scores 33 and it takes two fresh rejects with zero delivered ham
	// to reach the 50 auto-block threshold used by the reputation check.
	rspamdPriorMass = 2.0
	// rspamdDecayHalfLife halves a row's influence per week so the score
	// tracks recent behaviour instead of lifetime accumulation; rspamd's
	// rolling history can span months on quiet servers.
	rspamdDecayHalfLife = 7 * 24 * time.Hour
)

// RspamdSource queries rspamd's rolling history and returns a score
// 0..100 derived only from rows matching the requested IP.
//
// Token resolution happens at Score time (not at construction time) so
// operators can rotate the rspamd controller password via env var
// without restarting the daemon.
type RspamdSource struct {
	url      string
	token    string // static token from config (may be empty)
	tokenEnv string // env var name to consult at query time
	client   *http.Client
}

func NewRspamdSource(url, token, tokenEnv string) *RspamdSource {
	return &RspamdSource{
		url:      url,
		token:    token,
		tokenEnv: tokenEnv,
		client:   &http.Client{Timeout: 5 * time.Second},
	}
}

func (s *RspamdSource) Name() string { return "rspamd" }

// resolveToken reads the env var (if set) at query time, falling back to
// the static token. Lets operators rotate via env without daemon restart.
func (s *RspamdSource) resolveToken() string {
	if s.tokenEnv != "" {
		if v := os.Getenv(s.tokenEnv); v != "" {
			return v
		}
	}
	return s.token
}

type rspamdHistoryResp struct {
	Rows    []rspamdHistoryRow `json:"rows"`
	History []rspamdHistoryRow `json:"history"`
	Data    []rspamdHistoryRow `json:"data"`
}

func (r rspamdHistoryResp) entries() []rspamdHistoryRow {
	out := make([]rspamdHistoryRow, 0, len(r.Rows)+len(r.History)+len(r.Data))
	out = append(out, r.Rows...)
	out = append(out, r.History...)
	out = append(out, r.Data...)
	return out
}

type rspamdHistoryRow struct {
	IP       string
	Action   string
	Score    float64
	UnixTime float64
}

func (r *rspamdHistoryRow) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.IP = firstJSONString(raw, "ip", "sender_ip", "client_ip")
	r.Action = firstJSONString(raw, "action", "metric_action")
	r.Score = firstJSONFloat(raw, "score")
	r.UnixTime = firstJSONFloat(raw, "unix_time")
	return nil
}

func firstJSONString(raw map[string]json.RawMessage, names ...string) string {
	for _, name := range names {
		v, ok := raw[name]
		if !ok {
			continue
		}
		var s string
		if err := json.Unmarshal(v, &s); err == nil {
			return s
		}
	}
	return ""
}

func firstJSONFloat(raw map[string]json.RawMessage, names ...string) float64 {
	for _, name := range names {
		v, ok := raw[name]
		if !ok {
			continue
		}
		var f float64
		if err := json.Unmarshal(v, &f); err == nil {
			return f
		}
	}
	return 0
}

// Score sends a GET to <url>/history and scores only history rows for ip.
func (s *RspamdSource) Score(ctx context.Context, ip string) (int, error) {
	endpoint, err := s.historyEndpoint()
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	if tok := s.resolveToken(); tok != "" {
		req.Header.Set("Password", tok)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("rspamd: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("rspamd HTTP %d", resp.StatusCode)
	}
	rows, err := decodeRspamdHistory(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("rspamd decode: %w", err)
	}
	return scoreRspamdHistory(rows, ip, time.Now()), nil
}

func (s *RspamdSource) historyEndpoint() (string, error) {
	u, err := url.Parse(s.url)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("rspamd URL must include scheme and host")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/history"
	u.RawQuery = ""
	return u.String(), nil
}

func decodeRspamdHistory(r io.Reader) ([]rspamdHistoryRow, error) {
	var raw json.RawMessage
	if err := json.NewDecoder(io.LimitReader(r, rspamdMaxHistoryBytes)).Decode(&raw); err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "[") {
		var rows []rspamdHistoryRow
		if err := json.Unmarshal(raw, &rows); err != nil {
			return nil, err
		}
		return rows, nil
	}
	var history rspamdHistoryResp
	if err := json.Unmarshal(raw, &history); err != nil {
		return nil, err
	}
	return history.entries(), nil
}

// scoreRspamdHistory converts an IP's history rows into a 0..100
// confidence that the IP is a spam source. The score is the recency-
// weighted proportion of definitive spam verdicts among classifiable
// delivered/spam verdicts, smoothed by rspamdPriorMass. Delivered ham
// therefore dilutes the score toward 0 instead of accumulating it: a
// correspondent MTA that sends mostly legitimate mail stays near 0 no
// matter how much it sends, while an IP whose recent traffic is
// predominantly rejected climbs toward 100.
func scoreRspamdHistory(rows []rspamdHistoryRow, ip string, now time.Time) int {
	want := normalizeIP(ip)
	var spamMass, totalMass float64
	for _, row := range rows {
		if normalizeIP(row.IP) != want {
			continue
		}
		spamWeight, counts := rspamdActionSignal(row.Action)
		if !counts {
			continue
		}
		recency := rspamdRecencyFactor(row.UnixTime, now)
		spamMass += spamWeight * recency
		totalMass += recency
	}
	if spamMass == 0 || totalMass == 0 {
		return 0
	}
	return int(math.Round(100 * spamMass / (totalMass + rspamdPriorMass)))
}

// rspamdActionSignal maps an rspamd action onto per-message spam mass
// in [0,1] and reports whether the row is classifiable as ham or spam.
// "no action" is delivered ham; greylist and soft reject are tempfail
// flow control that fires on first contact from every unknown sender
// and on rate limits, so they are neutral instead of ham. Genuinely
// spammy retries earn reject, quarantine, discard, add-header, or
// rewrite-subject rows, which do count. The numeric rspamd score is
// ignored on purpose: the action already is rspamd's calibrated
// thresholding of that score.
func rspamdActionSignal(action string) (float64, bool) {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "reject", "discard", "quarantine", "spam":
		return 1.0, true
	case "add header", "rewrite subject", "probable spam":
		return 0.7, true
	case "no action", "clean":
		return 0, true
	default:
		return 0, false
	}
}

// rspamdRecencyFactor halves a row's weight per rspamdDecayHalfLife.
// Rows without a parseable unix_time count at full weight rather than
// being dropped: rspamd's rolling history is bounded, so undated rows
// are treated as current.
func rspamdRecencyFactor(unixTime float64, now time.Time) float64 {
	if unixTime <= 0 {
		return 1
	}
	age := now.Sub(time.Unix(int64(unixTime), 0))
	if age <= 0 {
		return 1
	}
	return math.Exp2(-age.Hours() / rspamdDecayHalfLife.Hours())
}

func normalizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	return parsed.String()
}
