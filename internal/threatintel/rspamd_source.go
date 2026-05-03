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
	IP     string
	Action string
	Score  float64
}

func (r *rspamdHistoryRow) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.IP = firstJSONString(raw, "ip", "sender_ip", "client_ip")
	r.Action = firstJSONString(raw, "action", "metric_action")
	r.Score = firstJSONFloat(raw, "score")
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
	return scoreRspamdHistory(rows, ip), nil
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

func scoreRspamdHistory(rows []rspamdHistoryRow, ip string) int {
	want := normalizeIP(ip)
	score := 0
	for _, row := range rows {
		if normalizeIP(row.IP) != want {
			continue
		}
		score += rspamdActionScore(row.Action)
		if row.Score > 0 {
			score += int(math.Ceil(row.Score * 4))
		}
		if score >= 100 {
			return 100
		}
	}
	return score
}

func rspamdActionScore(action string) int {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "reject":
		return 50
	case "soft reject":
		return 35
	case "greylist", "add header", "rewrite subject":
		return 20
	default:
		return 0
	}
}

func normalizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	return parsed.String()
}
