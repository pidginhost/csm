package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// RspamdSource queries rspamd's /stat endpoint and returns a score 0..100
// derived from the reject/junk count for the IP. The mapping is
// "min(rejects * 10, 100)" - tunable later if rspamd surfaces a richer
// per-IP breakdown.
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

type rspamdStatResp struct {
	Actions map[string]int `json:"actions"`
}

// Score sends a GET to <url>/stat and reads the rejects count.
// Note: rspamd's actual API for per-IP stats is `/checkv2` with the IP
// in the body; if your rspamd version exposes per-IP counters elsewhere,
// adjust this method without changing the Source contract.
func (s *RspamdSource) Score(ctx context.Context, ip string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url+"/stat", nil)
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
	var stat rspamdStatResp
	if err := json.NewDecoder(resp.Body).Decode(&stat); err != nil {
		return 0, fmt.Errorf("rspamd decode: %w", err)
	}
	rejects := stat.Actions["reject"]
	score := rejects * 10
	if score > 100 {
		score = 100
	}
	return score, nil
}
