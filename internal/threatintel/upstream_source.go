package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// UpstreamConfig configures the HTTP threat-intel client. TokenEnv (if
// set) is consulted at every Score call so operators can rotate via env
// without restarting the daemon (P3+P4 lesson).
type UpstreamConfig struct {
	URL      string
	Token    string
	TokenEnv string
	CacheTTL time.Duration
	Timeout  time.Duration
}

// UpstreamSource queries a panel-side TI cache. The wire contract is
// documented in docs/upstream-threat-intel-contract.md (added in T4).
//
//	GET <URL>/lookup?ip=<ip>
//	Authorization: Bearer <token>     (omitted if no token resolved)
//
//	200 OK
//	{"ip":"1.2.3.4","score":75,"source":"upstream","ttl_sec":900}
//
// Errors of any flavour (network, 4xx, 5xx, malformed JSON) propagate
// up - the aggregator treats them as "no signal" rather than fatal.
type UpstreamSource struct {
	cfg    UpstreamConfig
	client *http.Client

	mu    sync.RWMutex
	cache map[string]upstreamEntry
}

type upstreamEntry struct {
	score   int
	expires time.Time
}

// upstreamResponse mirrors the documented panel response shape.
type upstreamResponse struct {
	IP     string `json:"ip"`
	Score  int    `json:"score"`
	Source string `json:"source,omitempty"`
	TTLSec int    `json:"ttl_sec,omitempty"`
}

func NewUpstreamSource(cfg UpstreamConfig) *UpstreamSource {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 15 * time.Minute
	}
	return &UpstreamSource{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
		cache:  make(map[string]upstreamEntry),
	}
}

func (u *UpstreamSource) Name() string { return "upstream" }

// resolveToken reads TokenEnv (if set) at query time, falling back to the
// static token. P3+P4 pattern: lets operators rotate via env without
// restarting the daemon.
func (u *UpstreamSource) resolveToken() string {
	if u.cfg.TokenEnv != "" {
		if v := os.Getenv(u.cfg.TokenEnv); v != "" {
			return v
		}
	}
	return u.cfg.Token
}

func (u *UpstreamSource) Score(ctx context.Context, ip string) (int, error) {
	if v, ok := u.cacheGet(ip); ok {
		return v, nil
	}

	endpoint, err := url.Parse(u.cfg.URL)
	if err != nil {
		return 0, fmt.Errorf("parsing upstream URL: %w", err)
	}
	endpoint.Path += "/lookup"
	q := endpoint.Query()
	q.Set("ip", ip)
	endpoint.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return 0, err
	}
	if tok := u.resolveToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := u.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("upstream request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("upstream HTTP %d", resp.StatusCode)
	}
	var body upstreamResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, fmt.Errorf("upstream decode: %w", err)
	}

	ttl := u.cfg.CacheTTL
	if body.TTLSec > 0 {
		ttl = time.Duration(body.TTLSec) * time.Second
	}
	u.cachePut(ip, body.Score, ttl)
	return body.Score, nil
}

func (u *UpstreamSource) cacheGet(ip string) (int, bool) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	e, ok := u.cache[ip]
	if !ok || time.Now().After(e.expires) {
		return 0, false
	}
	return e.score, true
}

func (u *UpstreamSource) cachePut(ip string, score int, ttl time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.cache[ip] = upstreamEntry{score: score, expires: time.Now().Add(ttl)}
}
