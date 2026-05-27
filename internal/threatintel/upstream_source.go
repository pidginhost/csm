package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	upstreamMaxResponseBytes = 1 << 20

	// defaultMaxCacheEntries caps the per-IP score cache so a sustained
	// flood of unique attacker IPs cannot grow the map without bound.
	// Once the cap is reached, expired entries are pruned first; if the
	// cap is still exceeded the oldest entry (by expires) is evicted.
	defaultMaxCacheEntries = 10000

	// defaultBreakerTrip is the number of consecutive upstream failures
	// after which the source short-circuits subsequent Score calls.
	defaultBreakerTrip = 5

	// defaultBreakerCooldown is how long the breaker stays open before
	// allowing a probe call through.
	defaultBreakerCooldown = 60 * time.Second
)

// UpstreamConfig configures the HTTP threat-intel client. TokenEnv (if
// set) is consulted at every Score call so operators can rotate via env
// without restarting the daemon.
type UpstreamConfig struct {
	URL      string
	Token    string
	TokenEnv string
	CacheTTL time.Duration
	Timeout  time.Duration
}

// UpstreamSource queries a panel-side TI cache. The wire contract is
// documented in docs/upstream-threat-intel-contract.md.
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

	// maxCacheEntries caps the in-memory score cache. Exposed for tests
	// that want to validate eviction without staging 10k entries.
	maxCacheEntries int

	// breakerMu guards the circuit-breaker state below.
	breakerMu         sync.Mutex
	consecutiveErrors int
	breakerOpenedAt   time.Time
	breakerTrip       int
	breakerCooldown   time.Duration
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
		cfg:             cfg,
		client:          &http.Client{Timeout: cfg.Timeout},
		cache:           make(map[string]upstreamEntry),
		maxCacheEntries: defaultMaxCacheEntries,
		breakerTrip:     defaultBreakerTrip,
		breakerCooldown: defaultBreakerCooldown,
	}
}

func (u *UpstreamSource) Name() string { return "upstream" }

// resolveToken reads TokenEnv (if set) at query time, falling back to the
// static token. Lets operators rotate via env without daemon restart.
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
	if open, until := u.breakerOpen(); open {
		return 0, fmt.Errorf("upstream breaker open for %s", time.Until(until).Round(time.Second))
	}

	endpoint, err := u.lookupEndpoint(ip)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	if tok := u.resolveToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := u.client.Do(req)
	if err != nil {
		u.breakerObserve(false)
		return 0, fmt.Errorf("upstream request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		u.breakerObserve(false)
		fmt.Fprintf(os.Stderr, "upstream threat-intel: HTTP %d for %s\n", resp.StatusCode, ip)
		return 0, fmt.Errorf("upstream HTTP %d", resp.StatusCode)
	}
	var body upstreamResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, upstreamMaxResponseBytes)).Decode(&body); err != nil {
		u.breakerObserve(false)
		return 0, fmt.Errorf("upstream decode: %w", err)
	}
	if normalizeIP(body.IP) != normalizeIP(ip) {
		u.breakerObserve(false)
		return 0, fmt.Errorf("upstream response ip mismatch: got %q want %q", body.IP, ip)
	}
	if body.Score < 0 || body.Score > 100 {
		u.breakerObserve(false)
		return 0, fmt.Errorf("upstream score out of range: %d", body.Score)
	}

	u.breakerObserve(true)
	ttl := u.cfg.CacheTTL
	if body.TTLSec > 0 {
		ttl = time.Duration(body.TTLSec) * time.Second
	}
	u.cachePut(ip, body.Score, ttl)
	return body.Score, nil
}

// breakerOpen reports whether the circuit breaker is currently open.
// When open and the cooldown has elapsed, the breaker transitions to a
// half-open state by clearing the timestamp so one probe call may pass.
func (u *UpstreamSource) breakerOpen() (bool, time.Time) {
	u.breakerMu.Lock()
	defer u.breakerMu.Unlock()
	if u.breakerOpenedAt.IsZero() {
		return false, time.Time{}
	}
	if time.Since(u.breakerOpenedAt) >= u.breakerCooldown {
		u.breakerOpenedAt = time.Time{}
		return false, time.Time{}
	}
	return true, u.breakerOpenedAt.Add(u.breakerCooldown)
}

// breakerObserve records the outcome of an upstream call so the
// breaker can trip after enough consecutive failures or reset on a
// successful response.
func (u *UpstreamSource) breakerObserve(success bool) {
	u.breakerMu.Lock()
	defer u.breakerMu.Unlock()
	if success {
		u.consecutiveErrors = 0
		u.breakerOpenedAt = time.Time{}
		return
	}
	u.consecutiveErrors++
	if u.breakerTrip > 0 && u.consecutiveErrors >= u.breakerTrip {
		u.breakerOpenedAt = time.Now()
	}
}

func (u *UpstreamSource) lookupEndpoint(ip string) (string, error) {
	endpoint, err := url.Parse(u.cfg.URL)
	if err != nil {
		return "", fmt.Errorf("parsing upstream URL: %w", err)
	}
	if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return "", fmt.Errorf("upstream URL must use http or https")
	}
	if endpoint.Host == "" {
		return "", fmt.Errorf("upstream URL must include host")
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/lookup"
	endpoint.Fragment = ""
	q := endpoint.Query()
	q.Set("ip", normalizeIP(ip))
	endpoint.RawQuery = q.Encode()
	return endpoint.String(), nil
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
	u.evictLocked()
}

// evictLocked drops expired entries first, then evicts the oldest
// (smallest expires) until size is within maxCacheEntries. Caller
// must hold u.mu.
func (u *UpstreamSource) evictLocked() {
	if u.maxCacheEntries <= 0 || len(u.cache) <= u.maxCacheEntries {
		return
	}
	now := time.Now()
	for k, e := range u.cache {
		if now.After(e.expires) {
			delete(u.cache, k)
		}
	}
	for len(u.cache) > u.maxCacheEntries {
		var oldestKey string
		var oldestAt time.Time
		first := true
		for k, e := range u.cache {
			if first || e.expires.Before(oldestAt) {
				oldestKey = k
				oldestAt = e.expires
				first = false
			}
		}
		delete(u.cache, oldestKey)
	}
}

// cacheLen is exposed for tests to inspect cache size without exposing
// the underlying map.
func (u *UpstreamSource) cacheLen() int {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return len(u.cache)
}
