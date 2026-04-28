package challenge

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// IPUnblocker is the interface for temporarily allowing an IP.
type IPUnblocker interface {
	TempAllowIP(ip string, reason string, timeout time.Duration) error
}

// Server serves challenge pages to gray-listed IPs.
// When an IP passes the challenge, it gets a temporary allow.
type Server struct {
	cfg            *config.Config
	secret         []byte
	unblocker      IPUnblocker
	ipList         *IPList
	srv            *http.Server
	trustedProxies map[string]bool

	// Track recently verified IPs to prevent replay
	verified   map[string]time.Time
	verifiedMu sync.Mutex

	// Optional subsystems wired in by configuration. Any of these may
	// be nil; the handlers branch accordingly so a fresh deployment
	// without the new blocks behaves exactly as before.
	captcha       CaptchaProvider
	sessionSigner *AdminSessionSigner
	crawlers      *CrawlerVerifier

	// adminFailures tracks failed admin-token submissions per source
	// IP for rate-limiting brute-force probes. Sliding window: an IP
	// that hits adminMaxFailuresInWindow within adminFailureWindow
	// gets locked out (subsequent submissions return 429) until the
	// oldest failure ages out.
	adminFailures   map[string][]time.Time
	adminFailuresMu sync.Mutex
}

const (
	adminFailureWindow       = 5 * time.Minute
	adminMaxFailuresInWindow = 5
)

// New creates a challenge server.
func New(cfg *config.Config, unblocker IPUnblocker, ipList *IPList) *Server {
	secret := []byte(cfg.Challenge.Secret)
	if len(secret) == 0 {
		secret = make([]byte, 32)
		_, _ = rand.Read(secret)
	}

	trusted := make(map[string]bool)
	for _, p := range cfg.Challenge.TrustedProxies {
		trusted[strings.TrimSpace(p)] = true
	}

	s := &Server{
		cfg:            cfg,
		secret:         secret,
		unblocker:      unblocker,
		ipList:         ipList,
		trustedProxies: trusted,
		verified:       make(map[string]time.Time),
		adminFailures:  make(map[string][]time.Time),
	}

	// Optional sub-features. Each is opt-in via its own config block;
	// initialization errors degrade to "feature off" with a stderr
	// message rather than refusing to start the challenge server.
	if name := cfg.Challenge.CaptchaFallback.Provider; name != "" {
		p, err := NewCaptchaProvider(name, cfg.Challenge.CaptchaFallback.SecretKey, cfg.Challenge.CaptchaFallback.Timeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[challenge] captcha disabled: %v\n", err)
		}
		s.captcha = p
	}
	if cfg.Challenge.VerifiedSession.Enabled {
		signer, err := NewAdminSessionSigner(cfg.Challenge.VerifiedSession.TTL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[challenge] verified-session disabled: %v\n", err)
		}
		s.sessionSigner = signer
	}
	if cfg.Challenge.VerifiedCrawlers.Enabled {
		s.crawlers = NewCrawlerVerifier(
			cfg.Challenge.VerifiedCrawlers.Providers,
			cfg.Challenge.VerifiedCrawlers.CacheTTL,
			nil, // net.DefaultResolver
		)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/challenge", s.handleChallenge)
	mux.HandleFunc("/challenge/verify", s.handleVerify)
	mux.HandleFunc("/challenge/captcha-verify", s.handleCaptchaVerify)
	mux.HandleFunc("/challenge/admin-token", s.handleAdminToken)

	s.srv = &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Challenge.ListenPort),
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return s
}

// Start begins serving challenge pages.
func (s *Server) Start() error {
	return s.srv.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown() {
	_ = s.srv.Close()
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	ip := s.extractIP(r)

	// Bypass paths run before the PoW page is generated. Each
	// short-circuits to the same markVerified flow, so a passing
	// visitor never sees the challenge UI even once.
	if s.bypassByAdminCookie(r, ip) {
		s.markVerified(w, r, ip, "admin session", "")
		return
	}
	if s.bypassByVerifiedCrawler(r.Context(), ip) {
		s.markVerified(w, r, ip, "verified crawler", "")
		return
	}

	nonce := generateNonce()
	difficulty := s.cfg.Challenge.Difficulty
	token := s.makeToken(ip, nonce)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	captchaBlock := s.captchaNoscriptHTML(token, nonce)

	// #nosec G705 -- All interpolated values are constrained to non-HTML
	// character sets: ip is validated via net.ParseIP / net.SplitHostPort
	// in extractIP (never attacker-controlled string); nonce and token
	// are hex.EncodeToString output (0-9, a-f only); difficulty is an int.
	// captchaBlock is constructed from configured site keys (operator
	// supplied) plus hex token/nonce; it never includes attacker input.
	fmt.Fprintf(w, challengePageHTML, ip, captchaBlock, nonce, token, difficulty, difficulty)
}

// bypassByAdminCookie returns true when the visitor presents a valid
// signed-session cookie issued by THIS daemon for THIS IP. Daemon
// restart rotates the signing key, so old cookies fall back to the
// normal PoW flow automatically.
func (s *Server) bypassByAdminCookie(r *http.Request, ip string) bool {
	if s.sessionSigner == nil {
		return false
	}
	cookieName := s.cfg.Challenge.VerifiedSession.CookieName
	if cookieName == "" {
		cookieName = "csm_admin_session"
	}
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return false
	}
	return s.sessionSigner.Verify(c.Value, ip) == nil
}

// bypassByVerifiedCrawler resolves the visitor's reverse DNS and
// confirms the forward lookup -- skipping the PoW only for traffic
// from the configured crawler families. A spoofed UA from a residential
// IP fails forward-confirm and falls through to PoW.
func (s *Server) bypassByVerifiedCrawler(ctx context.Context, ip string) bool {
	if s.crawlers == nil {
		return false
	}
	return s.crawlers.Verified(ctx, ip)
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := s.extractIP(r)
	nonce := r.FormValue("nonce")
	token := r.FormValue("token")
	solution := r.FormValue("solution")

	// Verify HMAC token
	expected := s.makeToken(ip, nonce)
	if token != expected {
		http.Error(w, "Invalid token", http.StatusForbidden)
		return
	}

	// Verify proof-of-work solution
	if !verifyPoW(nonce, solution, s.cfg.Challenge.Difficulty) {
		http.Error(w, "Invalid solution", http.StatusForbidden)
		return
	}

	// Prevent replay -- one nonce, one verification.
	s.verifiedMu.Lock()
	if _, seen := s.verified[nonce]; seen {
		s.verifiedMu.Unlock()
		http.Error(w, "Token already used", http.StatusForbidden)
		return
	}
	s.verified[nonce] = time.Now()
	s.verifiedMu.Unlock()

	s.markVerified(w, r, ip, "passed challenge", r.FormValue("dest"))
}

// handleCaptchaVerify accepts a provider token, validates it
// server-side, and (on success) puts the visitor through the same
// markVerified flow PoW uses. Available only when the operator has
// configured a CAPTCHA provider.
func (s *Server) handleCaptchaVerify(w http.ResponseWriter, r *http.Request) {
	if s.captcha == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := s.extractIP(r)
	nonce := r.FormValue("nonce")
	token := r.FormValue("token")
	captchaToken := r.FormValue("captcha-token")

	// Same HMAC + replay checks PoW does -- a CAPTCHA bypass without
	// nonce binding would let a single completed CAPTCHA grant cookies
	// to an attacker.
	if expected := s.makeToken(ip, nonce); token != expected {
		http.Error(w, "Invalid token", http.StatusForbidden)
		return
	}
	s.verifiedMu.Lock()
	if _, seen := s.verified[nonce]; seen {
		s.verifiedMu.Unlock()
		http.Error(w, "Token already used", http.StatusForbidden)
		return
	}
	s.verified[nonce] = time.Now()
	s.verifiedMu.Unlock()

	ok, err := s.captcha.Verify(r.Context(), captchaToken, ip)
	if err != nil || !ok {
		http.Error(w, "CAPTCHA verification failed", http.StatusForbidden)
		return
	}

	s.markVerified(w, r, ip, "passed captcha", r.FormValue("dest"))
}

// handleAdminToken issues a signed-session cookie when the operator
// presents the configured admin_secret. Returns 204 with Set-Cookie on
// success, 403 on bad/missing secret, 429 once an IP has burned
// through adminMaxFailuresInWindow failures inside adminFailureWindow.
// The 429 is returned BEFORE the constant-time compare so an attacker
// cannot keep probing once they are throttled.
func (s *Server) handleAdminToken(w http.ResponseWriter, r *http.Request) {
	if s.sessionSigner == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := s.extractIP(r)

	if s.adminRateLimited(ip) {
		http.Error(w, "Too many failed attempts; try again later.", http.StatusTooManyRequests)
		return
	}

	presented := r.FormValue("secret")
	if !CompareAdminSecret(s.cfg.Challenge.VerifiedSession.AdminSecret, presented) {
		s.recordAdminFailure(ip)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	// Successful auth clears the failure log so a legitimate operator
	// who fat-fingered the secret a few times can keep using the
	// endpoint after they get it right.
	s.clearAdminFailures(ip)

	cookieName := s.cfg.Challenge.VerifiedSession.CookieName
	if cookieName == "" {
		cookieName = "csm_admin_session"
	}
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    s.sessionSigner.Issue(ip),
		Path:     "/",
		MaxAge:   int(s.sessionSigner.TTL().Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusNoContent)
}

// adminRateLimited returns true when ip has at least
// adminMaxFailuresInWindow failures in the last adminFailureWindow.
// Also opportunistically prunes aged-out entries so the per-IP slice
// stays bounded.
func (s *Server) adminRateLimited(ip string) bool {
	cutoff := time.Now().Add(-adminFailureWindow)
	s.adminFailuresMu.Lock()
	defer s.adminFailuresMu.Unlock()
	pruned := s.adminFailures[ip][:0]
	for _, t := range s.adminFailures[ip] {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	s.adminFailures[ip] = pruned
	return len(pruned) >= adminMaxFailuresInWindow
}

func (s *Server) recordAdminFailure(ip string) {
	s.adminFailuresMu.Lock()
	defer s.adminFailuresMu.Unlock()
	s.adminFailures[ip] = append(s.adminFailures[ip], time.Now())
}

func (s *Server) clearAdminFailures(ip string) {
	s.adminFailuresMu.Lock()
	defer s.adminFailuresMu.Unlock()
	delete(s.adminFailures, ip)
}

// markVerified is the shared post-success path used by handleVerify,
// handleCaptchaVerify, and the bypass shortcuts in handleChallenge.
// Centralising the side effects (firewall tempallow, ipList removal,
// verification cookie, redirect render) keeps all four paths in sync;
// the alternative -- copy-pasting four times -- is the easiest way to
// drift the behaviour of one path away from the others over time.
func (s *Server) markVerified(w http.ResponseWriter, r *http.Request, ip, reason, destOverride string) {
	allowDuration := 4 * time.Hour
	if s.unblocker != nil {
		if err := s.unblocker.TempAllowIP(ip, reason, allowDuration); err != nil {
			fmt.Fprintf(os.Stderr, "[challenge] failed to allow %s: %v\n", ip, err)
		}
	}
	if s.ipList != nil {
		s.ipList.Remove(ip)
	}

	// Set verification cookie. Secure is always on: CSM is designed to
	// run behind HTTPS and the cookie grants a multi-hour bypass of
	// the PoW gate, so leaking it over plaintext is never acceptable.
	cookie := &http.Cookie{
		Name:     "csm_verified",
		Value:    s.makeVerifyCookie(ip),
		Path:     "/",
		MaxAge:   int(allowDuration.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)

	dest := sanitizeRedirectDest(destOverride, r.Host)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta http-equiv="refresh" content="2;url=%s">
<style>body{font-family:system-ui;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#1a2234;color:#c8d3e0}
.ok{text-align:center}.ok h1{color:#2fb344;font-size:3em}p{font-size:1.2em}</style>
</head><body><div class="ok"><h1>&#10003;</h1><p>Verified - redirecting...</p></div></body></html>`, html.EscapeString(dest))
}

// captchaNoscriptHTML renders the CAPTCHA fallback widget. Returns the
// empty string when no provider is configured, in which case the
// challenge page's <noscript> block falls back to the existing
// "JavaScript is required" message.
//
// token and nonce are guaranteed hex by upstream constructors; siteKey
// is operator-supplied so we escape it to keep a typo from breaking
// the page (an attacker would need write access to csm.yaml to inject
// HTML here, which is already game-over, but defence-in-depth is
// cheap).
func (s *Server) captchaNoscriptHTML(token, nonce string) string {
	if s.captcha == nil {
		return ""
	}
	siteKey := html.EscapeString(s.cfg.Challenge.CaptchaFallback.SiteKey)
	switch s.captcha.Name() {
	case "turnstile":
		return fmt.Sprintf(`<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<form method="POST" action="/challenge/captcha-verify">
<input type="hidden" name="token" value="%s">
<input type="hidden" name="nonce" value="%s">
<div class="cf-turnstile" data-sitekey="%s" data-callback="csmCaptchaCallback"></div>
<input type="hidden" name="captcha-token" id="captchaToken">
</form>
<script>function csmCaptchaCallback(t){document.getElementById('captchaToken').value=t;document.forms[0].submit();}</script>`,
			token, nonce, siteKey)
	case "hcaptcha":
		return fmt.Sprintf(`<script src="https://js.hcaptcha.com/1/api.js" async defer></script>
<form method="POST" action="/challenge/captcha-verify">
<input type="hidden" name="token" value="%s">
<input type="hidden" name="nonce" value="%s">
<div class="h-captcha" data-sitekey="%s" data-callback="csmCaptchaCallback"></div>
<input type="hidden" name="captcha-token" id="captchaToken">
</form>
<script>function csmCaptchaCallback(t){document.getElementById('captchaToken').value=t;document.forms[0].submit();}</script>`,
			token, nonce, siteKey)
	default:
		return ""
	}
}

func (s *Server) makeToken(ip, nonce string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(ip + ":" + nonce))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) makeVerifyCookie(ip string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte("cookie:" + ip + ":" + time.Now().Truncate(time.Hour).Format(time.RFC3339)))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

// CleanExpired removes old verification records, prunes the
// admin-failure log, and evicts stale crawler-cache entries. Called
// from the daemon's challengeEscalator ticker every 60 seconds; under
// a sustained scan from many source IPs, this is the only thing
// keeping per-IP map entries from accumulating until restart.
func (s *Server) CleanExpired() {
	now := time.Now()

	s.verifiedMu.Lock()
	verifiedCutoff := now.Add(-4 * time.Hour)
	for k, t := range s.verified {
		if t.Before(verifiedCutoff) {
			delete(s.verified, k)
		}
	}
	s.verifiedMu.Unlock()

	// Drop admin-failure entries whose latest failure has aged out of
	// the rate-limit window. An IP that hammered the endpoint once
	// and stopped will otherwise sit in the map forever.
	s.adminFailuresMu.Lock()
	failureCutoff := now.Add(-adminFailureWindow)
	for ip, times := range s.adminFailures {
		kept := times[:0]
		for _, t := range times {
			if t.After(failureCutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(s.adminFailures, ip)
		} else {
			s.adminFailures[ip] = kept
		}
	}
	s.adminFailuresMu.Unlock()

	if s.crawlers != nil {
		s.crawlers.cleanExpired(now)
	}
}

// extractIP returns the client IP from the request. X-Forwarded-For is only
// trusted when the direct peer is in the configured trusted_proxies list.
// Uses the rightmost XFF entry (the one appended by the trusted proxy),
// not the leftmost (which the client controls). Without trusted proxies,
// RemoteAddr is always used — this prevents attackers from spoofing their IP
// to mint firewall allow rules for arbitrary addresses.
func (s *Server) extractIP(r *http.Request) string {
	peerIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if len(s.trustedProxies) > 0 && s.trustedProxies[peerIP] {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			// Use rightmost entry — the one the trusted proxy appended
			for i := len(parts) - 1; i >= 0; i-- {
				ip := strings.TrimSpace(parts[i])
				if net.ParseIP(ip) != nil {
					return ip
				}
			}
		}
	}
	return peerIP
}

func generateNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// sanitizeRedirectDest validates that a redirect destination is a safe same-origin
// relative path or absolute URL matching the request host. Rejects cross-origin
// redirects, javascript: URIs, backslash-based bypasses, and other open-redirect payloads.
// Returns a reconstructed URL from parsed components to prevent any raw-string injection.
func sanitizeRedirectDest(dest, requestHost string) string {
	if dest == "" {
		return "/"
	}

	// Parse through url.Parse to normalize and detect scheme/host
	parsed, err := url.Parse(dest)
	if err != nil {
		return "/"
	}

	// Scheme whitelist — applies even for opaque URLs with empty Host.
	// Without this, `javascript:alert(1)` produces an opaque URL with
	// Host="" and Scheme="javascript", which would slip past the
	// host-equality check below and end up reconstructed as
	// `"javascript:"`. The only acceptable schemes are the empty
	// string (pure-path relatives) and the two HTTP variants.
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "" && scheme != "http" && scheme != "https" {
		return "/"
	}

	// Reject anything with a host component that doesn't match the request host.
	// This catches protocol-relative (//evil.com), backslash tricks (/\evil.com
	// which some browsers normalize to //evil.com), and explicit cross-origin URLs.
	if parsed.Host != "" {
		destHost := parsed.Hostname()
		reqHost := requestHost
		if h, _, err := net.SplitHostPort(requestHost); err == nil {
			reqHost = h
		}
		if destHost != reqHost {
			return "/"
		}
	}

	// For relative paths: reject anything that doesn't start with a clean /
	if parsed.Host == "" && parsed.Scheme == "" {
		if !strings.HasPrefix(parsed.Path, "/") {
			return "/"
		}
		// Reject backslash in path (browser normalization attack)
		if strings.ContainsRune(parsed.Path, '\\') {
			return "/"
		}
	}

	// Reconstruct from parsed components to prevent raw-string injection
	safe := &url.URL{
		Scheme:   parsed.Scheme,
		Host:     parsed.Host,
		Path:     parsed.Path,
		RawQuery: parsed.RawQuery,
		Fragment: parsed.Fragment,
	}
	return safe.String()
}

// verifyPoW checks that SHA256(nonce + solution) starts with `difficulty` zero nibbles.
func verifyPoW(nonce, solution string, difficulty int) bool {
	h := sha256.Sum256([]byte(nonce + solution))
	hexHash := hex.EncodeToString(h[:])
	for i := 0; i < difficulty; i++ {
		if i >= len(hexHash) || hexHash[i] != '0' {
			return false
		}
	}
	return true
}
