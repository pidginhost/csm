package challenge

import (
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
}

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
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/challenge", s.handleChallenge)
	mux.HandleFunc("/challenge/verify", s.handleVerify)

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
	nonce := generateNonce()
	difficulty := s.cfg.Challenge.Difficulty

	// Generate HMAC token binding nonce to IP
	token := s.makeToken(ip, nonce)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	fmt.Fprintf(w, challengePageHTML, ip, nonce, token, difficulty, difficulty)
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

	// Prevent replay
	s.verifiedMu.Lock()
	if _, seen := s.verified[nonce]; seen {
		s.verifiedMu.Unlock()
		http.Error(w, "Token already used", http.StatusForbidden)
		return
	}
	s.verified[nonce] = time.Now()
	s.verifiedMu.Unlock()

	// Allow the IP temporarily (4 hours)
	allowDuration := 4 * time.Hour
	if s.unblocker != nil {
		if err := s.unblocker.TempAllowIP(ip, "passed challenge", allowDuration); err != nil {
			fmt.Fprintf(os.Stderr, "[challenge] failed to allow %s: %v\n", ip, err)
		}
	}

	// Remove from challenge list so Apache stops redirecting
	if s.ipList != nil {
		s.ipList.Remove(ip)
	}

	// Set verification cookie. Secure is always on: CSM is designed to run
	// behind HTTPS and the cookie grants a multi-hour bypass of the PoW
	// gate, so leaking it over plaintext is never acceptable.
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

	// Redirect to original destination (sanitized to prevent open redirect / XSS)
	dest := sanitizeRedirectDest(r.FormValue("dest"), r.Host)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta http-equiv="refresh" content="2;url=%s">
<style>body{font-family:system-ui;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#1a2234;color:#c8d3e0}
.ok{text-align:center}.ok h1{color:#2fb344;font-size:3em}p{font-size:1.2em}</style>
</head><body><div class="ok"><h1>&#10003;</h1><p>Verified - redirecting...</p></div></body></html>`, html.EscapeString(dest))
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

// CleanExpired removes old verification records.
func (s *Server) CleanExpired() {
	s.verifiedMu.Lock()
	defer s.verifiedMu.Unlock()
	cutoff := time.Now().Add(-4 * time.Hour)
	for k, t := range s.verified {
		if t.Before(cutoff) {
			delete(s.verified, k)
		}
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
