package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
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
	cfg       *config.Config
	secret    []byte
	unblocker IPUnblocker
	ipList    *IPList
	srv       *http.Server

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

	s := &Server{
		cfg:       cfg,
		secret:    secret,
		unblocker: unblocker,
		ipList:    ipList,
		verified:  make(map[string]time.Time),
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
	ip := extractIP(r)
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

	ip := extractIP(r)
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

	// Set verification cookie
	cookie := &http.Cookie{
		Name:     "csm_verified",
		Value:    s.makeVerifyCookie(ip),
		Path:     "/",
		MaxAge:   int(allowDuration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)

	// Redirect to original destination
	dest := r.FormValue("dest")
	if dest == "" {
		dest = "/"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta http-equiv="refresh" content="2;url=%s">
<style>body{font-family:system-ui;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#1a2234;color:#c8d3e0}
.ok{text-align:center}.ok h1{color:#2fb344;font-size:3em}p{font-size:1.2em}</style>
</head><body><div class="ok"><h1>&#10003;</h1><p>Verified - redirecting...</p></div></body></html>`, dest)
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

func extractIP(r *http.Request) string {
	// Check X-Forwarded-For (from Apache ErrorDocument proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

func generateNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
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
