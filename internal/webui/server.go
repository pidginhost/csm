package webui

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

// IPBlocker abstracts the firewall engine for block/unblock operations.
type IPBlocker interface {
	BlockIP(ip string, reason string, timeout time.Duration) error
	UnblockIP(ip string) error
}

// Server is the web UI HTTP server. Serves API always; serves HTML pages
// and static files only if the UI directory exists on disk.
type Server struct {
	cfg             *config.Config
	store           *state.Store
	hub             *Hub
	httpSrv         *http.Server
	templates       map[string]*template.Template
	hasUI           bool   // true if UI directory with templates exists
	uiDir           string // path to UI directory on disk
	startTime       time.Time
	sigCount        int // loaded signature rule count
	fanotifyActive  bool
	logWatcherCount int
	blocker         IPBlocker

	// Rate limiting
	loginMu       sync.Mutex
	loginAttempts map[string][]time.Time
	scanMu        sync.Mutex
	scanRunning   bool // only one scan at a time
}

// New creates a new web UI server.
func New(cfg *config.Config, store *state.Store) (*Server, error) {
	s := &Server{
		cfg:           cfg,
		store:         store,
		hub:           NewHub(),
		startTime:     time.Now(),
		loginAttempts: make(map[string][]time.Time),
	}

	// Check if UI directory exists on disk
	s.uiDir = cfg.WebUI.UIDir
	if s.uiDir == "" {
		s.uiDir = "/opt/csm/ui"
	}

	funcMap := template.FuncMap{
		"severityClass": severityClass,
		"severityLabel": severityLabel,
		"timeAgo":       timeAgo,
		"formatTime":    formatTime,
		"csrfToken":     s.csrfToken,
		"multiply":      func(a, b int) int { return a * b },
		"add":           func(a, b int) int { return a + b },
		"subtract":      func(a, b int) int { return a - b },
		"divisibleBy":   func(a, b int) bool { return b != 0 && a%b == 0 },
	}

	// Try to load templates from disk
	templateDir := filepath.Join(s.uiDir, "templates")
	staticDir := filepath.Join(s.uiDir, "static")
	if _, err := os.Stat(templateDir); err == nil {
		s.templates = make(map[string]*template.Template)
		layoutPath := filepath.Join(templateDir, "layout.html")
		for _, page := range []string{"dashboard", "findings", "history", "quarantine", "blocked", "firewall"} {
			pagePath := filepath.Join(templateDir, page+".html")
			t, err := template.New(page+".html").Funcs(funcMap).ParseFiles(layoutPath, pagePath)
			if err != nil {
				return nil, fmt.Errorf("parsing template %s from %s: %w", page, templateDir, err)
			}
			s.templates[page+".html"] = t
		}
		loginPath := filepath.Join(templateDir, "login.html")
		loginTmpl, err := template.New("login.html").Funcs(funcMap).ParseFiles(loginPath)
		if err != nil {
			return nil, fmt.Errorf("parsing login template: %w", err)
		}
		s.templates["login.html"] = loginTmpl
		s.hasUI = true
		fmt.Fprintf(os.Stderr, "WebUI: loaded templates from %s\n", templateDir)
	} else {
		fmt.Fprintf(os.Stderr, "WebUI: UI directory not found at %s — running in API-only mode\n", s.uiDir)
	}

	// Set up routes
	mux := http.NewServeMux()

	// Static files and HTML pages — only if UI directory exists
	if s.hasUI {
		mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))
		mux.HandleFunc("/login", s.handleLogin)
		mux.Handle("/", s.requireAuth(http.HandlerFunc(s.handleDashboard)))
		mux.Handle("/dashboard", s.requireAuth(http.HandlerFunc(s.handleDashboard)))
		mux.Handle("/findings", s.requireAuth(http.HandlerFunc(s.handleFindings)))
		mux.Handle("/history", s.requireAuth(http.HandlerFunc(s.handleHistory)))
		mux.Handle("/quarantine", s.requireAuth(http.HandlerFunc(s.handleQuarantine)))
		mux.Handle("/blocked", s.requireAuth(http.HandlerFunc(s.handleBlocked)))
		mux.Handle("/firewall", s.requireAuth(http.HandlerFunc(s.handleFirewall)))
	}

	// Auth-protected API — read
	mux.Handle("/api/v1/status", s.requireAuth(http.HandlerFunc(s.apiStatus)))
	mux.Handle("/api/v1/findings", s.requireAuth(http.HandlerFunc(s.apiFindings)))
	mux.Handle("/api/v1/history", s.requireAuth(http.HandlerFunc(s.apiHistory)))
	mux.Handle("/api/v1/quarantine", s.requireAuth(http.HandlerFunc(s.apiQuarantine)))
	mux.Handle("/api/v1/stats", s.requireAuth(http.HandlerFunc(s.apiStats)))
	mux.Handle("/api/v1/blocked-ips", s.requireAuth(http.HandlerFunc(s.apiBlockedIPs)))
	mux.Handle("/api/v1/health", s.requireAuth(http.HandlerFunc(s.apiHealth)))
	mux.Handle("/api/v1/accounts", s.requireAuth(http.HandlerFunc(s.apiAccounts)))
	mux.Handle("/api/v1/history/csv", s.requireAuth(http.HandlerFunc(s.apiHistoryCSV)))

	// Firewall API
	mux.Handle("/api/v1/firewall/status", s.requireAuth(http.HandlerFunc(s.apiFirewallStatus)))
	mux.Handle("/api/v1/firewall/audit", s.requireAuth(http.HandlerFunc(s.apiFirewallAudit)))
	mux.Handle("/api/v1/firewall/subnets", s.requireAuth(http.HandlerFunc(s.apiFirewallSubnets)))

	// Auth-protected API — actions (with CSRF validation)
	mux.Handle("/api/v1/fix", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiFix))))
	mux.Handle("/api/v1/fix-bulk", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiBulkFix))))
	mux.Handle("/api/v1/fix-preview", s.requireAuth(http.HandlerFunc(s.apiFixPreview)))
	mux.Handle("/api/v1/scan-account", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiScanAccount))))
	mux.Handle("/api/v1/block-ip", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiBlockIP))))
	mux.Handle("/api/v1/unblock-ip", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiUnblockIP))))
	mux.Handle("/api/v1/dismiss", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiDismissFinding))))
	mux.Handle("/api/v1/quarantine-restore", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiQuarantineRestore))))
	mux.Handle("/api/v1/firewall/deny-subnet", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiFirewallDenySubnet))))
	mux.Handle("/api/v1/firewall/remove-subnet", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiFirewallRemoveSubnet))))
	mux.Handle("/api/v1/firewall/flush", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiFirewallFlush))))

	// Logout (clears cookie)
	mux.HandleFunc("/logout", s.handleLogout)

	// WebSocket (auth via cookie)
	mux.HandleFunc("/ws/findings", s.handleWSFindings)

	s.httpSrv = &http.Server{
		Addr:           cfg.WebUI.Listen,
		Handler:        s.securityHeaders(mux),
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   120 * time.Second, // account scans can take 30-60s
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	return s, nil
}

// Start starts the HTTPS server. Blocks until shutdown.
func (s *Server) Start() error {
	certPath := s.cfg.WebUI.TLSCert
	keyPath := s.cfg.WebUI.TLSKey

	if certPath == "" {
		certPath = filepath.Join(s.cfg.StatePath, "webui.crt")
		keyPath = filepath.Join(s.cfg.StatePath, "webui.key")
	}

	if err := EnsureTLSCert(certPath, keyPath, s.cfg.Hostname); err != nil {
		return fmt.Errorf("TLS cert setup: %w", err)
	}

	fmt.Fprintf(os.Stderr, "WebUI listening on https://%s\n", s.cfg.WebUI.Listen)
	return s.httpSrv.ListenAndServeTLS(certPath, keyPath)
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

// Broadcast sends findings to all WebSocket clients.
func (s *Server) Broadcast(findings []alert.Finding) {
	s.hub.Broadcast(findings)
}

// SetSigCount sets the loaded signature count for the status API.
func (s *Server) SetSigCount(count int) {
	s.sigCount = count
}

// HasUI returns true if UI templates were loaded from disk.
func (s *Server) HasUI() bool {
	return s.hasUI
}

// SetIPBlocker sets the firewall engine for block/unblock operations.
func (s *Server) SetIPBlocker(b IPBlocker) {
	s.blocker = b
}

// SetHealthInfo sets daemon health info for the health API.
func (s *Server) SetHealthInfo(fanotifyActive bool, logWatchers int) {
	s.fanotifyActive = fanotifyActive
	s.logWatcherCount = logWatchers
}

// --- Authentication ---

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.isAuthenticated(r) {
			next.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	})
}

func (s *Server) isAuthenticated(r *http.Request) bool {
	token := s.cfg.WebUI.AuthToken
	if token == "" {
		return false
	}

	// Check Authorization header
	if auth := r.Header.Get("Authorization"); auth != "" {
		if len(auth) > 7 && auth[:7] == "Bearer " {
			if subtle.ConstantTimeCompare([]byte(auth[7:]), []byte(token)) == 1 {
				return true
			}
		}
	}

	// Check cookie
	if cookie, err := r.Cookie("csm_auth"); err == nil {
		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(token)) == 1 {
			return true
		}
	}

	// Check query param (for WebSocket)
	if q := r.URL.Query().Get("token"); q != "" {
		if subtle.ConstantTimeCompare([]byte(q), []byte(token)) == 1 {
			return true
		}
	}

	return false
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		_ = s.templates["login.html"].Execute(w, nil)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limit: 5 attempts per minute per IP (strip port from RemoteAddr)
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	s.loginMu.Lock()
	now := time.Now()
	attempts := s.loginAttempts[ip]
	var recent []time.Time
	for _, t := range attempts {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	if len(recent) >= 5 {
		s.loginMu.Unlock()
		http.Error(w, "Too many login attempts", http.StatusTooManyRequests)
		return
	}
	s.loginAttempts[ip] = append(recent, now)
	s.loginMu.Unlock()

	token := r.FormValue("token")
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.WebUI.AuthToken)) != 1 {
		_ = s.templates["login.html"].Execute(w, map[string]string{"Error": "Invalid token"})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "csm_auth",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400, // 24 hours
	})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (s *Server) handleWSFindings(w http.ResponseWriter, r *http.Request) {
	if !s.isAuthenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	s.hub.HandleWebSocket(w, r)
}

// --- Template helpers ---

func severityClass(sev alert.Severity) string {
	switch sev {
	case alert.Critical:
		return "critical"
	case alert.High:
		return "high"
	case alert.Warning:
		return "warning"
	default:
		return "info"
	}
}

func severityLabel(sev alert.Severity) string {
	switch sev {
	case alert.Critical:
		return "CRITICAL"
	case alert.High:
		return "HIGH"
	case alert.Warning:
		return "WARNING"
	default:
		return "INFO"
	}
}

func timeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func formatTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}

// --- Security headers middleware ---

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		// CSP: allow inline styles (needed for card styling) but block inline scripts
		// except those with the nonce — we use 'unsafe-inline' for now since templates
		// have inline scripts; tighten when scripts are moved to external files
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		next.ServeHTTP(w, r)
	})
}

// --- CSRF protection ---

// csrfToken generates a deterministic CSRF token from the auth token.
// This is safe because the auth token is secret and the CSRF token is
// derived via HMAC — knowing the CSRF token doesn't reveal the auth token.
func (s *Server) csrfToken() string {
	mac := hmac.New(sha256.New, []byte("csm-csrf-v1"))
	mac.Write([]byte(s.cfg.WebUI.AuthToken))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

// validateCSRF checks the CSRF token on POST requests.
// Checks X-CSRF-Token header (for API calls) or csrf_token form field (for form posts).
func (s *Server) validateCSRF(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return true // only validate POST
	}

	// Skip CSRF for Bearer token auth — the token itself proves identity.
	// CSRF protection is only needed for cookie-based browser sessions.
	if auth := r.Header.Get("Authorization"); auth != "" {
		if len(auth) > 7 && auth[:7] == "Bearer " {
			token := s.cfg.WebUI.AuthToken
			if subtle.ConstantTimeCompare([]byte(auth[7:]), []byte(token)) == 1 {
				return true
			}
		}
	}

	expected := s.csrfToken()

	// Check header (API calls from JS use this)
	if token := r.Header.Get("X-CSRF-Token"); token != "" {
		return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
	}

	// Check form field (traditional form posts)
	if token := r.FormValue("csrf_token"); token != "" {
		return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
	}

	return false
}

// requireCSRF wraps a handler to validate CSRF on POST requests.
func (s *Server) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && !s.validateCSRF(r) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- Logout ---

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "csm_auth",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // delete cookie
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// --- Scan rate limiting ---

// acquireScan tries to start a scan. Returns false if a scan is already running.
func (s *Server) acquireScan() bool {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	if s.scanRunning {
		return false
	}
	s.scanRunning = true
	return true
}

func (s *Server) releaseScan() {
	s.scanMu.Lock()
	s.scanRunning = false
	s.scanMu.Unlock()
}
