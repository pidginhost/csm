package webui

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/emailav"
	"github.com/pidginhost/cpanel-security-monitor/internal/geoip"
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
	cfg                *config.Config
	store              *state.Store
	httpSrv            *http.Server
	templates          map[string]*template.Template
	hasUI              bool   // true if UI directory with templates exists
	uiDir              string // path to UI directory on disk
	startTime          time.Time
	sigCount           int // loaded signature rule count
	fanotifyActive     bool
	logWatcherCount    int
	blocker            IPBlocker
	geoIPDB            atomic.Pointer[geoip.DB]
	emailQuarantine    *emailav.Quarantine
	emailAVWatcherMode string
	perfSnapshot       atomic.Pointer[perfMetrics]
	perfCancel         context.CancelFunc

	// Rate limiting
	loginMu       sync.Mutex
	loginAttempts map[string][]time.Time
	apiMu         sync.Mutex
	apiRequests   map[string][]time.Time // per-IP API rate limiting
	scanMu        sync.Mutex
	scanRunning   bool       // only one scan at a time
	modSecApplyMu sync.Mutex // serializes modsec rules apply (write+reload+rollback)

	// Graceful shutdown signal for background goroutines
	pruneDone chan struct{}
}

// New creates a new web UI server.
func New(cfg *config.Config, store *state.Store) (*Server, error) {
	s := &Server{
		cfg:           cfg,
		store:         store,
		startTime:     time.Now(),
		loginAttempts: make(map[string][]time.Time),
		apiRequests:   make(map[string][]time.Time),
		pruneDone:     make(chan struct{}),
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
		"csmConfig":     func() template.JS { return template.JS(s.csmConfigJSON()) },
		"json": func(v any) template.JS {
			b, _ := json.Marshal(v)
			return template.JS(b)
		},
		"multiply":    func(a, b int) int { return a * b },
		"add":         func(a, b int) int { return a + b },
		"subtract":    func(a, b int) int { return a - b },
		"divisibleBy": func(a, b int) bool { return b != 0 && a%b == 0 },
	}

	// Try to load templates from disk
	templateDir := filepath.Join(s.uiDir, "templates")
	staticDir := filepath.Join(s.uiDir, "static")
	if _, err := os.Stat(templateDir); err == nil {
		s.templates = make(map[string]*template.Template)
		layoutPath := filepath.Join(templateDir, "layout.html")
		for _, page := range []string{"dashboard", "findings", "quarantine", "firewall", "modsec", "modsec-rules", "threat", "rules", "audit", "account", "incident", "email"} {
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
		mux.Handle("/history", s.requireAuth(http.HandlerFunc(s.handleHistoryRedirect)))
		mux.Handle("/quarantine", s.requireAuth(http.HandlerFunc(s.handleQuarantine)))
		mux.Handle("/blocked", s.requireAuth(http.HandlerFunc(s.handleFirewall))) // redirect old URL
		mux.Handle("/firewall", s.requireAuth(http.HandlerFunc(s.handleFirewall)))
		mux.Handle("/threat", s.requireAuth(http.HandlerFunc(s.handleThreat)))
		mux.Handle("/rules", s.requireAuth(http.HandlerFunc(s.handleRules)))
		mux.Handle("/audit", s.requireAuth(http.HandlerFunc(s.handleAudit)))
		mux.Handle("/account", s.requireAuth(http.HandlerFunc(s.handleAccount)))
		mux.Handle("/incident", s.requireAuth(http.HandlerFunc(s.handleIncident)))
		mux.Handle("/email", s.requireAuth(http.HandlerFunc(s.handleEmail)))
		mux.Handle("/modsec", s.requireAuth(http.HandlerFunc(s.handleModSec)))
		mux.Handle("/modsec/rules", s.requireAuth(http.HandlerFunc(s.handleModSecRules)))
	}

	// Auth-protected API — read
	mux.Handle("/api/v1/status", s.requireAuth(http.HandlerFunc(s.apiStatus)))
	mux.Handle("/api/v1/findings", s.requireAuth(http.HandlerFunc(s.apiFindings)))
	mux.Handle("/api/v1/findings/enriched", s.requireAuth(http.HandlerFunc(s.apiFindingsEnriched)))
	mux.Handle("/api/v1/history", s.requireAuth(http.HandlerFunc(s.apiHistory)))
	mux.Handle("/api/v1/quarantine", s.requireAuth(http.HandlerFunc(s.apiQuarantine)))
	mux.Handle("/api/v1/stats", s.requireAuth(http.HandlerFunc(s.apiStats)))
	mux.Handle("/api/v1/stats/trend", s.requireAuth(http.HandlerFunc(s.apiStatsTrend)))
	mux.Handle("/api/v1/stats/timeline", s.requireAuth(http.HandlerFunc(s.apiStatsTimeline)))
	mux.Handle("/api/v1/blocked-ips", s.requireAuth(http.HandlerFunc(s.apiBlockedIPs)))
	mux.Handle("/api/v1/modsec/stats", s.requireAuth(http.HandlerFunc(s.apiModSecStats)))
	mux.Handle("/api/v1/modsec/blocks", s.requireAuth(http.HandlerFunc(s.apiModSecBlocks)))
	mux.Handle("/api/v1/modsec/events", s.requireAuth(http.HandlerFunc(s.apiModSecEvents)))
	mux.Handle("/api/v1/modsec/rules", s.requireAuth(http.HandlerFunc(s.apiModSecRules)))
	mux.Handle("/api/v1/modsec/rules/apply", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiModSecRulesApply))))
	mux.Handle("/api/v1/modsec/rules/escalation", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiModSecRulesEscalation))))
	mux.Handle("/api/v1/health", s.requireAuth(http.HandlerFunc(s.apiHealth)))
	mux.Handle("/api/v1/accounts", s.requireAuth(http.HandlerFunc(s.apiAccounts)))
	mux.Handle("/api/v1/account", s.requireAuth(http.HandlerFunc(s.apiAccountDetail)))
	mux.Handle("/api/v1/history/csv", s.requireAuth(http.HandlerFunc(s.apiHistoryCSV)))
	mux.Handle("/api/v1/export", s.requireAuth(http.HandlerFunc(s.apiExport)))
	mux.Handle("/api/v1/import", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiImport))))
	mux.Handle("/api/v1/incident", s.requireAuth(http.HandlerFunc(s.apiIncident)))
	mux.Handle("/api/v1/email/stats", s.requireAuth(http.HandlerFunc(s.apiEmailStats)))
	mux.Handle("/api/v1/email/quarantine", s.requireAuth(http.HandlerFunc(s.apiEmailQuarantineList)))
	mux.Handle("/api/v1/email/quarantine/", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiEmailQuarantineAction))))
	mux.Handle("/api/v1/email/av/status", s.requireAuth(http.HandlerFunc(s.apiEmailAVStatus)))

	// Threat Intelligence API
	mux.Handle("/api/v1/threat/stats", s.requireAuth(http.HandlerFunc(s.apiThreatStats)))
	mux.Handle("/api/v1/threat/top-attackers", s.requireAuth(http.HandlerFunc(s.apiThreatTopAttackers)))
	mux.Handle("/api/v1/threat/ip", s.requireAuth(http.HandlerFunc(s.apiThreatIP)))
	mux.Handle("/api/v1/threat/events", s.requireAuth(http.HandlerFunc(s.apiThreatEvents)))
	mux.Handle("/api/v1/threat/db-stats", s.requireAuth(http.HandlerFunc(s.apiThreatDBStats)))
	mux.Handle("/api/v1/audit", s.requireAuth(http.HandlerFunc(s.apiUIAudit)))
	mux.Handle("/api/v1/finding-detail", s.requireAuth(http.HandlerFunc(s.apiFindingDetail)))
	mux.Handle("/api/v1/threat/whitelist-ip", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiThreatWhitelistIP))))
	mux.Handle("/api/v1/threat/whitelist", s.requireAuth(http.HandlerFunc(s.apiThreatWhitelist)))
	mux.Handle("/api/v1/threat/unwhitelist-ip", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiThreatUnwhitelistIP))))
	mux.Handle("/api/v1/threat/block-ip", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiThreatBlockIP))))
	mux.Handle("/api/v1/threat/clear-ip", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiThreatClearIP))))
	mux.Handle("/api/v1/threat/temp-whitelist-ip", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiThreatTempWhitelistIP))))

	// Rules API
	mux.Handle("/api/v1/rules/status", s.requireAuth(http.HandlerFunc(s.apiRulesStatus)))
	mux.Handle("/api/v1/rules/list", s.requireAuth(http.HandlerFunc(s.apiRulesList)))
	mux.Handle("/api/v1/rules/reload", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiRulesReload))))
	mux.Handle("/api/v1/rules/modsec-escalation", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiModSecEscalation))))

	// Suppressions API (CSRF validated inside handler for POST/DELETE)
	mux.Handle("/api/v1/suppressions", s.requireAuth(http.HandlerFunc(s.apiSuppressions)))

	// Firewall API
	mux.Handle("/api/v1/firewall/status", s.requireAuth(http.HandlerFunc(s.apiFirewallStatus)))
	mux.Handle("/api/v1/firewall/audit", s.requireAuth(http.HandlerFunc(s.apiFirewallAudit)))
	mux.Handle("/api/v1/firewall/subnets", s.requireAuth(http.HandlerFunc(s.apiFirewallSubnets)))
	mux.Handle("/api/v1/firewall/check", s.requireAuth(http.HandlerFunc(s.apiFirewallCheck)))

	// GeoIP API
	mux.Handle("/api/v1/geoip", s.requireAuth(http.HandlerFunc(s.apiGeoIPLookup)))
	mux.Handle("/api/v1/geoip/batch", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiGeoIPBatch))))

	// Auth-protected API — actions (with CSRF validation)
	mux.Handle("/api/v1/fix", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiFix))))
	mux.Handle("/api/v1/fix-bulk", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiBulkFix))))
	mux.Handle("/api/v1/scan-account", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiScanAccount))))
	mux.Handle("/api/v1/test-alert", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiTestAlert))))
	mux.Handle("/api/v1/block-ip", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiBlockIP))))
	mux.Handle("/api/v1/unblock-ip", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiUnblockIP))))
	mux.Handle("/api/v1/unblock-bulk", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiUnblockBulk))))
	mux.Handle("/api/v1/dismiss", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiDismissFinding))))
	mux.Handle("/api/v1/quarantine-preview", s.requireAuth(http.HandlerFunc(s.apiQuarantinePreview)))
	mux.Handle("/api/v1/quarantine-restore", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiQuarantineRestore))))
	mux.Handle("/api/v1/firewall/deny-subnet", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiFirewallDenySubnet))))
	mux.Handle("/api/v1/firewall/remove-subnet", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiFirewallRemoveSubnet))))
	mux.Handle("/api/v1/firewall/flush", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiFirewallFlush))))
	mux.Handle("/api/v1/firewall/unban", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiFirewallUnban))))

	// Logout (clears cookie, requires auth to prevent logout CSRF)
	mux.Handle("/logout", s.requireAuth(http.HandlerFunc(s.handleLogout)))

	s.httpSrv = &http.Server{
		Addr:              cfg.WebUI.Listen,
		Handler:           s.securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,  // slowloris protection
		ReadTimeout:       30 * time.Second,  // max time to read full request
		WriteTimeout:      300 * time.Second, // account scans can take several minutes
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Disable HTTP/2: Go's HTTP/2 implementation applies WriteTimeout
			// to the entire connection, not per-stream. Long-running handlers
			// (account scans ~5min) cause ERR_HTTP2_PROTOCOL_ERROR in browsers
			// when the timeout fires. HTTP/1.1 handles per-request deadlines
			// correctly via ResponseController.SetWriteDeadline.
			NextProtos: []string{"http/1.1"},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		},
	}

	return s, nil
}

// pruneLoginAttempts periodically cleans up stale rate-limit entries.
// It returns when s.pruneDone is closed.
func (s *Server) pruneLoginAttempts() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.pruneDone:
			return
		case <-ticker.C:
			s.loginMu.Lock()
			cutoff := time.Now().Add(-time.Minute)
			for ip, attempts := range s.loginAttempts {
				var recent []time.Time
				for _, t := range attempts {
					if t.After(cutoff) {
						recent = append(recent, t)
					}
				}
				if len(recent) == 0 {
					delete(s.loginAttempts, ip)
				} else {
					s.loginAttempts[ip] = recent
				}
			}
			s.loginMu.Unlock()

			// Also prune API rate-limit entries
			s.apiMu.Lock()
			for ip, reqs := range s.apiRequests {
				var recent []time.Time
				for _, t := range reqs {
					if t.After(cutoff) {
						recent = append(recent, t)
					}
				}
				if len(recent) == 0 {
					delete(s.apiRequests, ip)
				} else {
					s.apiRequests[ip] = recent
				}
			}
			s.apiMu.Unlock()
		}
	}
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

	go s.pruneLoginAttempts()

	perfCtx, perfCancel := context.WithCancel(context.Background())
	s.perfCancel = perfCancel
	go s.sampleMetricsLoop(perfCtx)

	fmt.Fprintf(os.Stderr, "WebUI listening on https://%s\n", s.cfg.WebUI.Listen)
	return s.httpSrv.ListenAndServeTLS(certPath, keyPath)
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.perfCancel != nil {
		s.perfCancel()
	}
	close(s.pruneDone)
	return s.httpSrv.Shutdown(ctx)
}

// Broadcast is a no-op kept for daemon compatibility; dashboard uses polling.
func (s *Server) Broadcast(_ []alert.Finding) {}

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

// SetEmailQuarantine sets the email quarantine for the email AV API endpoints.
func (s *Server) SetEmailQuarantine(q *emailav.Quarantine) {
	s.emailQuarantine = q
}

// SetEmailAVWatcherMode sets the watcher mode string for the email AV status API.
func (s *Server) SetEmailAVWatcherMode(mode string) {
	s.emailAVWatcherMode = mode
}

// csmConfigJSON returns a JSON string of feature flags for the frontend.
func (s *Server) csmConfigJSON() string {
	flags := map[string]interface{}{
		"emailAV":      s.cfg.EmailAV.Enabled,
		"firewall":     s.cfg.Firewall != nil && s.cfg.Firewall.Enabled,
		"autoResponse": s.cfg.AutoResponse.Enabled,
		"threatIntel":  s.cfg.Reputation.AbuseIPDBKey != "",
		"signatures":   s.cfg.Signatures.RulesDir != "",
		"challenge":    s.cfg.Challenge.Difficulty > 0,
		"hostname":     s.cfg.Hostname,
	}
	b, _ := json.Marshal(flags)
	return string(b)
}

// --- Authentication ---

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.isAuthenticated(r) {
			next.ServeHTTP(w, r)
			return
		}
		// API calls get 401 JSON; browser requests get redirect to login
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSONError(w, "Unauthorized", http.StatusUnauthorized)
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

	return false
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Redirect already-authenticated users to dashboard
	if s.isAuthenticated(r) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	if r.Method == http.MethodGet {
		s.renderTemplate(w, "login.html", nil)
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
		s.renderTemplate(w, "login.html", map[string]string{"Error": "Invalid token"})
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

// severityRank returns a numeric rank for severity labels (higher = more severe).
func severityRank(label string) int {
	switch label {
	case "CRITICAL":
		return 3
	case "HIGH":
		return 2
	case "WARNING":
		return 1
	default:
		return 0
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
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		w.Header().Set("Cache-Control", "no-store")

		// CORS/origin validation: reject cross-origin API requests
		if strings.HasPrefix(r.URL.Path, "/api/") {
			origin := r.Header.Get("Origin")
			if origin != "" {
				// Only allow same-origin — use r.Host which includes port
				host := r.Host
				if host == "" {
					// Fallback: build from config (hostname + listen port)
					host = s.cfg.Hostname
					if listen := s.cfg.WebUI.Listen; listen != "" {
						if idx := strings.LastIndex(listen, ":"); idx >= 0 {
							port := listen[idx+1:]
							if port != "443" {
								host = host + ":" + port
							}
						}
					}
				}
				allowed := "https://" + host
				if origin != allowed {
					http.Error(w, "Cross-origin request blocked", http.StatusForbidden)
					return
				}
				w.Header().Set("Access-Control-Allow-Origin", allowed)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			// Deny CORS preflight from unknown origins
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}

		// API rate limiting: 600 requests per minute per IP
		if strings.HasPrefix(r.URL.Path, "/api/") {
			ip := r.RemoteAddr
			if idx := strings.LastIndex(ip, ":"); idx >= 0 {
				ip = ip[:idx]
			}
			s.apiMu.Lock()
			now := time.Now()
			cutoff := now.Add(-time.Minute)
			var recent []time.Time
			for _, t := range s.apiRequests[ip] {
				if t.After(cutoff) {
					recent = append(recent, t)
				}
			}
			if len(recent) >= 600 {
				s.apiMu.Unlock()
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			s.apiRequests[ip] = append(recent, now)
			s.apiMu.Unlock()
		}

		next.ServeHTTP(w, r)
	})
}

// --- CSRF protection ---

// csrfToken generates a deterministic CSRF token from the auth token.
// This is safe because the auth token is secret and the CSRF token is
// derived via HMAC — knowing the CSRF token doesn't reveal the auth token.
func (s *Server) csrfToken() string {
	mac := hmac.New(sha256.New, []byte(s.cfg.WebUI.AuthToken))
	// Include start time so token rotates on each daemon restart
	fmt.Fprintf(mac, "csm-csrf-v1:%d", s.startTime.Unix())
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
		// Skip CSRF for Bearer token auth (API-to-API calls don't need CSRF protection)
		if r.Method == http.MethodPost && !s.isBearerAuth(r) && !s.validateCSRF(r) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) isBearerAuth(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return subtle.ConstantTimeCompare([]byte(auth[7:]), []byte(s.cfg.WebUI.AuthToken)) == 1
	}
	return false
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
