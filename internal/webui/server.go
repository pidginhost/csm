package webui

import (
	"context"
	"crypto/subtle"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

// Server is the embedded web UI HTTP server.
type Server struct {
	cfg       *config.Config
	store     *state.Store
	hub       *Hub
	httpSrv   *http.Server
	templates *template.Template
	startTime time.Time
	sigCount  int // loaded signature rule count

	// Login rate limiting
	loginMu       sync.Mutex
	loginAttempts map[string][]time.Time
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

	// Parse embedded templates
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"severityClass": severityClass,
		"severityLabel": severityLabel,
		"timeAgo":       timeAgo,
		"formatTime":    formatTime,
	}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parsing templates: %w", err)
	}
	s.templates = tmpl

	// Set up routes
	mux := http.NewServeMux()

	// Static files (no auth required)
	staticSub, _ := fs.Sub(staticFS, "static")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Login (no auth required)
	mux.HandleFunc("/login", s.handleLogin)

	// Auth-protected pages
	mux.Handle("/", s.requireAuth(http.HandlerFunc(s.handleDashboard)))
	mux.Handle("/dashboard", s.requireAuth(http.HandlerFunc(s.handleDashboard)))
	mux.Handle("/findings", s.requireAuth(http.HandlerFunc(s.handleFindings)))
	mux.Handle("/history", s.requireAuth(http.HandlerFunc(s.handleHistory)))
	mux.Handle("/quarantine", s.requireAuth(http.HandlerFunc(s.handleQuarantine)))

	// Auth-protected API
	mux.Handle("/api/v1/status", s.requireAuth(http.HandlerFunc(s.apiStatus)))
	mux.Handle("/api/v1/findings", s.requireAuth(http.HandlerFunc(s.apiFindings)))
	mux.Handle("/api/v1/history", s.requireAuth(http.HandlerFunc(s.apiHistory)))
	mux.Handle("/api/v1/quarantine", s.requireAuth(http.HandlerFunc(s.apiQuarantine)))
	mux.Handle("/api/v1/stats", s.requireAuth(http.HandlerFunc(s.apiStats)))

	// WebSocket (auth via query param)
	mux.HandleFunc("/ws/findings", s.handleWSFindings)

	s.httpSrv = &http.Server{
		Addr:         cfg.WebUI.Listen,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
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
		_ = s.templates.ExecuteTemplate(w, "login.html", nil)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limit: 5 attempts per minute per IP
	ip := r.RemoteAddr
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
		_ = s.templates.ExecuteTemplate(w, "login.html", map[string]string{"Error": "Invalid token"})
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
