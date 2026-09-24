package webui

import (
	"crypto/subtle"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/session"
)

// --- Authentication ---

// tokenHasScope reports whether the credentials in r grant at least the
// requested scope. "read" is granted by any token; "admin" is granted only
// by admin-scope tokens. Constant-time compare against every configured
// token. Browser sessions bind to the named administrator credential that
// created them; the API credential itself is never accepted from a cookie.
func (s *Server) tokenHasScope(r *http.Request, want string) bool {
	// Browser cookie session
	if _, ok := s.cookieTokenWithScope(r, want); ok {
		return true
	}

	// Bearer token
	_, ok := s.bearerTokenWithScope(r, want)
	return ok
}

func (s *Server) cookieTokenWithScope(r *http.Request, want string) (string, bool) {
	return s.cookieSessionToken(r, want, sessionActivity(r))
}

// sessionActivity reports whether a request is the operator's own activity,
// which extends an idle browser session: a page load, or an API call the UI
// marks with X-CSM-Active because it followed the operator's input. Timer
// polls and the event stream do not, so a page left open still reaches the
// idle timeout.
func sessionActivity(r *http.Request) bool {
	if r.URL.Path == "/metrics" || r.URL.Path == "/api/v1/events" {
		return false
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		return r.Header.Get("X-CSM-Active") == "1"
	}
	if r.Method != http.MethodGet {
		return false
	}
	// Fetches can poll HTML pages too. Only navigation counts as a page
	// load; older browsers identify it by Accept instead of Fetch Metadata.
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" {
		return mode == "navigate"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func (s *Server) cookieSessionToken(r *http.Request, want string, touch bool) (string, bool) {
	tok, ok := s.cookieSessionCredential(r, want, touch)
	return tok.Token, ok
}

func (s *Server) cookieSessionCredential(r *http.Request, want string, touch bool) (config.WebUIToken, bool) {
	c, err := r.Cookie("csm_auth")
	if err != nil || s.sessions == nil {
		return config.WebUIToken{}, false
	}
	rec, err := s.sessions.Access(c.Value, s.sessionNow(), touch)
	if err != nil {
		return config.WebUIToken{}, false
	}
	for _, tok := range s.cfg.WebUI.Tokens {
		if tok.Name == rec.Name && session.Hash(tok.Token) == rec.Credential && tok.Scope == "admin" && webUITokenAllows(tok, want) {
			return tok, true
		}
	}
	// A removed, rotated or downgraded login credential cannot leave a
	// browser session active, even if a caller changes config in place.
	_ = s.sessions.Revoke(rec.ID)
	return config.WebUIToken{}, false
}

func (s *Server) bearerTokenWithScope(r *http.Request, want string) (string, bool) {
	tok, ok := s.bearerCredentialWithScope(r, want)
	return tok.Token, ok
}

func (s *Server) bearerCredentialWithScope(r *http.Request, want string) (config.WebUIToken, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return config.WebUIToken{}, false
	}
	supplied := strings.TrimPrefix(auth, "Bearer ")
	if supplied == "" {
		return config.WebUIToken{}, false
	}
	for _, tok := range s.cfg.WebUI.Tokens {
		if webUITokenMatches(supplied, tok) && webUITokenAllows(tok, want) {
			return tok, true
		}
	}
	return config.WebUIToken{}, false
}

func webUITokenMatches(supplied string, tok config.WebUIToken) bool {
	return supplied != "" &&
		tok.Token != "" &&
		subtle.ConstantTimeCompare([]byte(supplied), []byte(tok.Token)) == 1
}

func webUITokenAllows(tok config.WebUIToken, want string) bool {
	switch want {
	case "read":
		return tok.Scope == "read" || tok.Scope == "admin"
	case "admin":
		return tok.Scope == "admin"
	default:
		return false
	}
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tok, ok := s.cookieSessionCredential(r, "admin", sessionActivity(r)); ok {
			next.ServeHTTP(w, withAuditActor(r, tok.Name, "browser"))
			return
		}
		if tok, ok := s.bearerCredentialWithScope(r, "admin"); ok {
			next.ServeHTTP(w, withAuditActor(r, tok.Name, "api"))
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

func (s *Server) requireRead(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.tokenHasScope(r, "read") {
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", http.MethodGet)
				writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
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

// isAuthenticated is a thin shim used by handleLogin and metrics_api.
// New callers should prefer tokenHasScope directly.
func (s *Server) isAuthenticated(r *http.Request) bool {
	return s.tokenHasScope(r, "admin")
}

// clientIPKey strips the port from a net/http RemoteAddr for use as a
// per-client rate-limit key, handling bracketed IPv6 ([::1]:443 -> ::1).
// Falls back to the raw value when there is no host:port to split, so a
// missing port never collapses distinct clients onto one key.
func clientIPKey(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// rateLimitKey is the client a rate limit counts: the IPv4 address, or the
// /64 of an IPv6 address, since one IPv6 client is routed a whole /64 and can
// rotate addresses inside it.
func rateLimitKey(remoteAddr string) string {
	host := clientIPKey(remoteAddr)
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	ip = ip.WithZone("").Unmap()
	if ip.Is4() {
		return ip.String()
	}
	return netip.PrefixFrom(ip, 64).Masked().String()
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Redirect already-authenticated users to dashboard
	if r.Method == http.MethodGet && s.isAuthenticated(r) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	if r.Method == http.MethodGet {
		s.renderTemplate(w, r, "login.html", nil)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limit: 5 attempts per minute per client (IPv4 address or IPv6 /64)
	ip := rateLimitKey(r.RemoteAddr)
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
	if _, tracked := s.loginAttempts[ip]; !tracked {
		boundRateLimitMap(s.loginAttempts, now.Add(-time.Minute))
	}
	s.loginAttempts[ip] = append(recent, now)
	s.loginMu.Unlock()

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return
	}
	token := r.PostForm.Get("token")
	// Only admin-scope tokens may log in via the browser form.
	var loginName string
	if token != "" {
		for _, tok := range s.cfg.WebUI.Tokens {
			if tok.Scope == "admin" && webUITokenMatches(token, tok) {
				loginName = tok.Name
				break
			}
		}
	}
	if loginName == "" {
		// Failed logins go to the daemon log, not the UI audit trail: they
		// are unauthenticated, and addresses from a whole network could
		// otherwise rotate operator history out of the audit file.
		// #nosec G706 -- RemoteAddr is the TCP peer address net/http sets, not request content.
		log.Printf("webui: failed browser login from %s", safeLogString(clientIPKey(r.RemoteAddr)))
		s.renderTemplate(w, r, "login.html", map[string]string{"Error": "Invalid token"})
		return
	}

	if s.sessions == nil {
		http.Error(w, "Session store unavailable", http.StatusServiceUnavailable)
		return
	}
	previous := ""
	if c, err := r.Cookie("csm_auth"); err == nil {
		// Reauthentication already proved the new login credential. Look up
		// the old session without touching it, and retain storage errors so
		// a failed lookup cannot silently turn rotation into a fresh login.
		_, err := s.sessions.Access(c.Value, s.sessionNow(), false)
		if err != nil && !errors.Is(err, session.ErrInvalid) {
			http.Error(w, "Session store unavailable", http.StatusServiceUnavailable)
			return
		}
		if err == nil {
			previous = c.Value
		}
	}
	secret, record, err := s.sessions.Create(loginName, session.Hash(token), previous, clientIPKey(r.RemoteAddr), r.UserAgent(), s.sessionNow())
	if errors.Is(err, session.ErrFull) {
		// The Sessions page needs a login, so name the recovery paths here.
		http.Error(w, "Browser session limit reached. Wait for idle sessions to expire, or revoke sessions with an admin API token.", http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		http.Error(w, "Cannot create browser session", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "csm_auth",
		Value:    secret,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(record.Expires.Sub(record.Created).Seconds()),
		Expires:  record.Expires,
	})
	s.auditLogAs(r, loginName, "browser", "login", loginName, "browser session started")
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// --- Logout ---

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if c, err := r.Cookie("csm_auth"); err == nil && s.sessions != nil {
		rec, err := s.sessions.Access(c.Value, s.sessionNow(), false)
		if err != nil && !errors.Is(err, session.ErrInvalid) {
			http.Error(w, "Cannot revoke browser session", http.StatusServiceUnavailable)
			return
		}
		if err == nil {
			if err = s.sessions.Revoke(rec.ID); err != nil {
				http.Error(w, "Cannot revoke browser session", http.StatusServiceUnavailable)
				return
			}
			s.auditLogAs(r, rec.Name, "browser", "logout", rec.Name, "browser session ended")
		}
	}
	clearBrowserCookie(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func clearBrowserCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "csm_auth",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // delete cookie
	})
}
