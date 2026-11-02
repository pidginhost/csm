package webui

import (
	"crypto/subtle"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// mcpPath is where the read-only MCP endpoint answers on the Web UI
// listener.
const mcpPath = "/mcp"

// MCPServer answers MCP requests the Web UI has authenticated. caller names
// the mcp.tokens credential.
type MCPServer interface {
	ServeMCP(w http.ResponseWriter, r *http.Request, caller string)
}

// SetMCP attaches the read-only MCP endpoint. Call it before Start.
func (s *Server) SetMCP(m MCPServer) { s.mcp = m }

// serveMCP admits only mcp.tokens credentials: a Web UI token or browser
// session never opens it, and an MCP token opens nothing else. Unknown
// tokens draw on the same per-client guess budget as the login form and
// API bearer tokens.
func (s *Server) serveMCP(w http.ResponseWriter, r *http.Request) {
	if s.mcp == nil {
		writeJSONError(w, "Not found", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		// No server-initiated stream and no sessions: the transport allows 405.
		w.Header().Set("Allow", http.MethodPost)
		writeJSONError(w, "This endpoint accepts POST only", http.StatusMethodNotAllowed)
		return
	}
	tok, status, msg := s.mcpCredential(r)
	if status != 0 {
		// A spent budget is not logged: a flood would fill the log.
		if status != http.StatusTooManyRequests {
			// #nosec G706 -- RemoteAddr is the TCP peer address net/http sets and the name comes from csm.yaml, not request content.
			log.Printf("mcp: refused token %q from %s: %s", tok.Name, safeLogString(clientIPKey(r.RemoteAddr)), msg)
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="csm-mcp"`)
		writeJSONError(w, msg, status)
		return
	}
	s.mcp.ServeMCP(w, r, tok.Name)
}

// mcpCredential returns the mcp.tokens entry the request presents and, when
// it is refused, the status and message; a known entry is returned even
// then so the refusal can name it. Budget check, comparison and the charge
// for an unknown token share one critical section, as in refuseSpentBearer.
// A known token outside its dates or addresses is not a guess and is not
// charged.
func (s *Server) mcpCredential(r *http.Request) (config.MCPToken, int, string) {
	supplied, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || supplied == "" {
		return config.MCPToken{}, http.StatusUnauthorized, "Bearer token required"
	}
	ip := rateLimitKey(r.RemoteAddr)
	s.loginMu.Lock()
	now := time.Now()
	recent := s.recentCredentialAttempts(ip, now)
	if len(recent) >= credentialAttemptsPerMinute {
		s.loginMu.Unlock()
		return config.MCPToken{}, http.StatusTooManyRequests, "Too many failed token attempts"
	}
	tok, known := mcpTokenFor(s.cfg.MCP.Tokens, supplied)
	if !known && !s.knownWebUIBearer(r) {
		if _, tracked := s.loginAttempts[ip]; !tracked {
			boundRateLimitMap(s.loginAttempts, now.Add(-time.Minute))
		}
		s.loginAttempts[ip] = append(recent, now)
	}
	s.loginMu.Unlock()
	switch {
	case !known:
		return config.MCPToken{}, http.StatusUnauthorized, "Invalid token"
	case !tok.Current(now):
		return tok, http.StatusUnauthorized, "Token expired or not yet valid"
	case !tok.AcceptsFrom(requestAddr(r)):
		return tok, http.StatusUnauthorized, "Token not accepted from this address"
	}
	return tok, 0, ""
}

// mcpTokenFor compares supplied against every entry in constant time, so
// timing does not tell which entry matched.
func mcpTokenFor(tokens []config.MCPToken, supplied string) (config.MCPToken, bool) {
	var found config.MCPToken
	matched := false
	for _, tok := range tokens {
		if tok.Token != "" && subtle.ConstantTimeCompare([]byte(tok.Token), []byte(supplied)) == 1 && !matched {
			found, matched = tok, true
		}
	}
	return found, matched
}
