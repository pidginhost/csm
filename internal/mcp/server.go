package mcp

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
)

const (
	// Endpoint is the only path the listener serves.
	Endpoint = "/mcp"
	// maxBodyBytes bounds one JSON-RPC request body.
	maxBodyBytes = 1 << 20
	// maxConcurrentCalls bounds tool calls running at once, since several
	// routes read the live host (queue listings, account walks).
	maxConcurrentCalls = 4
	// callTimeout bounds one tool call; the dispatcher gets it as a
	// context deadline.
	callTimeout = 30 * time.Second
	// queueWait bounds how long a call waits for a free slot.
	queueWait = 10 * time.Second
	// credentialAttemptsPerMinute is the unknown-token budget per client,
	// as on the Web UI.
	credentialAttemptsPerMinute = 5
	// maxTrackedClients bounds the attempt map.
	maxTrackedClients = 10000
	// maxBatch bounds one JSON-RPC batch.
	maxBatch = 20
)

// Options wires a Server.
type Options struct {
	Config config.MCPConfig
	// Dispatcher serves the allowlisted reads; required.
	Dispatcher Dispatcher
	// Version, Hostname and Platform are reported by csm_overview.
	Version  string
	Hostname string
	Platform map[string]any
	// ConfigSummary answers csm_config_summary; nil disables the tool's
	// data with an error result.
	ConfigSummary func() map[string]any
	// GetCertificate supplies the TLS certificate for a TCP listener. It is
	// required for a TCP listen address and ignored for a Unix socket.
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// Now is the clock for token expiry and rate limits; nil means time.Now.
	Now func() time.Time
}

// Server is the MCP listener.
type Server struct {
	cfg           config.MCPConfig
	dispatcher    Dispatcher
	tools         map[string]tool
	descriptors   []toolDescriptor
	version       string
	hostname      string
	platform      map[string]any
	configSummary func() map[string]any
	now           func() time.Time
	getCert       func(*tls.ClientHelloInfo) (*tls.Certificate, error)

	httpSrv  *http.Server
	calls    chan struct{}
	attempts map[string][]time.Time
	mu       sync.Mutex
	listenMu sync.Mutex
	listener net.Listener
}

// New builds a server; it does not listen until Start.
func New(opts Options) (*Server, error) {
	if opts.Dispatcher == nil {
		return nil, errors.New("mcp: dispatcher is required")
	}
	if !opts.Config.Enabled {
		return nil, errors.New("mcp: not enabled")
	}
	usable := 0
	for _, tok := range opts.Config.Tokens {
		if tok.Token != "" && strings.TrimSpace(tok.Name) != "" {
			usable++
		}
	}
	if usable == 0 {
		return nil, errors.New("mcp: no token configured")
	}
	listen := opts.Config.Listen
	if listen == "" {
		listen = config.DefaultMCPListen
	}
	if config.MCPUnixSocketPath(listen) == "" {
		if _, _, err := net.SplitHostPort(listen); err != nil {
			return nil, fmt.Errorf("mcp: listen %q: %w", listen, err)
		}
		if opts.GetCertificate == nil {
			return nil, errors.New("mcp: a TCP listener needs a TLS certificate")
		}
	}
	s := &Server{
		cfg:           opts.Config,
		dispatcher:    opts.Dispatcher,
		version:       opts.Version,
		hostname:      opts.Hostname,
		platform:      opts.Platform,
		configSummary: opts.ConfigSummary,
		now:           opts.Now,
		getCert:       opts.GetCertificate,
		calls:         make(chan struct{}, maxConcurrentCalls),
		attempts:      make(map[string][]time.Time),
	}
	s.cfg.Listen = listen
	if s.now == nil {
		s.now = time.Now
	}
	s.tools, s.descriptors = toolTable(opts.Dispatcher)
	mux := http.NewServeMux()
	mux.HandleFunc(Endpoint, s.handle)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
	s.httpSrv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      callTimeout + 10*time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
	if s.getCert != nil {
		s.httpSrv.TLSConfig = &tls.Config{
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"http/1.1"},
			GetCertificate: s.getCert,
		}
	}
	return s, nil
}

// Handler exposes the HTTP handler for tests and embedding.
func (s *Server) Handler() http.Handler { return s.httpSrv.Handler }

// Tools lists the tool names the server offers, for logs and tests.
func (s *Server) Tools() []string {
	names := make([]string, 0, len(s.descriptors))
	for _, d := range s.descriptors {
		names = append(names, d.Name)
	}
	return names
}

// Start listens and serves until Shutdown. A Unix socket is created with
// mode 0660 after removing a stale file at the path.
func (s *Server) Start() error {
	var ln net.Listener
	if path := config.MCPUnixSocketPath(s.cfg.Listen); path != "" {
		if err := removeStaleSocket(path); err != nil {
			return err
		}
		l, err := net.Listen("unix", path)
		if err != nil {
			return fmt.Errorf("mcp: listen %s: %w", path, err)
		}
		// #nosec G302 -- group access is the point of the socket: a local
		// agent in the daemon's group connects without a TCP listener.
		if err := os.Chmod(path, 0o660); err != nil {
			_ = l.Close()
			return fmt.Errorf("mcp: chmod %s: %w", path, err)
		}
		ln = l
		csmlog.Info("mcp listening", "socket", path, "tools", len(s.descriptors))
	} else {
		l, err := net.Listen("tcp", s.cfg.Listen)
		if err != nil {
			return fmt.Errorf("mcp: listen %s: %w", s.cfg.Listen, err)
		}
		ln = tls.NewListener(l, s.httpSrv.TLSConfig)
		csmlog.Info("mcp listening", "addr", "https://"+s.cfg.Listen+Endpoint, "tools", len(s.descriptors))
	}
	s.listenMu.Lock()
	s.listener = ln
	s.listenMu.Unlock()
	err := s.httpSrv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("mcp: %s: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("mcp: %s exists and is not a socket", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("mcp: remove stale socket %s: %w", path, err)
	}
	return nil
}

// Shutdown stops the listener and waits for in-flight calls up to ctx.
func (s *Server) Shutdown(ctx context.Context) error {
	err := s.httpSrv.Shutdown(ctx)
	if path := config.MCPUnixSocketPath(s.cfg.Listen); path != "" {
		_ = os.Remove(path)
	}
	return err
}

// --- HTTP layer ---

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	switch r.Method {
	case http.MethodPost:
	case http.MethodGet, http.MethodDelete:
		// No server-initiated stream and no sessions: the spec allows 405.
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "this endpoint accepts POST only")
		return
	default:
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.originAllowed(r) {
		writeError(w, http.StatusForbidden, "origin not allowed")
		return
	}
	tok, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if v := r.Header.Get("MCP-Protocol-Version"); v != "" && !supportedProtocol(v) {
		writeError(w, http.StatusBadRequest, "unsupported MCP protocol version "+v)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "cannot read request body")
		return
	}
	if len(body) > maxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	peer := r.RemoteAddr
	requests, batch, perr := parseRequests(body)
	if perr != nil {
		writeJSON(w, http.StatusOK, newError(nil, perr.Code, perr.Message))
		return
	}
	var responses []rpcResponse
	for _, req := range requests {
		resp, ok := s.dispatch(r.Context(), req, tok.Name, peer)
		if ok {
			responses = append(responses, resp)
		}
	}
	if len(responses) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if batch {
		writeJSON(w, http.StatusOK, responses)
		return
	}
	writeJSON(w, http.StatusOK, responses[0])
}

// parseRequests decodes one request or a batch. It answers the JSON-RPC
// error the spec names for malformed input.
func parseRequests(body []byte) ([]rpcRequest, bool, *rpcError) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, false, &rpcError{Code: codeInvalidRequest, Message: "empty request"}
	}
	if strings.HasPrefix(trimmed, "[") {
		var reqs []rpcRequest
		if err := json.Unmarshal(body, &reqs); err != nil {
			return nil, true, &rpcError{Code: codeParse, Message: "parse error"}
		}
		if len(reqs) == 0 {
			return nil, true, &rpcError{Code: codeInvalidRequest, Message: "empty batch"}
		}
		if len(reqs) > maxBatch {
			return nil, true, &rpcError{Code: codeInvalidRequest, Message: fmt.Sprintf("batch larger than %d", maxBatch)}
		}
		return reqs, true, nil
	}
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, false, &rpcError{Code: codeParse, Message: "parse error"}
	}
	return []rpcRequest{req}, false, nil
}

// dispatch answers one JSON-RPC request. ok is false for a notification.
func (s *Server) dispatch(ctx context.Context, req rpcRequest, tokenName, peer string) (rpcResponse, bool) {
	if req.JSONRPC != "2.0" || req.Method == "" {
		if req.isNotification() {
			return rpcResponse{}, false
		}
		return newError(req.ID, codeInvalidRequest, "invalid request"), true
	}
	if strings.HasPrefix(req.Method, "notifications/") {
		return rpcResponse{}, false
	}
	if req.isNotification() {
		// A request without an id gets no answer under JSON-RPC 2.0.
		return rpcResponse{}, false
	}
	switch req.Method {
	case "initialize":
		var p initializeParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return newError(req.ID, codeInvalidParams, "invalid initialize params"), true
			}
		}
		version := protocolVersions[0]
		if supportedProtocol(p.ProtocolVersion) {
			version = p.ProtocolVersion
		}
		return newResult(req.ID, map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": ServerName, "version": s.version},
			"instructions":    instructions,
		}), true
	case "ping":
		return newResult(req.ID, map[string]any{}), true
	case "tools/list":
		return newResult(req.ID, map[string]any{"tools": s.descriptors}), true
	case "tools/call":
		var p toolsCallParams
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			return newError(req.ID, codeInvalidParams, "tools/call needs a name"), true
		}
		if _, ok := s.tools[p.Name]; !ok {
			return newError(req.ID, codeInvalidParams, "unknown tool "+p.Name), true
		}
		result, err := s.runCall(ctx, p, tokenName, peer)
		if err != nil {
			return newError(req.ID, codeInvalidParams, err.Error()), true
		}
		return newResult(req.ID, result), true
	case "resources/list":
		return newResult(req.ID, map[string]any{"resources": []any{}}), true
	case "resources/templates/list":
		return newResult(req.ID, map[string]any{"resourceTemplates": []any{}}), true
	case "prompts/list":
		return newResult(req.ID, map[string]any{"prompts": []any{}}), true
	}
	return newError(req.ID, codeMethodNotFound, "method not found: "+req.Method), true
}

// instructions is sent on initialize so a client model knows the surface.
const instructions = "Read-only view of the CSM security monitor on this server. " +
	"Every tool reads; none can block, unblock, fix, scan or change settings. " +
	"Start with csm_overview, use csm_lookup_ip for an address and csm_account for a hosting account. " +
	"Lists answer {items, total, truncated}; page with the limit, offset or page arguments a tool declares."

// runCall runs one tool call under the concurrency cap and timeout and
// logs it.
func (s *Server) runCall(ctx context.Context, p toolsCallParams, tokenName, peer string) (toolResult, error) {
	select {
	case s.calls <- struct{}{}:
	case <-ctx.Done():
		return errorResult("request cancelled"), nil
	case <-time.After(queueWait):
		return errorResult("server busy; retry shortly"), nil
	}
	defer func() { <-s.calls }()
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	start := s.now()
	result, status, err := s.callTool(ctx, p.Name, p.Arguments, peer)
	outcome := "ok"
	switch {
	case err != nil:
		outcome = "invalid"
	case result.IsError:
		outcome = "error"
	}
	csmlog.Info("mcp tool call", "token", tokenName, "tool", p.Name, "peer", peerForLog(peer),
		"status", status, "outcome", outcome, "duration_ms", s.now().Sub(start).Milliseconds(),
		"args", argsForLog(p.Arguments))
	return result, err
}

func peerForLog(peer string) string {
	if host, _, err := net.SplitHostPort(peer); err == nil {
		return host
	}
	if peer == "" || peer == "@" {
		return "unix"
	}
	return peer
}

// argsForLog keeps the call arguments in the log, cut to a line.
func argsForLog(raw json.RawMessage) string {
	s := strings.TrimSpace(string(raw))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// --- auth ---

// authenticate checks the bearer token against mcp.tokens. The attempt
// budget is charged for unknown tokens only; a known token outside its
// source restriction or past its expiry is refused without a charge, as it
// is not a guess.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (config.MCPToken, bool) {
	refuse := func(status int, msg string) (config.MCPToken, bool) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="csm-mcp"`)
		writeError(w, status, msg)
		return config.MCPToken{}, false
	}
	supplied, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	supplied = strings.TrimSpace(supplied)
	if !ok || supplied == "" {
		return refuse(http.StatusUnauthorized, "bearer token required")
	}
	key := rateLimitKey(r.RemoteAddr)
	s.mu.Lock()
	now := s.now()
	recent := s.recentAttempts(key, now)
	if len(recent) >= credentialAttemptsPerMinute {
		s.mu.Unlock()
		csmlog.Warn("mcp auth rate limited", "peer", peerForLog(r.RemoteAddr))
		return refuse(http.StatusTooManyRequests, "too many failed token attempts")
	}
	tok, known := s.lookupToken(supplied)
	if !known {
		if len(s.attempts) >= maxTrackedClients {
			s.attempts = make(map[string][]time.Time)
		}
		s.attempts[key] = append(recent, now)
	}
	s.mu.Unlock()
	if !known {
		csmlog.Warn("mcp auth failed", "peer", peerForLog(r.RemoteAddr), "reason", "unknown token")
		return refuse(http.StatusUnauthorized, "invalid token")
	}
	if !tok.Current(now) {
		csmlog.Warn("mcp auth failed", "peer", peerForLog(r.RemoteAddr), "token", tok.Name, "reason", "expired or not yet valid")
		return refuse(http.StatusUnauthorized, "token expired")
	}
	if addr, isTCP := peerAddr(r.RemoteAddr); isTCP && !tok.AcceptsFrom(addr) {
		csmlog.Warn("mcp auth failed", "peer", peerForLog(r.RemoteAddr), "token", tok.Name, "reason", "source not allowed")
		return refuse(http.StatusUnauthorized, "token not accepted from this address")
	}
	return tok, true
}

func (s *Server) lookupToken(supplied string) (config.MCPToken, bool) {
	var found config.MCPToken
	matched := false
	for _, tok := range s.cfg.Tokens {
		if tok.Token == "" {
			continue
		}
		// Compare every entry so timing does not reveal which one matched.
		if subtle.ConstantTimeCompare([]byte(tok.Token), []byte(supplied)) == 1 && !matched {
			found, matched = tok, true
		}
	}
	return found, matched
}

func (s *Server) recentAttempts(key string, now time.Time) []time.Time {
	var recent []time.Time
	for _, t := range s.attempts[key] {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	return recent
}

// peerAddr parses a TCP peer. A Unix socket peer has no address and is
// reported as not TCP, so allowed_ips does not apply to it.
func peerAddr(remote string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

// rateLimitKey is the IPv4 address or the IPv6 /64 of a peer; a Unix peer
// shares one key.
func rateLimitKey(remote string) string {
	addr, ok := peerAddr(remote)
	if !ok {
		return "unix"
	}
	addr = addr.WithZone("").Unmap()
	if addr.Is4() {
		return addr.String()
	}
	return netip.PrefixFrom(addr, 64).Masked().String()
}

// originAllowed is the DNS-rebinding guard the transport asks for: a
// browser-style Origin must be loopback or name this listener's host.
// Requests without an Origin, the normal case for an agent, pass.
func (s *Server) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || origin == "null" {
		return origin == ""
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil && ip.IsLoopback() {
		return true
	}
	listenHost, _, err := net.SplitHostPort(s.cfg.Listen)
	if err != nil || listenHost == "" {
		return false
	}
	return strings.EqualFold(host, listenHost) || strings.EqualFold(u.Host, r.Host)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
