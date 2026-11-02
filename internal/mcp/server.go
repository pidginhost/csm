package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/obs"
)

const (
	// maxBodyBytes bounds one JSON-RPC request body.
	maxBodyBytes = 1 << 20
	// maxConcurrentCalls bounds tool calls running at once, since several
	// routes read the live host (queue listings, account walks).
	maxConcurrentCalls = 4
	// requestTimeout bounds one request, every call of a batch included;
	// the dispatcher gets it as a context deadline. A deadline per call let
	// a batch outlive the listener's write timeout.
	requestTimeout = 30 * time.Second
	// queueWait bounds how long a call waits for a free slot.
	queueWait = 10 * time.Second
	// maxBatch bounds one JSON-RPC batch.
	maxBatch = 20
)

// Options wires a Server.
type Options struct {
	// Dispatcher serves the allowlisted reads.
	Dispatcher Dispatcher
	// Version, Hostname and Platform are reported by csm_overview.
	Version  string
	Hostname string
	Platform map[string]any
	// ConfigSummary answers csm_config_summary; nil makes the tool answer
	// an error result.
	ConfigSummary func() map[string]any
}

// Server speaks MCP over requests the Web UI listener has already
// authenticated; it holds no listener or credentials of its own.
type Server struct {
	dispatcher    Dispatcher
	tools         map[string]tool
	descriptors   []toolDescriptor
	version       string
	hostname      string
	platform      map[string]any
	configSummary func() map[string]any
	calls         chan struct{}
}

// New builds a server for opts.
func New(opts Options) *Server {
	s := &Server{
		dispatcher:    opts.Dispatcher,
		version:       opts.Version,
		hostname:      opts.Hostname,
		platform:      opts.Platform,
		configSummary: opts.ConfigSummary,
		calls:         make(chan struct{}, maxConcurrentCalls),
	}
	s.tools, s.descriptors = toolTable(opts.Dispatcher)
	return s
}

// Tools lists the tool names the server offers, for logs and tests.
func (s *Server) Tools() []string {
	names := make([]string, 0, len(s.descriptors))
	for _, d := range s.descriptors {
		names = append(names, d.Name)
	}
	return names
}

// ServeMCP answers one POST of the Streamable HTTP transport. The caller
// has checked the method, origin and credential; caller names the
// credential for the call log.
func (s *Server) ServeMCP(w http.ResponseWriter, r *http.Request, caller string) {
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
	requests, batch, perr := parseRequests(body)
	if perr != nil {
		writeJSON(w, http.StatusOK, newError(nil, perr.Code, perr.Message))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	var responses []rpcResponse
	for _, req := range requests {
		resp, ok := s.dispatch(ctx, req, caller, r.RemoteAddr)
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

// runCall runs one tool call under the concurrency cap and the request's
// deadline, and logs it.
func (s *Server) runCall(ctx context.Context, p toolsCallParams, tokenName, peer string) (toolResult, error) {
	if err := ctx.Err(); err != nil {
		return errorResult(err.Error()), nil
	}
	select {
	case s.calls <- struct{}{}:
	case <-ctx.Done():
		return errorResult("request cancelled"), nil
	case <-time.After(queueWait):
		return errorResult("server busy; retry shortly"), nil
	}
	// A free slot and cancellation can become ready together. Do not start
	// another batch member after the request has expired.
	if err := ctx.Err(); err != nil {
		<-s.calls
		return errorResult(err.Error()), nil
	}
	type answer struct {
		result toolResult
		err    error
	}
	done := make(chan answer, 1)
	obs.SafeGo("mcp", func() {
		// Some live-host reads cannot observe cancellation. Keep their slot
		// until they finish so repeated timeouts cannot spawn unlimited work.
		out := answer{result: errorResult("tool call failed")}
		defer func() {
			<-s.calls
			done <- out
		}()
		out.result, out.err = s.loggedCall(ctx, p, tokenName, peer)
	})
	select {
	case <-ctx.Done():
		return errorResult("request cancelled"), nil
	case out := <-done:
		if err := ctx.Err(); err != nil {
			return errorResult(err.Error()), nil
		}
		return out.result, out.err
	}
}

func (s *Server) loggedCall(ctx context.Context, p toolsCallParams, tokenName, peer string) (toolResult, error) {
	start := time.Now()
	result, status, err := s.callTool(ctx, p.Name, p.Arguments, peer)
	outcome := "ok"
	switch {
	case err != nil:
		outcome = "invalid"
	case result.IsError:
		outcome = "error"
	}
	csmlog.Info("mcp tool call", "token", tokenName, "tool", p.Name, "peer", peerForLog(peer),
		"status", status, "outcome", outcome, "duration_ms", time.Since(start).Milliseconds(),
		"args", argsForLog(p.Arguments))
	return result, err
}

func peerForLog(peer string) string {
	if host, _, err := net.SplitHostPort(peer); err == nil {
		return host
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
