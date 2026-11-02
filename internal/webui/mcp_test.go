package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mcp"
)

const (
	mcpTestToken    = "mcp-agent-0123456789abcdef0123456789abcdef0123"
	mcpOfficeToken  = "mcp-office-0123456789abcdef0123456789abcdef012"
	mcpExpiredToken = "mcp-expired-0123456789abcdef0123456789abcdef01"
	webTestToken    = "web-admin-0123456789abcdef0123456789abcdef0123"
)

// recordingMCP stands in for the MCP server: it records the credential name
// the Web UI authenticated each request as.
type recordingMCP struct{ callers []string }

func (m *recordingMCP) ServeMCP(w http.ResponseWriter, _ *http.Request, caller string) {
	m.callers = append(m.callers, caller)
	writeJSON(w, map[string]bool{"ok": true})
}

func newMCPTestServer(t *testing.T) *Server {
	t.Helper()
	s := newTestServer(t, webTestToken)
	s.cfg.MCP = config.MCPConfig{Enabled: true, Tokens: []config.MCPToken{
		{Name: "agent", Token: mcpTestToken},
		{Name: "office", Token: mcpOfficeToken, AllowedIPs: []string{"198.51.100.0/24"}},
		{Name: "old", Token: mcpExpiredToken, ExpiresAt: "2020-01-01T00:00:00Z"},
	}}
	return s
}

// mcpRequest sends one request through the Web UI's full handler chain.
// headers are name/value pairs; "Host" sets the request host.
func mcpRequest(s *Server, method, path, token, remote, body string, headers ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = remote
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		if headers[i] == "Host" {
			req.Host = headers[i+1]
			continue
		}
		req.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	return w
}

const mcpPing = `{"jsonrpc":"2.0","id":1,"method":"ping"}`

func TestMCPEndpointOnWebUIListener(t *testing.T) {
	s := newMCPTestServer(t)
	m := &recordingMCP{}
	s.SetMCP(m)
	if w := mcpRequest(s, http.MethodPost, "/mcp", mcpTestToken, "127.0.0.1:4000", mcpPing); w.Code != http.StatusOK {
		t.Fatalf("POST /mcp: %d %s", w.Code, w.Body)
	}
	if len(m.callers) != 1 || m.callers[0] != "agent" {
		t.Fatalf("callers = %v, want [agent]", m.callers)
	}
	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodPut} {
		w := mcpRequest(s, method, "/mcp", mcpTestToken, "127.0.0.1:4000", "")
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != http.MethodPost {
			t.Errorf("%s /mcp: %d allow=%q", method, w.Code, w.Header().Get("Allow"))
		}
	}
	if len(m.callers) != 1 {
		t.Errorf("non-POST requests reached the MCP server: %v", m.callers)
	}
}

func TestMCPNotAttachedAnswersNotFound(t *testing.T) {
	s := newMCPTestServer(t)
	if w := mcpRequest(s, http.MethodPost, "/mcp", mcpTestToken, "127.0.0.1:4000", mcpPing); w.Code != http.StatusNotFound {
		t.Errorf("POST /mcp without an MCP server: %d", w.Code)
	}
}

func TestMCPCredentialsAreSeparateFromWebUI(t *testing.T) {
	s := newMCPTestServer(t)
	m := &recordingMCP{}
	s.SetMCP(m)
	if w := mcpRequest(s, http.MethodPost, "/mcp", webTestToken, "127.0.0.1:4000", mcpPing); w.Code != http.StatusUnauthorized {
		t.Errorf("Web UI admin token on /mcp: %d", w.Code)
	}
	if w := mcpRequest(s, http.MethodGet, "/api/v1/status", mcpTestToken, "127.0.0.1:4001", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("MCP token on /api/v1/status: %d", w.Code)
	}
	if len(m.callers) != 0 {
		t.Errorf("refused requests reached the MCP server: %v", m.callers)
	}
}

func TestMCPTokenDatesAndSources(t *testing.T) {
	s := newMCPTestServer(t)
	m := &recordingMCP{}
	s.SetMCP(m)
	for _, tc := range []struct {
		name, token, remote string
		want                int
	}{
		{"no token", "", "127.0.0.1:4000", http.StatusUnauthorized},
		{"expired", mcpExpiredToken, "127.0.0.1:4000", http.StatusUnauthorized},
		{"outside allowed_ips", mcpOfficeToken, "127.0.0.1:4000", http.StatusUnauthorized},
		{"inside allowed_ips", mcpOfficeToken, "198.51.100.7:4000", http.StatusOK},
	} {
		if w := mcpRequest(s, http.MethodPost, "/mcp", tc.token, tc.remote, mcpPing); w.Code != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, w.Code, tc.want)
		}
	}
	if len(m.callers) != 1 || m.callers[0] != "office" {
		t.Errorf("callers = %v, want [office]", m.callers)
	}
}

// TestMCPSharesCredentialGuessBudget proves /mcp and the API draw on one
// guess budget per client, so a client cannot double its guesses by
// splitting them across the two.
func TestMCPSharesCredentialGuessBudget(t *testing.T) {
	s := newMCPTestServer(t)
	m := &recordingMCP{}
	s.SetMCP(m)
	const client = "203.0.113.9:4000"
	for i := 0; i < credentialAttemptsPerMinute-2; i++ {
		if w := mcpRequest(s, http.MethodGet, "/api/v1/status", "wrong-api-guess-"+string(rune('a'+i)), client, ""); w.Code != http.StatusUnauthorized {
			t.Fatalf("API guess %d: %d", i, w.Code)
		}
	}
	for i := 0; i < 2; i++ {
		if w := mcpRequest(s, http.MethodPost, "/mcp", "wrong-mcp-guess-"+string(rune('a'+i)), client, mcpPing); w.Code != http.StatusUnauthorized {
			t.Fatalf("MCP guess %d: %d", i, w.Code)
		}
	}
	if w := mcpRequest(s, http.MethodPost, "/mcp", mcpTestToken, client, mcpPing); w.Code != http.StatusTooManyRequests {
		t.Errorf("valid token after the budget is spent: %d", w.Code)
	}
	if len(m.callers) != 0 {
		t.Errorf("a client past its budget reached the MCP server: %v", m.callers)
	}
	// A known token outside its dates is not a guess and spends nothing.
	const other = "203.0.113.10:4000"
	for i := 0; i < credentialAttemptsPerMinute+1; i++ {
		mcpRequest(s, http.MethodPost, "/mcp", mcpExpiredToken, other, mcpPing)
	}
	if w := mcpRequest(s, http.MethodPost, "/mcp", mcpTestToken, other, mcpPing); w.Code != http.StatusOK {
		t.Errorf("expired-token retries spent the budget: %d", w.Code)
	}
}

// TestMCPRefusesRebindingOrigin covers DNS rebinding: a page on a foreign
// name that resolves to this host sends its own name as both Origin and
// Host. Only the configured origin passes.
func TestMCPRefusesRebindingOrigin(t *testing.T) {
	s := newMCPTestServer(t)
	s.cfg.Hostname = "server.example"
	s.cfg.WebUI.Listen = "0.0.0.0:9443"
	m := &recordingMCP{}
	s.SetMCP(m)
	w := mcpRequest(s, http.MethodPost, "/mcp", mcpTestToken, "127.0.0.1:4000", mcpPing,
		"Origin", "https://evil.example:9443", "Host", "evil.example:9443")
	if w.Code != http.StatusForbidden {
		t.Errorf("rebinding origin: %d", w.Code)
	}
	if len(m.callers) != 0 {
		t.Errorf("rebinding origin reached the MCP server: %v", m.callers)
	}
	w = mcpRequest(s, http.MethodPost, "/mcp", mcpTestToken, "127.0.0.1:4000", mcpPing,
		"Origin", "https://server.example:9443", "Host", "server.example:9443")
	if w.Code != http.StatusOK {
		t.Errorf("configured origin: %d %s", w.Code, w.Body)
	}
}

// TestMCPEndToEnd drives the real MCP server over the Web UI handler chain
// with the real read-only dispatcher behind it.
func TestMCPEndToEnd(t *testing.T) {
	s := newMCPTestServer(t)
	s.cfg.Hostname = "e2e.example"
	s.SetVersion("e2e")
	s.SetMCP(mcp.New(mcp.Options{
		Dispatcher:    s.ReadOnly(),
		Version:       "e2e",
		Hostname:      s.cfg.Hostname,
		ConfigSummary: func() map[string]any { return map[string]any{"hostname": "e2e.example"} },
	}))
	call := func(payload string) map[string]any {
		t.Helper()
		w := mcpRequest(s, http.MethodPost, "/mcp", mcpTestToken, "127.0.0.1:4000", payload)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", payload, w.Code, w.Body)
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s: %v: %s", payload, err, w.Body)
		}
		if out["error"] != nil {
			t.Fatalf("%s: rpc error %v", payload, out["error"])
		}
		return out
	}
	call(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`)

	tools := call(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)["result"].(map[string]any)["tools"].([]any)
	listed := map[string]bool{}
	for _, tl := range tools {
		listed[tl.(map[string]any)["name"].(string)] = true
	}
	if want := len(s.ReadOnly().Routes()) + 3; len(listed) != want {
		t.Errorf("%d tools listed, want one per read-only route plus 3 composites (%d)", len(listed), want)
	}
	for _, name := range []string{"csm_health", "csm_status", "csm_lookup_ip", "csm_quarantine", "csm_email_queue"} {
		if !listed[name] {
			t.Errorf("tool %s missing", name)
		}
	}

	if text, isErr := mcpResultText(t, call(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"csm_health"}}`)); isErr || !strings.Contains(text, `"uptime_seconds"`) {
		t.Errorf("csm_health: isError=%v %s", isErr, text)
	}
	if text, isErr := mcpResultText(t, call(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"csm_overview"}}`)); isErr || !strings.Contains(text, `"hostname":"e2e.example"`) || !strings.Contains(text, `"capabilities"`) {
		t.Errorf("csm_overview: isError=%v %s", isErr, text)
	}
	if text, isErr := mcpResultText(t, call(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"csm_lookup_ip","arguments":{"ip":"203.0.113.9"}}}`)); isErr || !strings.Contains(text, `"ip":"203.0.113.9"`) {
		t.Errorf("csm_lookup_ip: isError=%v %s", isErr, text)
	}
	// A route's own validation comes back as a tool error, not a transport error.
	if _, isErr := mcpResultText(t, call(`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"csm_account","arguments":{"name":"../etc"}}}`)); !isErr {
		t.Error("csm_account with a bad name succeeded")
	}
}

func mcpResultText(t *testing.T, out map[string]any) (string, bool) {
	t.Helper()
	res, _ := out["result"].(map[string]any)
	content, _ := res["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("content: %v", out)
	}
	isErr, _ := res["isError"].(bool)
	return content[0].(map[string]any)["text"].(string), isErr
}
