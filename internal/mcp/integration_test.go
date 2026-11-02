package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mcp"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/webui"
)

const integrationToken = "integration-token-0123456789abcdef0123456789abcdef"

// TestEndToEndOverUnixSocket runs the real Web UI read-only dispatcher
// behind the MCP listener on a Unix socket and drives it over HTTP: the
// path a support agent on the host takes.
func TestEndToEndOverUnixSocket(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "e2e.example"}
	cfg.WebUI.Enabled = true
	cfg.WebUI.UIDir = filepath.Join(t.TempDir(), "ui-missing")
	cfg.WebUI.Tokens = []config.WebUIToken{{Name: "admin", Token: strings.Repeat("a", 48), Scope: "admin"}}
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	web, err := webui.New(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	web.SetVersion("e2e")

	// Socket paths have a short limit on some platforms; keep it short.
	sock := filepath.Join(shortTempDir(t), "m.sock")
	cfg.MCP = config.MCPConfig{Enabled: true, Listen: "unix:" + sock, Tokens: []config.MCPToken{{Name: "agent", Token: integrationToken}}}
	srv, err := mcp.New(mcp.Options{
		Config:        cfg.MCP,
		Dispatcher:    web.ReadOnly(),
		Version:       "e2e",
		Hostname:      cfg.Hostname,
		ConfigSummary: func() map[string]any { return map[string]any{"hostname": cfg.Hostname} },
	})
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		if err := <-errCh; err != nil {
			t.Errorf("server: %v", err)
		}
	})
	waitForSocket(t, sock)

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	call := func(payload string, token string) (int, map[string]any) {
		req, _ := http.NewRequest(http.MethodPost, "http://mcp/mcp", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(body, &out)
		return resp.StatusCode, out
	}

	if status, _ := call(`{"jsonrpc":"2.0","id":1,"method":"ping"}`, ""); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", status)
	}
	// A Web UI admin token does not open the MCP endpoint.
	if status, _ := call(`{"jsonrpc":"2.0","id":1,"method":"ping"}`, strings.Repeat("a", 48)); status != http.StatusUnauthorized {
		t.Fatalf("webui token accepted: %d", status)
	}
	status, out := call(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`, integrationToken)
	if status != 200 || out["error"] != nil {
		t.Fatalf("initialize: %d %v", status, out)
	}
	_, out = call(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, integrationToken)
	tools := out["result"].(map[string]any)["tools"].([]any)
	if len(tools) < 60 {
		t.Fatalf("only %d tools listed", len(tools))
	}
	for _, name := range []string{"csm_health", "csm_status", "csm_lookup_ip", "csm_quarantine", "csm_email_queue_message"} {
		if !hasTool(tools, name) {
			t.Errorf("tool %s missing", name)
		}
	}

	_, out = call(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"csm_health"}}`, integrationToken)
	text, isErr := resultText(t, out)
	if isErr || !strings.Contains(text, `"uptime_seconds"`) {
		t.Fatalf("csm_health: isError=%v %s", isErr, text)
	}
	_, out = call(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"csm_overview"}}`, integrationToken)
	text, isErr = resultText(t, out)
	if isErr || !strings.Contains(text, `"hostname":"e2e.example"`) || !strings.Contains(text, `"capabilities"`) {
		t.Fatalf("csm_overview: isError=%v %s", isErr, text)
	}
	_, out = call(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"csm_lookup_ip","arguments":{"ip":"203.0.113.9"}}}`, integrationToken)
	text, isErr = resultText(t, out)
	if isErr || !strings.Contains(text, `"ip":"203.0.113.9"`) {
		t.Fatalf("csm_lookup_ip: isError=%v %s", isErr, text)
	}
	// A route's own validation comes back as a tool error, not a transport error.
	_, out = call(`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"csm_account","arguments":{"name":"../etc"}}}`, integrationToken)
	if _, isErr := resultText(t, out); !isErr {
		t.Fatalf("csm_account with a bad name succeeded: %v", out)
	}
	// Nothing but POST /mcp exists on the listener.
	req, _ := http.NewRequest(http.MethodPost, "http://mcp/api/v1/block-ip", strings.NewReader(`{"ip":"203.0.113.9"}`))
	req.Header.Set("Authorization", "Bearer "+integrationToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("write route on the MCP listener: %d", resp.StatusCode)
	}
}

func hasTool(tools []any, name string) bool {
	for _, tl := range tools {
		if tl.(map[string]any)["name"] == name {
			return true
		}
	}
	return false
}

func resultText(t *testing.T, out map[string]any) (string, bool) {
	t.Helper()
	if out["error"] != nil {
		t.Fatalf("rpc error: %v", out["error"])
	}
	res, _ := out["result"].(map[string]any)
	content, _ := res["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("content: %v", out)
	}
	isErr, _ := res["isError"].(bool)
	return content[0].(map[string]any)["text"].(string), isErr
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("unix", path); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("socket %s did not come up", path)
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if len(dir) > 80 {
		// macOS temp dirs are long; fall back to /tmp with a unique name.
		dir = filepath.Join("/tmp", "csm-mcp-"+strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")))
		_ = removeAllIfOurs(dir)
		if err := mkdirAll(dir); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = removeAllIfOurs(dir) })
	}
	return dir
}
