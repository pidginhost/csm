package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDispatcher records every dispatch and answers canned JSON. It fails
// the test on anything that is not one of its routes, as the real one does.
type fakeDispatcher struct {
	mu     sync.Mutex
	calls  []fakeCall
	routes map[string]string // path -> JSON body
	status map[string]int
	block  chan struct{}
	huge   bool
	// deadlines holds the context deadline each dispatch ran under.
	deadlines []time.Time
}

type fakeCall struct {
	path  string
	query url.Values
	peer  string
}

type truncatedErr struct{}

func (truncatedErr) Error() string   { return "cut" }
func (truncatedErr) Truncated() bool { return true }

func (f *fakeDispatcher) Routes() []string {
	var out []string
	for p := range f.routes {
		out = append(out, p)
	}
	return out
}

func (f *fakeDispatcher) Dispatch(ctx context.Context, path string, query url.Values, peer string) (int, string, []byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, fakeCall{path, query, peer})
	if dl, ok := ctx.Deadline(); ok {
		f.deadlines = append(f.deadlines, dl)
	}
	f.mu.Unlock()
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return 0, "", nil, ctx.Err()
		}
	}
	pattern := path
	for p := range f.routes {
		if strings.Contains(p, "{id}") && strings.HasPrefix(path, strings.SplitN(p, "{id}", 2)[0]) {
			pattern = p
		}
	}
	body, ok := f.routes[pattern]
	if !ok {
		return 0, "", nil, errors.New("not a read-only route")
	}
	if f.huge {
		return 200, "application/json", []byte(body), truncatedErr{}
	}
	status := 200
	if s, ok := f.status[pattern]; ok {
		status = s
	}
	return status, "application/json; charset=utf-8", []byte(body), nil
}

func newFake() *fakeDispatcher {
	return &fakeDispatcher{
		routes: map[string]string{
			"/api/v1/status":         `{"version":"test","security_posture":"healthy"}`,
			"/api/v1/health":         `{"uptime_seconds":5}`,
			"/api/v1/capabilities":   `{"items":["mcp.readonly.v1"]}`,
			"/api/v1/firewall/check": `{"blocked":false}`,
			"/api/v1/threat/ip":      `{"ip":"203.0.113.9","attacks":2}`,
			"/api/v1/geoip":          `{"country":"RO"}`,
			"/api/v1/blocked-ips":    `{"items":[{"ip":"203.0.113.9","reason":"test"}],"total":1}`,
			"/api/v1/history":        `{"items":[],"total":0}`,
			"/api/v1/incidents/{id}": `{"id":"abc"}`,
			"/api/v1/account":        `{"error":"account not found"}`,
		},
		status: map[string]int{"/api/v1/account": 404},
	}
}

func newTestServer(t *testing.T, d Dispatcher) *Server {
	t.Helper()
	return New(Options{
		Dispatcher:    d,
		Version:       "9.9.9",
		Hostname:      "host.example",
		Platform:      map[string]any{"panel": "cpanel"},
		ConfigSummary: func() map[string]any { return map[string]any{"mode": "standard"} },
	})
}

type rpcCall struct {
	status int
	body   []byte
	resp   rpcResponse
}

// post sends payload to ServeMCP as the Web UI does after authenticating
// the request.
func post(t *testing.T, s *Server, payload any, headers ...string) rpcCall {
	t.Helper()
	var body []byte
	switch v := payload.(type) {
	case string:
		body = []byte(v)
	default:
		body, _ = json.Marshal(v)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:4000"
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	s.ServeMCP(w, req, "agent")
	out := rpcCall{status: w.Code, body: w.Body.Bytes()}
	_ = json.Unmarshal(out.body, &out.resp)
	return out
}

func rpc(id int, method string, params any) map[string]any {
	m := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		m["params"] = params
	}
	return m
}

func toolText(t *testing.T, c rpcCall) (string, bool) {
	t.Helper()
	if c.resp.Error != nil {
		t.Fatalf("rpc error: %+v (%s)", c.resp.Error, c.body)
	}
	raw, _ := json.Marshal(c.resp.Result)
	var res toolResult
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("result is not a tool result: %v: %s", err, raw)
	}
	if len(res.Content) != 1 || res.Content[0].Type != "text" {
		t.Fatalf("content: %+v", res.Content)
	}
	return res.Content[0].Text, res.IsError
}

func TestInitializeAndToolsList(t *testing.T) {
	s := newTestServer(t, newFake())
	c := post(t, s, rpc(1, "initialize", map[string]any{"protocolVersion": "2025-03-26"}))
	if c.status != 200 || c.resp.Error != nil {
		t.Fatalf("initialize: %d %s", c.status, c.body)
	}
	res := c.resp.Result.(map[string]any)
	if res["protocolVersion"] != "2025-03-26" {
		t.Errorf("protocolVersion = %v", res["protocolVersion"])
	}
	if _, ok := res["capabilities"].(map[string]any)["tools"]; !ok {
		t.Errorf("tools capability missing: %v", res)
	}
	c = post(t, s, rpc(2, "initialize", map[string]any{"protocolVersion": "1999-01-01"}))
	if v := c.resp.Result.(map[string]any)["protocolVersion"]; v != protocolVersions[0] {
		t.Errorf("unknown client version answered %v", v)
	}

	c = post(t, s, rpc(3, "tools/list", nil))
	raw, _ := json.Marshal(c.resp.Result)
	var list struct {
		Tools []toolDescriptor `json:"tools"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	names := map[string]toolDescriptor{}
	for _, d := range list.Tools {
		names[d.Name] = d
		if !d.Annotations.ReadOnlyHint || d.Annotations.DestructiveHint {
			t.Errorf("%s is not annotated read-only", d.Name)
		}
		if d.InputSchema["type"] != "object" {
			t.Errorf("%s schema: %v", d.Name, d.InputSchema)
		}
	}
	// Route tools appear only for routes the dispatcher serves; composites always.
	for _, want := range []string{"csm_status", "csm_history", "csm_incident", "csm_overview", "csm_lookup_ip", "csm_config_summary"} {
		if _, ok := names[want]; !ok {
			t.Errorf("tool %s missing", want)
		}
	}
	if _, ok := names["csm_quarantine"]; ok {
		t.Errorf("csm_quarantine listed although the dispatcher does not serve its route")
	}
	req := names["csm_lookup_ip"].InputSchema["required"].([]any)
	if len(req) != 1 || req[0] != "ip" {
		t.Errorf("csm_lookup_ip required = %v", req)
	}
}

func TestToolCallDispatchesGETOnly(t *testing.T) {
	fake := newFake()
	s := newTestServer(t, fake)
	c := post(t, s, rpc(1, "tools/call", map[string]any{"name": "csm_history", "arguments": map[string]any{"limit": 5, "severity": "HIGH"}}))
	text, isErr := toolText(t, c)
	if isErr || text != `{"items":[],"total":0}` {
		t.Fatalf("history: isError=%v text=%s", isErr, text)
	}
	if len(fake.calls) != 1 || fake.calls[0].path != "/api/v1/history" {
		t.Fatalf("calls: %+v", fake.calls)
	}
	q := fake.calls[0].query
	if q.Get("limit") != "5" || q.Get("severity") != "HIGH" {
		t.Errorf("query: %v", q)
	}
	if fake.calls[0].peer != "127.0.0.1:4000" {
		t.Errorf("peer: %q", fake.calls[0].peer)
	}
}

func TestToolCallPathValue(t *testing.T) {
	fake := newFake()
	s := newTestServer(t, fake)
	c := post(t, s, rpc(1, "tools/call", map[string]any{"name": "csm_incident", "arguments": map[string]any{"id": "abc"}}))
	text, isErr := toolText(t, c)
	if isErr || text != `{"id":"abc"}` {
		t.Fatalf("incident: %v %s", isErr, text)
	}
	if fake.calls[0].path != "/api/v1/incidents/abc" {
		t.Errorf("path: %s", fake.calls[0].path)
	}
	// A path-traversal id never reaches the dispatcher.
	c = post(t, s, rpc(2, "tools/call", map[string]any{"name": "csm_incident", "arguments": map[string]any{"id": "../fix"}}))
	if _, isErr := toolText(t, c); !isErr {
		t.Errorf("traversal id accepted")
	}
	if len(fake.calls) != 1 {
		t.Errorf("traversal id dispatched: %+v", fake.calls)
	}
}

func TestToolCallArgumentValidation(t *testing.T) {
	s := newTestServer(t, newFake())
	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{"csm_lookup_ip", map[string]any{}, `"ip" is required`},
		{"csm_history", map[string]any{"bogus": 1}, "unknown argument"},
		{"csm_history", map[string]any{"limit": []int{1}}, "must be a scalar"},
	}
	for _, tc := range cases {
		c := post(t, s, rpc(1, "tools/call", map[string]any{"name": tc.name, "arguments": tc.args}))
		if c.resp.Error == nil || !strings.Contains(c.resp.Error.Message, tc.want) {
			t.Errorf("%s %v: got %+v, want %q", tc.name, tc.args, c.resp.Error, tc.want)
		}
	}
	c := post(t, s, rpc(1, "tools/call", map[string]any{"name": "csm_block_ip", "arguments": map[string]any{"ip": "203.0.113.9"}}))
	if c.resp.Error == nil || c.resp.Error.Code != codeInvalidParams {
		t.Errorf("unknown tool: %+v", c.resp.Error)
	}
}

func TestRouteErrorBecomesToolError(t *testing.T) {
	s := newTestServer(t, newFake())
	c := post(t, s, rpc(1, "tools/call", map[string]any{"name": "csm_account", "arguments": map[string]any{"name": "nobody"}}))
	text, isErr := toolText(t, c)
	if !isErr || text != "account not found" {
		t.Errorf("isError=%v text=%q", isErr, text)
	}
}

func TestTruncatedResponseAsksToNarrow(t *testing.T) {
	fake := newFake()
	fake.huge = true
	s := newTestServer(t, fake)
	c := post(t, s, rpc(1, "tools/call", map[string]any{"name": "csm_history"}))
	text, isErr := toolText(t, c)
	if !isErr || !strings.Contains(text, "narrow") {
		t.Errorf("isError=%v text=%q", isErr, text)
	}
}

func TestCompositeTools(t *testing.T) {
	fake := newFake()
	s := newTestServer(t, fake)
	c := post(t, s, rpc(1, "tools/call", map[string]any{"name": "csm_lookup_ip", "arguments": map[string]any{"ip": "203.0.113.9"}}))
	text, isErr := toolText(t, c)
	if isErr {
		t.Fatalf("lookup: %s", text)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	if out["blocked"].(map[string]any)["reason"] != "test" {
		t.Errorf("blocked entry: %v", out["blocked"])
	}
	if out["geoip"].(map[string]any)["country"] != "RO" || out["threat"] == nil || out["firewall"] == nil {
		t.Errorf("lookup: %v", out)
	}
	for _, call := range fake.calls {
		if call.path != "/api/v1/blocked-ips" && call.query.Get("ip") != "203.0.113.9" {
			t.Errorf("call %s without ip: %v", call.path, call.query)
		}
	}

	c = post(t, s, rpc(2, "tools/call", map[string]any{"name": "csm_overview"}))
	text, isErr = toolText(t, c)
	if isErr {
		t.Fatalf("overview: %s", text)
	}
	out = nil
	_ = json.Unmarshal([]byte(text), &out)
	if out["hostname"] != "host.example" || out["version"] != "9.9.9" || out["status"] == nil || out["platform"].(map[string]any)["panel"] != "cpanel" {
		t.Errorf("overview: %v", out)
	}

	c = post(t, s, rpc(3, "tools/call", map[string]any{"name": "csm_config_summary"}))
	text, isErr = toolText(t, c)
	if isErr || text != `{"mode":"standard"}` {
		t.Errorf("config summary: %v %s", isErr, text)
	}
}

func TestTransportRules(t *testing.T) {
	s := newTestServer(t, newFake())
	if c := post(t, s, rpc(1, "ping", nil), "MCP-Protocol-Version", "2000-01-01"); c.status != http.StatusBadRequest {
		t.Errorf("bad protocol version: %d", c.status)
	}
	if c := post(t, s, rpc(1, "ping", nil), "MCP-Protocol-Version", "2025-06-18"); c.status != 200 {
		t.Errorf("good protocol version: %d", c.status)
	}
	if c := post(t, s, strings.Repeat("x", maxBodyBytes+1)); c.status != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: %d", c.status)
	}
	if c := post(t, s, "{not json"); c.resp.Error == nil || c.resp.Error.Code != codeParse {
		t.Errorf("parse error: %+v", c.resp)
	}
	if c := post(t, s, rpc(1, "no/such", nil)); c.resp.Error == nil || c.resp.Error.Code != codeMethodNotFound {
		t.Errorf("unknown method: %+v", c.resp)
	}
	// Notifications get 202 and no body.
	c := post(t, s, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	if c.status != http.StatusAccepted || len(c.body) != 0 {
		t.Errorf("notification: %d %q", c.status, c.body)
	}
	// Batches answer a batch; notifications inside are dropped.
	c = post(t, s, []any{rpc(1, "ping", nil), map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, rpc(2, "tools/list", nil)})
	var batch []rpcResponse
	if err := json.Unmarshal(c.body, &batch); err != nil || len(batch) != 2 {
		t.Errorf("batch: %v %s", err, c.body)
	}
	for _, m := range []string{"resources/list", "prompts/list"} {
		if c := post(t, s, rpc(1, m, nil)); c.resp.Error != nil {
			t.Errorf("%s: %+v", m, c.resp.Error)
		}
	}
}

func TestCallWaitsForDispatcher(t *testing.T) {
	fake := newFake()
	fake.block = make(chan struct{})
	s := newTestServer(t, fake)
	done := make(chan rpcCall, 1)
	go func() { done <- post(t, s, rpc(1, "tools/call", map[string]any{"name": "csm_status"})) }()
	select {
	case <-done:
		t.Fatal("call returned while the dispatcher was blocked")
	case <-time.After(100 * time.Millisecond):
	}
	close(fake.block)
	c := <-done
	if _, isErr := toolText(t, c); isErr {
		t.Errorf("unblocked call failed: %s", c.body)
	}
}

// TestBatchSharesOneDeadline bounds a whole request, a batch included, by
// one deadline. With a timeout per call, a batch of slow calls outlived the
// listener's write timeout: the answer was lost while the calls went on.
func TestBatchSharesOneDeadline(t *testing.T) {
	fake := newFake()
	s := newTestServer(t, fake)
	start := time.Now()
	c := post(t, s, []any{
		rpc(1, "tools/call", map[string]any{"name": "csm_status"}),
		rpc(2, "tools/call", map[string]any{"name": "csm_health"}),
		rpc(3, "tools/call", map[string]any{"name": "csm_history"}),
	})
	if c.status != http.StatusOK {
		t.Fatalf("batch: %d %s", c.status, c.body)
	}
	if len(fake.deadlines) != 3 {
		t.Fatalf("%d of 3 dispatches ran under a deadline", len(fake.deadlines))
	}
	for i, dl := range fake.deadlines {
		if !dl.Equal(fake.deadlines[0]) {
			t.Errorf("call %d deadline %v differs from the first call's %v", i, dl, fake.deadlines[0])
		}
		if dl.Sub(start) > requestTimeout+time.Second {
			t.Errorf("call %d deadline is %v after the request started", i, dl.Sub(start))
		}
	}
}
