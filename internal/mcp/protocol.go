// Package mcp serves a read-only Model Context Protocol endpoint for support
// agents. It speaks JSON-RPC 2.0 over the MCP Streamable HTTP transport on
// a listener of its own, authenticates against mcp.tokens, and answers every
// tool call by dispatching a GET to an allowlisted API read in-process. It
// holds no route that changes anything.
package mcp

import (
	"encoding/json"
)

// Protocol versions this server accepts, newest first. initialize answers
// the client's version when it is listed and the newest otherwise.
var protocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// ServerName is the name sent in initialize.
const ServerName = "csm"

// JSON-RPC 2.0 error codes.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// isNotification reports whether the request carries no id. A notification
// gets no response.
func (r rpcRequest) isNotification() bool {
	return len(r.ID) == 0 || string(r.ID) == "null"
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func newResult(id json.RawMessage, result any) rpcResponse {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func newError(id json.RawMessage, code int, message string) rpcResponse {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message}}
}

type initializeParams struct {
	ProtocolVersion string `json:"protocolVersion"`
}

type toolsCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// content is one MCP content block; this server sends text only.
type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolResult struct {
	Content []content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

func textResult(text string) toolResult {
	return toolResult{Content: []content{{Type: "text", Text: text}}}
}

func errorResult(text string) toolResult {
	return toolResult{Content: []content{{Type: "text", Text: text}}, IsError: true}
}

// toolAnnotations is the MCP hint block. Every tool here is read-only and
// idempotent; the dispatcher makes that true by construction.
type toolAnnotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    bool   `json:"readOnlyHint"`
	DestructiveHint bool   `json:"destructiveHint"`
	IdempotentHint  bool   `json:"idempotentHint"`
	OpenWorldHint   bool   `json:"openWorldHint"`
}

type toolDescriptor struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema map[string]any  `json:"inputSchema"`
	Annotations toolAnnotations `json:"annotations"`
}

func supportedProtocol(v string) bool {
	for _, p := range protocolVersions {
		if p == v {
			return true
		}
	}
	return false
}
