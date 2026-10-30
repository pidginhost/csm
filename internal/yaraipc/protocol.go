// Package yaraipc defines the wire protocol spoken between the CSM daemon
// and the supervised `csm yara-worker` child process. The worker exists to
// isolate the YARA-X cgo surface; a crash in the worker must not take the
// daemon down. See ROADMAP.md item 2 for the decision record.
//
// The protocol is length-prefixed JSON frames on a Unix-domain socket.
// Connections are persistent: the daemon opens one, streams scan and
// reload requests, and reconnects if the worker dies.
package yaraipc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxFrameBytes caps a single request or response payload. Scanned bytes
// never travel in a frame: they come as a descriptor. The cap bounds what a
// confused or hostile peer can make the other side allocate.
const MaxFrameBytes = 16 << 20

// Op selects the handler on the worker side. Strings (not iota ints) so
// adding a new op is additive and mismatched client/worker versions fail
// with a recognisable "unknown op" error instead of silently dispatching
// the wrong handler.
const (
	OpReload = "reload"
	OpPing   = "ping"
	// OpScanFD scans the file passed as the request's one descriptor, so
	// the worker never opens a path and nothing is copied through JSON.
	OpScanFD = "scan_fd"
)

// ScanFDArgs bounds how much of the descriptor the worker reads. No name is
// sent: the archive-by-name skip is for files on disk, not mail parts.
//
// EmptyRulesClean keeps the old scan_bytes contract for byte scans: a worker
// with no rules and no compile error answers clean, as the in-process scanner
// does. Mail parts leave it unset, so a worker without rules fails them.
type ScanFDArgs struct {
	MaxBytes        int  `json:"max_bytes"`
	EmptyRulesClean bool `json:"empty_rules_clean,omitempty"`
}

// scanFDResult requires an explicit matches array, including for clean scans.
// An empty or unrelated worker reply must not stand in for a completed scan.
type scanFDResult struct {
	Matches []Match `json:"matches"`
}

// Frame is the envelope. Request frames carry an Op and typed args in
// Payload; response frames carry the typed result (or an Error) in
// Payload and leave Op empty.
type Frame struct {
	Op      string          `json:"op,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// ReloadArgs triggers a rule recompile. RulesDir is optional; if empty
// the worker reuses the directory it was started with.
type ReloadArgs struct {
	RulesDir string `json:"rules_dir,omitempty"`
}

// Match mirrors yara.Match but is part of this package's public wire
// contract so the daemon does not need to import the yara package just to
// speak to its worker.
//
// Meta carries string-valued rule metadata (identifier -> value) pulled
// from yara_x `rule.Metadata()` inside the worker, where the compiled
// rules live. Non-string metadata (int / float / bool / bytes) is
// dropped: wiring only string values is a deliberate policy, not a
// fidelity claim. Consumers that need a specific key document their own
// default; e.g. emailav maps a missing "severity" entry to "high".
// Omitted from the wire when empty so the per-scan payload cost is zero
// for the common clean-file case.
type Match struct {
	RuleName string            `json:"rule"`
	Meta     map[string]string `json:"meta,omitempty"`
}

// ScanResult is the outcome of a scan_fd request.
type ScanResult struct {
	Matches []Match `json:"matches,omitempty"`
}

// ReloadResult is returned for OpReload. CompileError is non-empty when the
// worker is up but its rules failed to compile, so the daemon can tell a
// successful reload (RuleCount>0) from a still-broken rule set instead of
// treating a silent no-op as success.
type ReloadResult struct {
	RuleCount    int    `json:"rule_count"`
	CompileError string `json:"compile_error,omitempty"`
}

// PingResult is returned for OpPing. Used by the supervisor's liveness
// check and as the first frame after a reconnect to confirm the worker is
// past its rule-compile step before real scan traffic begins.
//
// CompileError is non-empty when the worker process is alive but its rule
// compile failed at startup and has not yet been recovered by a reload. It
// disambiguates "0 rules because the compile broke" (needs an operator alert)
// from "0 rules because there is no engine / empty rules dir".
type PingResult struct {
	Alive        bool   `json:"alive"`
	RuleCount    int    `json:"rule_count"`
	CompileError string `json:"compile_error,omitempty"`
}

// WriteFrame writes a 4-byte big-endian length prefix followed by the
// JSON-encoded frame. The caller owns any deadline on the underlying
// writer.
func WriteFrame(w io.Writer, f Frame) error {
	body, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("marshal frame: %w", err)
	}
	if len(body) > MaxFrameBytes {
		return fmt.Errorf("frame body %d bytes exceeds cap %d", len(body), MaxFrameBytes)
	}
	var hdr [4]byte
	// #nosec G115 -- len(body) is bounded above by MaxFrameBytes (16 MiB), which fits in uint32.
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	return nil
}

// ReadFrame reads one length-prefixed JSON frame from r. Frames larger
// than MaxFrameBytes are rejected before the body is read so a hostile or
// corrupt peer cannot make us allocate an unbounded buffer.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return Frame{}, errors.New("yaraipc: zero-length frame")
	}
	if n > MaxFrameBytes {
		return Frame{}, fmt.Errorf("yaraipc: frame length %d exceeds cap %d", n, MaxFrameBytes)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return Frame{}, err
	}
	var f Frame
	if err := json.Unmarshal(body, &f); err != nil {
		return Frame{}, fmt.Errorf("yaraipc: unmarshal frame: %w", err)
	}
	return f, nil
}

// DecodePayload unmarshals f.Payload into out. Kept as a helper because
// every handler does it and a typo in the json tag on one side is the
// kind of bug that hides until production.
func DecodePayload(f Frame, out any) error {
	if len(f.Payload) == 0 {
		return errors.New("yaraipc: empty payload")
	}
	return json.Unmarshal(f.Payload, out)
}

// EncodePayload marshals v and returns a Frame with Op set. Convenience
// for the client side.
func EncodePayload(op string, v any) (Frame, error) {
	if v == nil {
		return Frame{Op: op}, nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return Frame{}, fmt.Errorf("yaraipc: marshal payload: %w", err)
	}
	return Frame{Op: op, Payload: raw}, nil
}
