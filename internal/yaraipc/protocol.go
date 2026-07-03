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

// MaxFrameBytes caps a single request or response payload. Sized to cover
// a file sent inline via OpScanBytes up to the scanner's usual 8 MiB read
// ceiling, with headroom for JSON base64 expansion.
const MaxFrameBytes = 16 << 20

// MaxScanBytes is the largest raw payload OpScanBytes can carry in one frame.
// A []byte is base64-encoded in JSON (4/3 expansion) plus a small envelope, so
// the raw ceiling sits well below MaxFrameBytes. Callers reject an oversize
// buffer up front with ErrPayloadTooLarge instead of marshalling a multi-MiB
// frame only to have WriteFrame fail -- and, crucially, an oversize payload
// must surface as an error, never be silently treated as a clean scan.
const MaxScanBytes = (MaxFrameBytes - 256) * 3 / 4

// ErrPayloadTooLarge is returned by the client when an inline OpScanBytes
// payload would not fit in a single protocol frame.
var ErrPayloadTooLarge = errors.New("yaraipc: scan payload exceeds max inline size")

// Op selects the handler on the worker side. Strings (not iota ints) so
// adding a new op is additive and mismatched client/worker versions fail
// with a recognisable "unknown op" error instead of silently dispatching
// the wrong handler.
const (
	OpScanFile  = "scan_file"
	OpScanBytes = "scan_bytes"
	OpReload    = "reload"
	OpPing      = "ping"
)

// Frame is the envelope. Request frames carry an Op and typed args in
// Payload; response frames carry the typed result (or an Error) in
// Payload and leave Op empty.
type Frame struct {
	Op      string          `json:"op,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// ScanFileArgs asks the worker to read and scan a file by path. MaxBytes
// bounds the read so the daemon cannot make the worker allocate more than
// it agreed to.
type ScanFileArgs struct {
	Path     string `json:"path"`
	MaxBytes int    `json:"max_bytes"`
}

// ScanBytesArgs carries file content inline. Used when the caller already
// has the bytes (fanotify buffered reads) and avoids a second file open in
// the worker.
type ScanBytesArgs struct {
	Data []byte `json:"data"`
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

// ScanResult is returned for OpScanFile and OpScanBytes.
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
