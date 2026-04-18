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
type Match struct {
	RuleName string `json:"rule"`
}

// ScanResult is returned for OpScanFile and OpScanBytes.
type ScanResult struct {
	Matches []Match `json:"matches,omitempty"`
}

// ReloadResult is returned for OpReload.
type ReloadResult struct {
	RuleCount int `json:"rule_count"`
}

// PingResult is returned for OpPing. Used by the supervisor's liveness
// check and as the first frame after a reconnect to confirm the worker is
// past its rule-compile step before real scan traffic begins.
type PingResult struct {
	Alive     bool `json:"alive"`
	RuleCount int  `json:"rule_count"`
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
