// Package phptaintipc defines the wire protocol spoken between the CSM daemon
// and the supervised `csm phptaint-worker` child process.
//
// The worker exists because the PHP parser this analyzer depends on can enter
// an infinite loop on attacker-controlled input. Two such inputs are known and
// there is no reason to believe they are the only ones: it is a hand-written
// lexer in an unmaintained package, and the second class was found outside a
// search that had concluded the first was the only one. A loop is not a panic,
// so recover() cannot catch it, and the parser never checks context, so a
// deadline around the call cannot stop it either. The only thing that reliably
// stops it is killing the process it runs in -- which is what the supervisor on
// the other side of this protocol does, and why analysis runs out of process at
// all.
//
// The protocol is length-prefixed JSON frames over private pipes. Pipes rather
// than a Unix socket: the daemon runs under ProtectSystem=strict, and a pipe
// inherited across fork needs no socket path and so no new writable directory.
//
// Frames carry phptaint's own Report type rather than a restatement of it.
// Worker and daemon are the same binary, so the two definitions can never
// disagree, and a translation layer could only introduce drift. That matters
// more here than it looks: an unmapped status would decode as the zero value,
// which is StatusNotCandidate -- "this file is clean". A coverage gap silently
// becoming a clean result is the one failure this package must not have.
package phptaintipc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/pidginhost/csm/internal/phptaint"
)

// MaxFrameBytes caps a single request or response body. The largest legitimate
// frame is an analyze request carrying phptaint.MaxSourceBytes of source, which
// JSON base64-encodes at 4/3 expansion, plus envelope. Responses are far
// smaller: a Report's evidence is already bounded by phptaint itself.
const MaxFrameBytes = 8 << 20

// Op selects the handler on the worker side. Strings rather than iota ints so
// an unrecognised op is reported as such instead of silently matching whatever
// constant happens to share its number.
const (
	OpAnalyze = "analyze"
	OpPing    = "ping"
)

// ErrSourceTooLarge is returned when a source buffer exceeds what phptaint
// would analyze anyway. Rejecting it here keeps the ceiling in one place and
// avoids marshalling a multi-megabyte frame only to have the worker decline it.
var ErrSourceTooLarge = errors.New("phptaintipc: source exceeds maximum analyzed size")

// Frame is the envelope. A request carries an Op and a typed Payload; a
// response leaves Op empty and carries either a Payload or an Error.
type Frame struct {
	Op      string          `json:"op,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// AnalyzeArgs carries the bytes to analyze. The daemon has already read the
// file and run the pre-filter, so only admitted content crosses the boundary,
// and the worker is never given a path to open on its own.
type AnalyzeArgs struct {
	Source []byte `json:"source"`
}

// AnalyzeResult carries the completed report.
type AnalyzeResult struct {
	Report phptaint.Report `json:"report"`
}

// PingResult answers a readiness probe.
type PingResult struct {
	OK bool `json:"ok"`
}

// EncodePayload marshals v into a frame under op. AnalyzeArgs is size-checked
// here so an oversize source fails before it is ever encoded.
func EncodePayload(op string, v any) (Frame, error) {
	if args, ok := v.(AnalyzeArgs); ok && len(args.Source) > phptaint.MaxSourceBytes {
		return Frame{}, fmt.Errorf("%w (%d > %d bytes)", ErrSourceTooLarge, len(args.Source), phptaint.MaxSourceBytes)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return Frame{}, fmt.Errorf("phptaintipc: marshal %s payload: %w", op, err)
	}
	return Frame{Op: op, Payload: raw}, nil
}

// DecodePayload unmarshals a frame's payload into v.
func DecodePayload(f Frame, v any) error {
	if len(f.Payload) == 0 {
		return errors.New("phptaintipc: frame has no payload")
	}
	if err := json.Unmarshal(f.Payload, v); err != nil {
		return fmt.Errorf("phptaintipc: unmarshal payload: %w", err)
	}
	return nil
}

// WriteFrame writes one length-prefixed frame.
func WriteFrame(w io.Writer, f Frame) error {
	body, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("phptaintipc: marshal frame: %w", err)
	}
	if len(body) > MaxFrameBytes {
		return fmt.Errorf("phptaintipc: frame body %d bytes exceeds cap %d", len(body), MaxFrameBytes)
	}
	var hdr [4]byte
	// #nosec G115 -- len(body) is bounded above by MaxFrameBytes, which fits in uint32.
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("phptaintipc: write header: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("phptaintipc: write body: %w", err)
	}
	return nil
}

// ReadFrame reads one length-prefixed frame.
//
// The length prefix comes from the peer, so it is checked against the cap
// BEFORE any buffer is allocated. Reading the declared size first and
// validating afterwards would let a four-byte write ask for gigabytes.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, fmt.Errorf("phptaintipc: read header: %w", err)
	}
	size := binary.BigEndian.Uint32(hdr[:])
	if size > MaxFrameBytes {
		return Frame{}, fmt.Errorf("phptaintipc: declared frame size %d exceeds cap %d", size, MaxFrameBytes)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return Frame{}, fmt.Errorf("phptaintipc: read body: %w", err)
	}
	var f Frame
	if err := json.Unmarshal(body, &f); err != nil {
		return Frame{}, fmt.Errorf("phptaintipc: unmarshal frame: %w", err)
	}
	return f, nil
}
