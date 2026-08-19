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
	"strings"

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

// EncodePayload validates and marshals v into a frame under op. AnalyzeArgs is
// size-checked here so an oversize source fails before it is ever encoded.
func EncodePayload(op string, v any) (Frame, error) {
	if v == nil {
		return Frame{Op: op}, nil
	}
	if err := validatePayload(v); err != nil {
		return Frame{}, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return Frame{}, fmt.Errorf("phptaintipc: marshal %s payload: %w", op, err)
	}
	return Frame{Op: op, Payload: raw}, nil
}

// DecodePayload unmarshals and validates a frame's payload into v.
func DecodePayload(f Frame, v any) error {
	if len(f.Payload) == 0 {
		return errors.New("phptaintipc: frame has no payload")
	}

	// Decode the security-sensitive payloads into fresh values. A missing JSON
	// field must not retain a prior request's source or a prior response's clean
	// status when a caller reuses storage across frames.
	switch out := v.(type) {
	case *AnalyzeArgs:
		if out == nil {
			return errors.New("phptaintipc: nil AnalyzeArgs decode target")
		}
		if _, err := requiredJSONField(f.Payload, "source"); err != nil {
			return err
		}
		var decoded AnalyzeArgs
		if err := json.Unmarshal(f.Payload, &decoded); err != nil {
			return fmt.Errorf("phptaintipc: unmarshal payload: %w", err)
		}
		if err := validatePayload(decoded); err != nil {
			return err
		}
		*out = decoded
		return nil
	case *AnalyzeResult:
		if out == nil {
			return errors.New("phptaintipc: nil AnalyzeResult decode target")
		}
		reportJSON, err := requiredJSONField(f.Payload, "report")
		if err != nil {
			return err
		}
		statusJSON, err := requiredJSONField(reportJSON, "status")
		if err != nil {
			return err
		}
		var status *phptaint.Status
		if err := json.Unmarshal(statusJSON, &status); err != nil {
			return fmt.Errorf("phptaintipc: unmarshal report status: %w", err)
		}
		if status == nil {
			return errors.New("phptaintipc: report status is null")
		}
		var decoded AnalyzeResult
		if err := json.Unmarshal(f.Payload, &decoded); err != nil {
			return fmt.Errorf("phptaintipc: unmarshal payload: %w", err)
		}
		if decoded.Report.Status != *status {
			return errors.New("phptaintipc: ambiguous report status")
		}
		if err := validatePayload(decoded); err != nil {
			return err
		}
		*out = decoded
		return nil
	}

	if err := json.Unmarshal(f.Payload, v); err != nil {
		return fmt.Errorf("phptaintipc: unmarshal payload: %w", err)
	}
	return nil
}

func validatePayload(v any) error {
	switch payload := v.(type) {
	case AnalyzeArgs:
		return validateSourceSize(payload.Source)
	case *AnalyzeArgs:
		if payload == nil {
			return errors.New("phptaintipc: nil AnalyzeArgs payload")
		}
		return validateSourceSize(payload.Source)
	case AnalyzeResult:
		return validateReport(payload.Report)
	case *AnalyzeResult:
		if payload == nil {
			return errors.New("phptaintipc: nil AnalyzeResult payload")
		}
		return validateReport(payload.Report)
	}
	return nil
}

func validateSourceSize(source []byte) error {
	if len(source) > phptaint.MaxSourceBytes {
		return fmt.Errorf("%w (%d > %d bytes)", ErrSourceTooLarge, len(source), phptaint.MaxSourceBytes)
	}
	return nil
}

func validateReport(report phptaint.Report) error {
	if report.Status.String() == "unknown" {
		return fmt.Errorf("phptaintipc: unknown report status %d", report.Status)
	}

	hasEvidence := len(report.Results) != 0 || report.TotalResults != 0 ||
		len(report.PrecisionLoss) != 0 || report.EvidenceTruncated
	switch report.Status {
	case phptaint.StatusNotCandidate:
		if hasEvidence || report.Reason != "" {
			return errors.New("phptaintipc: not-candidate report carries analysis data")
		}
	case phptaint.StatusAnalyzed:
		if report.Reason != "" {
			return errors.New("phptaintipc: analyzed report carries an error reason")
		}
		if report.TotalResults < 0 || report.TotalResults < len(report.Results) {
			return errors.New("phptaintipc: analyzed report has inconsistent result counts")
		}
	default:
		if hasEvidence {
			return errors.New("phptaintipc: incomplete report carries analysis data")
		}
		if report.Reason == "" {
			return errors.New("phptaintipc: incomplete report has no reason")
		}
	}
	if len(report.Reason) > phptaint.MaxReasonBytes {
		return fmt.Errorf("phptaintipc: report reason is %d bytes, exceeds cap %d", len(report.Reason), phptaint.MaxReasonBytes)
	}
	return nil
}

func requiredJSONField(raw []byte, name string) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("phptaintipc: inspect %s field: %w", name, err)
	}
	var found json.RawMessage
	for field, value := range fields {
		if !strings.EqualFold(field, name) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("phptaintipc: payload has ambiguous %s fields", name)
		}
		found = value
	}
	if found == nil {
		return nil, fmt.Errorf("phptaintipc: payload has no %s field", name)
	}
	return found, nil
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
