package alert

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// AuditSchemaVersion is the value emitted in every AuditEvent's "v"
// field. Frozen contract -- downstream JSONL / syslog parsers pin on
// it. Bump only on incompatible schema changes; additive fields stay
// at the same version.
const AuditSchemaVersion = 1

// AuditEvent is the wire-stable shape every audit-log sink emits. JSON
// keys match what downstream SIEMs expect; fields are added at the
// end so older parsers ignore unknown ones.
type AuditEvent struct {
	V         int       `json:"v"`
	Timestamp time.Time `json:"ts"`
	FindingID string    `json:"finding_id"`
	Severity  string    `json:"severity"`
	Check     string    `json:"check"`
	Message   string    `json:"message"`
	Details   string    `json:"details,omitempty"`
	FilePath  string    `json:"file_path,omitempty"`
	Hostname  string    `json:"hostname"`
}

// AuditSink is what every audit-log destination implements. Emit must
// be safe for concurrent calls; the alert dispatcher fans out to
// multiple sinks per finding.
type AuditSink interface {
	// Name identifies the sink for diagnostics (e.g. "jsonl", "syslog").
	Name() string

	// Emit ships one event. Should return promptly; sinks that need
	// long-haul I/O are expected to handle their own buffering.
	Emit(event AuditEvent) error

	// Close releases any held resources. Safe to call multiple times.
	Close() error
}

// NewAuditEvent builds a versioned audit event from a Finding. hostname
// comes from cfg.Hostname (or os.Hostname() fallback); the caller is
// responsible for picking a stable value across emits.
func NewAuditEvent(hostname string, f Finding) AuditEvent {
	return AuditEvent{
		V:         AuditSchemaVersion,
		Timestamp: f.Timestamp.UTC(),
		FindingID: makeFindingID(f),
		Severity:  f.Severity.String(),
		Check:     f.Check,
		Message:   f.Message,
		Details:   f.Details,
		FilePath:  f.FilePath,
		Hostname:  hostname,
	}
}

// makeFindingID hashes the canonical fields of a Finding to a stable
// 16-hex-char ID. Two emits of the same finding (same timestamp + the
// same other fields) produce the same ID, so downstream dedup works
// across re-runs.
//
// The hash inputs use a "|" separator so the byte-for-byte
// concatenation cannot collide via field-boundary ambiguity (e.g. a
// Check name that ends in the same chars another field starts with).
func makeFindingID(f Finding) string {
	h := sha256.New()
	_, _ = h.Write([]byte(f.Timestamp.UTC().Format(time.RFC3339Nano)))
	_, _ = h.Write([]byte("|"))
	_, _ = h.Write([]byte(f.Check))
	_, _ = h.Write([]byte("|"))
	_, _ = h.Write([]byte(f.Severity.String()))
	_, _ = h.Write([]byte("|"))
	_, _ = h.Write([]byte(f.Message))
	_, _ = h.Write([]byte("|"))
	_, _ = h.Write([]byte(f.FilePath))
	return hex.EncodeToString(h.Sum(nil))[:16]
}
