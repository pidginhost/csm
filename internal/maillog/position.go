package maillog

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Position names where a mail log line was read: the stream (one generation
// of the log file, or the journal), the line's place in it, and when it was
// observed. An empty Stream means the reader has no position for the line.
type Position struct {
	Stream     string
	Cursor     string
	ObservedAt time.Time
}

// journalCursor encodes a journald cursor as a bounded token. systemd treats
// cursors as opaque, and a busy host's cursor outgrows the evidence bound, so
// a hash of the whole cursor names the entry.
func journalCursor(raw string) string {
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(raw))
	return "jc1:" + hex.EncodeToString(sum[:16])
}
