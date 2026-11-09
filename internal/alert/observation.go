package alert

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// Observation names where a finding was read: the producer that read it,
// the stream (a log file, or a journal), the position of the triggering
// record in that stream, and when it was observed. Admission mints evidence
// from it; the zero value means the producer has none.
type Observation struct {
	Producer   string    `json:"producer"`
	Stream     string    `json:"stream"`
	Cursor     string    `json:"cursor"`
	ObservedAt time.Time `json:"observed_at"`
}

// FileStream names a log file by device and inode. It depends on the file
// alone, so every reader of a file names it alike, across restarts.
func FileStream(dev, ino uint64) string {
	return "f:" + strconv.FormatUint(dev, 16) + ":" + strconv.FormatUint(ino, 16)
}

// RecordCursor names one record of a file stream by its start offset and its
// bytes, so a record rewritten at a reused offset is never an earlier one,
// while the same bytes read again keep their cursor. record is the line as
// read, with or without its line ending.
func RecordCursor(offset int64, record string) string {
	record = strings.TrimRight(strings.TrimSuffix(record, "\n"), "\r")
	sum := sha256.Sum256([]byte(record))
	var buf [20 + 1 + 16]byte
	b := strconv.AppendInt(buf[:0], offset, 10)
	b = append(b, ':')
	return string(hex.AppendEncode(b, sum[:8]))
}
