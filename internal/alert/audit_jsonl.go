package alert

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// JSONLSink appends one JSON object per finding to a file. Designed
// for SIEM ingest via standard log shippers (Vector, Filebeat,
// Fluentbit). Writes are mutex-serialised so concurrent emits cannot
// interleave bytes inside a single line; logrotate's copytruncate
// rotation works without daemon restart because the file's offset is
// reset by the truncate, which the open fd then writes past.
type JSONLSink struct {
	path string

	mu sync.Mutex
	f  *os.File
}

// NewJSONLSink opens (or creates) the JSONL file. Permissions are
// 0640 -- group-readable so an operator running a log shipper under
// a non-root user in the appropriate group can tail it. The parent
// directory is created with 0750 so packaging (logrotate) sees a
// reasonable default.
func NewJSONLSink(path string) (*JSONLSink, error) {
	if path == "" {
		return nil, errors.New("jsonl sink: path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, fmt.Errorf("jsonl sink: creating dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("jsonl sink: opening %s: %w", path, err)
	}
	return &JSONLSink{path: path, f: f}, nil
}

// Name returns the sink identifier used in error messages.
func (s *JSONLSink) Name() string { return "jsonl" }

// Emit appends one JSON line. The trailing newline is written as part
// of the same Write call so a partial write at EOL boundaries cannot
// leave a half-finished line in the file.
func (s *JSONLSink) Emit(event AuditEvent) error {
	line, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("jsonl sink: marshal: %w", err)
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return errors.New("jsonl sink: closed")
	}
	if _, err := s.f.Write(line); err != nil {
		return fmt.Errorf("jsonl sink: write: %w", err)
	}
	return nil
}

// Close releases the file descriptor. Safe to call multiple times.
func (s *JSONLSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}
