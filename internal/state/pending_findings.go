package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/atomicio"
)

const pendingFindingsFile = "pending_findings.json"

var removePendingFindingsFile = os.Remove

// pendingFindingsMax bounds the parked batch; a stop during a flood keeps the
// newest findings rather than growing the file without limit.
const pendingFindingsMax = 10000

// AppendPendingFindings parks findings that were still queued for dispatch
// when the daemon stopped. The next start takes them back and runs them
// through the full dispatch pipeline, so a realtime-only finding raised in the
// last seconds before a restart still triggers its auto-response instead of
// surviving only as a history line nothing re-detects. Shutdown drains the
// channel twice, so this appends rather than replaces.
func (s *Store) AppendPendingFindings(findings []alert.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, err := s.readPendingLocked()
	if err != nil {
		return err
	}
	pending = append(pending, findings...)
	if len(pending) > pendingFindingsMax {
		pending = pending[len(pending)-pendingFindingsMax:]
	}
	return atomicio.AtomicWriteJSON(filepath.Join(s.path, pendingFindingsFile), 0o600, pending)
}

// TakePendingFindings returns the parked findings and clears them, so a
// replay that itself gets interrupted cannot double-dispatch on the next
// start.
func (s *Store) TakePendingFindings() ([]alert.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, err := s.readPendingLocked()
	if err != nil {
		return nil, err
	}
	if err := removePendingFindingsFile(filepath.Join(s.path, pendingFindingsFile)); err != nil {
		if os.IsNotExist(err) && len(pending) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("clear pending findings: %w", err)
	}
	return pending, nil
}

func (s *Store) readPendingLocked() ([]alert.Finding, error) {
	data, err := os.ReadFile(filepath.Join(s.path, pendingFindingsFile)) // #nosec G304 -- fixed name under the state dir.
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read pending findings: %w", err)
	}
	var pending []alert.Finding
	if err := json.Unmarshal(data, &pending); err != nil {
		return nil, fmt.Errorf("decode pending findings: %w", err)
	}
	return pending, nil
}
