package state

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/atomicio"
)

const pendingFindingsFile = "pending_findings.json"

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
	pending := append(s.readPendingLocked(), findings...)
	if len(pending) > pendingFindingsMax {
		pending = pending[len(pending)-pendingFindingsMax:]
	}
	return atomicio.AtomicWriteJSON(filepath.Join(s.path, pendingFindingsFile), 0o600, pending)
}

// TakePendingFindings returns the parked findings and clears them, so a
// replay that itself gets interrupted cannot double-dispatch on the next
// start.
func (s *Store) TakePendingFindings() []alert.Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := s.readPendingLocked()
	_ = os.Remove(filepath.Join(s.path, pendingFindingsFile))
	return pending
}

func (s *Store) readPendingLocked() []alert.Finding {
	data, err := os.ReadFile(filepath.Join(s.path, pendingFindingsFile)) // #nosec G304 -- fixed name under the state dir.
	if err != nil {
		return nil
	}
	var pending []alert.Finding
	if err := json.Unmarshal(data, &pending); err != nil {
		return nil
	}
	return pending
}
