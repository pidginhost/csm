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
	call := s.pendingHealth().begin(len(findings))
	defer call.finish()
	s.mu.Lock()
	defer s.mu.Unlock()
	defer call.settleIO()
	call.start()
	pending, err := s.readPendingLocked(call)
	if err != nil {
		return err
	}
	old := pendingIdentity(pending)
	call.observe(old)
	total := len(pending) + len(findings)
	pending = append(pending, findings...)
	if len(pending) > pendingFindingsMax {
		pending = pending[len(pending)-pendingFindingsMax:]
	}
	next := pendingIdentity(pending)
	ages := call.appendedAges(old.count, len(pending))
	write := s.writePendingFile
	if write == nil {
		write = atomicio.AtomicWriteJSON
	}
	knownLoss := max(0, len(findings)-pendingFindingsMax)
	if !next.valid {
		knownLoss = len(findings)
	}
	call.offer(knownLoss)
	err = write(filepath.Join(s.path, pendingFindingsFile), 0o600, pending)
	if err == nil {
		call.complete(next, total-len(pending), false, ages)
		return nil
	}
	call.ioFailed()
	actual, readErr := s.readPendingLocked(call)
	if readErr != nil {
		return err
	}
	image := pendingIdentity(actual)
	switch {
	case image.valid && image == old:
		call.complete(image, len(findings), true, nil)
	case image.valid && next.valid && image == next:
		call.complete(image, total-len(pending), true, ages)
	default:
		call.unreadable(call.lost)
		call.observe(image)
	}
	return err
}

// TakePendingFindings returns the parked findings and clears them, so a
// replay that itself gets interrupted cannot double-dispatch on the next start.
func (s *Store) TakePendingFindings() ([]alert.Finding, error) {
	call := s.pendingHealth().begin(0)
	defer call.finish()
	findings, err := s.takePendingFindings(call)
	if err == nil {
		call.finishReplay()
	}
	return findings, err
}

// ReplayPendingFindings keeps the cleared batch owned through dispatch. The
// callback runs without the state lock; later shutdown appends stay independent.
func (s *Store) ReplayPendingFindings(consume func([]alert.Finding)) error {
	call := s.pendingHealth().begin(0)
	defer call.finish()
	pending, err := s.takePendingFindings(call)
	if err != nil {
		return err
	}
	if len(pending) > 0 {
		consume(pending)
	}
	call.finishReplay()
	return nil
}

func (s *Store) takePendingFindings(call *pendingCall) ([]alert.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer call.settleIO()
	call.start()
	pending, err := s.readPendingLocked(call)
	if err != nil {
		return nil, err
	}
	old := pendingIdentity(pending)
	call.observe(old)
	call.offer(0)
	if err := removePendingFindingsFile(filepath.Join(s.path, pendingFindingsFile)); err != nil {
		if os.IsNotExist(err) && len(pending) == 0 {
			call.complete(pendingImage{valid: true}, 0, false, nil)
			return nil, nil
		}
		call.ioFailed()
		actual, readErr := s.readPendingLocked(call)
		if readErr == nil {
			image := pendingIdentity(actual)
			switch {
			case image.valid && image == old:
				call.complete(image, 0, true, nil)
			case len(actual) == 0:
				call.complete(image, len(pending), true, nil)
			default:
				call.unreadable(0)
				call.observe(image)
			}
		}
		return nil, fmt.Errorf("clear pending findings: %w", err)
	}
	call.detach(len(pending))
	return pending, nil
}

func (s *Store) readPendingLocked(call *pendingCall) ([]alert.Finding, error) {
	read := s.readPendingFile
	if read == nil {
		read = os.ReadFile
	}
	data, err := read(filepath.Join(s.path, pendingFindingsFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		call.failedRead()
		return nil, fmt.Errorf("read pending findings: %w", err)
	}
	var pending []alert.Finding
	if err := json.Unmarshal(data, &pending); err != nil {
		call.failedRead()
		return nil, fmt.Errorf("decode pending findings: %w", err)
	}
	return pending, nil
}
