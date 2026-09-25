package admission

import (
	"errors"
	"time"
)

// InventoryObservation is one complete read of server-owned hosting
// inventory: sorted unique accounts, canonical domains mapped to their
// owners, and the count of domains left host-scoped because several
// accounts list them. A partial read must never be passed.
type InventoryObservation struct {
	Accounts         []string
	Domains          map[string]string
	AmbiguousDomains int
}

// CandidateRequest asks the ledger to queue a response. The engine supplies
// the kind, target, episode and generation; what describes the attack comes
// from published evidence, never from the caller.
type CandidateRequest struct {
	Kind       Kind
	Target     Target
	Episode    EpisodeID
	Generation uint32
	// Primary is the root the response answers. Its finding is the
	// candidate's original link; its entry and check are the candidate's.
	Primary EvidenceID
	// Support lists further roots, such as independent corroboration.
	Support []EvidenceID
}

var (
	// ErrCandidateTerminal refuses work on a candidate that has ended. A
	// new root set needs a new generation; the old row is never revived.
	ErrCandidateTerminal = errors.New("candidate has ended; queue a new generation")
	// ErrTransitionConflict refuses a change that contradicts the recorded
	// state or outcome.
	ErrTransitionConflict = errors.New("candidate transition conflicts with its recorded state")
	// ErrNotReady refuses to reserve a candidate before its retry time.
	ErrNotReady = errors.New("candidate is waiting for its retry time")
)

// Ledger is the durable admission state (spec 5.4). One engine owner
// serializes every mutating call; detector goroutines never call it.
// Each call is one transaction: an error leaves the ledger unchanged.
type Ledger interface {
	// Tick records a clock reading. Every other call uses the last
	// recorded Now, never raw wall time.
	Tick(ClockReading) (ClockTick, error)
	// PublishEvidence stores an immutable record after revalidating it.
	// An identical record again changes nothing and reports false; a
	// different record under the same ID is refused.
	PublishEvidence(Evidence) (bool, error)
	// LinkReport records a later finding that reported the same evidence,
	// in bounded metadata that never touches the evidence or its queue.
	LinkReport(EvidenceID, string) error
	// Reports returns the linked later findings and how many were not kept.
	Reports(EvidenceID) ([]string, uint32, error)
	// LoadEvidence loads a published record and revalidates it.
	LoadEvidence(EvidenceID) (Evidence, error)
	// RefreshInventory folds one complete observation into the persisted
	// generations. A failed call keeps the previous inventory.
	RefreshInventory(InventoryObservation) error
	// Inventory is the last committed inventory.
	Inventory() *Inventory
	// AmbiguousDomains is the count from the last committed observation.
	AmbiguousDomains() int
	// Enqueue queues a candidate, or coalesces the request into the existing
	// candidate with the same ID and reports false. A reserved or executing
	// candidate accepts no new roots.
	Enqueue(CandidateRequest) (Candidate, bool, error)
	Candidate(CandidateID) (Candidate, error)
	// Defer records a changed deferral reason on a queued candidate.
	Defer(CandidateID, Reason) (Candidate, error)
	// Terminate ends a queued candidate as refused, withheld or dropped.
	Terminate(CandidateID, Reason) (Candidate, error)
	// Reserve admits the next attempt. The first reservation fixes the
	// absolute expiry; later ones must keep it.
	Reserve(CandidateID, time.Time) (Candidate, AttemptRecord, error)
	// Execute marks a reserved attempt as running.
	Execute(ActionID) (Candidate, AttemptRecord, error)
	// Finish records an attempt outcome: applied, narrowed, failed or
	// unknown. A proven failure with attempts left requeues the candidate.
	Finish(ActionID, Disposition) (Candidate, AttemptRecord, error)
	Attempt(ActionID) (AttemptRecord, error)
}
