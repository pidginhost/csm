package admission

import (
	"errors"
	"time"
)

// InventoryObservation is one complete read of server-owned hosting
// inventory: sorted unique accounts, canonical domains mapped to their
// owners, and the count of domains left host-scoped because several
// accounts list them. Incarnations maps accounts to server-owned tokens
// that change when an account is deleted and created again; an account
// without one keeps its generation by name. A partial read must never be
// passed.
type InventoryObservation struct {
	Accounts         []string
	Domains          map[string]string
	AmbiguousDomains int
	Incarnations     map[string]string
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

// MaxArrivalGroup bounds the arrivals one ledger transaction persists, so
// a group commit stays short.
const MaxArrivalGroup = 64

// Arrival is one ingress submission ready for the ledger: the request the
// engine built for it, the evidence to publish first and the later
// findings that reported the same evidence while it waited.
type Arrival struct {
	Request     CandidateRequest
	Evidence    Evidence
	Reports     []string
	Dropped     uint32
	ReportsOnly bool
}

// ArrivalResult is the ledger's decision on one arrival.
type ArrivalResult struct {
	// Candidate is the request's candidate ID. With Err set it may name no
	// stored candidate.
	Candidate CandidateID
	// Created is true when the arrival queued a new candidate and false
	// when it coalesced into an existing one.
	Created bool
	// Err is the arrival's refusal. It does not affect the rest of its
	// group.
	Err error
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
	// ErrLaneIneligible refuses a reserved-lane reservation whose candidate
	// no longer qualifies for that lane. It stays queued: the next schedule
	// assesses it again and serves it on a lane it qualifies for.
	ErrLaneIneligible = errors.New("candidate no longer qualifies for the picked lane")
	// ErrEvidenceUnpublished refuses a reference to evidence the ledger does
	// not hold. Its reason is ReasonInvalid.
	ErrEvidenceUnpublished error = &Error{Reason: ReasonInvalid, Detail: "evidence is not published"}
	// ErrEvidenceConflict refuses a different record under a published
	// evidence ID. Its reason is ReasonInvalid. A record that differs only
	// in its finding is a later report: link it with LinkReport instead.
	ErrEvidenceConflict error = &Error{Reason: ReasonInvalid, Detail: "evidence ID already holds a different record"}
)

// Ledger is the durable admission state (spec 5.4). One engine owner
// serializes every mutating call; detector goroutines never call it.
// Each call is one transaction: an error leaves the ledger unchanged.
type Ledger interface {
	// Tick records a clock reading. Every other call uses the last
	// recorded Now, never raw wall time. A reopened ledger, or one whose
	// last reading was refused, admits and dispatches nothing until Tick
	// succeeds; recording an outcome needs only the stored time. The same
	// transaction credits the elapsed time to the ceiling and the history
	// allowances, releases the charges that have left the ceiling's window
	// and retires history at its target.
	Tick(ClockReading) (ClockTick, error)
	// SetCeiling records the effective hourly ceiling, 1 to MaxCeiling. The
	// engine sets it at startup and on every reload; nothing is charged
	// before the first. Credit is never topped up by a later call.
	SetCeiling(uint32) error
	// Ceiling is the committed ceiling state.
	Ceiling() (CeilingState, error)
	// Storage is the committed storage state.
	Storage() (StorageState, error)
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
	// Schedule picks the next candidates to serve within the lane budgets,
	// each at most what the ceiling can charge and the history allowance
	// can take now, and records the scheduler's position. Picks stay queued until the engine reserves or
	// ends them. Every pick is revalidated first.
	Schedule(ScheduleLimits) ([]Pick, error)
	// NextWake is when queued work next changes without a new report: a
	// retry wait ends, a queued deadline passes or ready work gains ceiling
	// or history budget.
	NextWake() (time.Time, bool, error)
	// BeginIngress starts an ingress generation. A previous generation
	// still open was interrupted: its unpersisted items are lost.
	BeginIngress() (IngressState, error)
	// EndIngress closes the current generation cleanly, after the owner has
	// persisted everything the ingress held.
	EndIngress() error
	// EnqueueGroup publishes and queues up to MaxArrivalGroup arrivals in
	// one transaction. A refused arrival is counted and reported in its
	// result; any other error leaves the ledger unchanged. The revision is
	// the committed transaction's snapshot fence, or zero on failure.
	EnqueueGroup([]Arrival, *IngressCheckpoint) ([]ArrivalResult, int, error)
	// QueueSnapshot is the durable queue as the ingress needs it.
	QueueSnapshot() (*QueueSnapshot, error)
	// Revalidate checks every queued candidate against current policy,
	// inventory and the admission clock: one that no longer qualifies ends,
	// the rest keep their positions under a new assessment. The engine
	// calls it after a policy reload and once after the ledger opens.
	Revalidate() error
	// Reserve admits the next attempt on the lane a schedule picked and
	// reports true. A reserved lane is rechecked against the candidate's
	// current assessment, then the attempt is charged to the lane's
	// ceiling budget and its history to the lane's history allowance in
	// the same transaction; a refusal before the charges consumes nothing. The first reservation fixes the absolute expiry;
	// later ones must keep it. On a candidate already reserved or running
	// it returns that attempt and false: a readback grants and charges
	// nothing, and a zero lane or expiry matches the recorded one.
	Reserve(CandidateID, Lane, time.Time) (Candidate, AttemptRecord, bool, error)
	// Execute marks a reserved attempt as running and reports true. On an
	// attempt already running it returns it and false: a readback is not
	// permission to dispatch its effect again.
	Execute(ActionID) (Candidate, AttemptRecord, bool, error)
	// Finish records an attempt outcome: applied, narrowed, failed or
	// unknown. A proven failure with attempts left requeues the candidate.
	Finish(ActionID, Disposition) (Candidate, AttemptRecord, error)
	Attempt(ActionID) (AttemptRecord, error)
}
