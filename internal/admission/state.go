package admission

import "fmt"

// State is where a candidate is in its lifecycle. Queued work either becomes
// an attempt (reserved, executing, then an outcome) or ends before one
// (refused, withheld, dropped). Values are persisted: append, never renumber.
type State uint8

const (
	StateQueued State = iota + 1
	StateReserved
	StateExecuting
	StateVerified
	StateFailed
	StateUnknown
	StateRefused
	StateWithheld
	StateDropped
	// StateObserved ends an attempt that was reserved as live work would
	// be and never ran: an observe preview, never an applied outcome.
	StateObserved
	stateEnd
)

var stateNames = [...]string{"", "queued", "reserved", "executing", "verified", "failed", "unknown", "refused", "withheld", "dropped", "observed"}

func (s State) Valid() bool { return s >= StateQueued && s < stateEnd }

func (s State) String() string {
	if s.Valid() {
		return stateNames[s]
	}
	return fmt.Sprintf("state(%d)", uint8(s))
}

// Terminal reports whether s ends the candidate. A verified effect can later
// expire or be evicted through linked events, but the candidate never runs
// again; a new root set needs a new generation.
func (s State) Terminal() bool { return s >= StateVerified && s < stateEnd }

// CanTransition reports whether the lifecycle allows from -> to. Queued to
// queued records a changed deferral reason. A proven failure with attempts
// left returns the candidate to the queue; an unknown outcome never does.
// Only a reservation can end as a preview: an attempt that ran may have
// applied something.
func CanTransition(from, to State) bool {
	switch from {
	case StateQueued:
		return to == StateQueued || to == StateReserved || to == StateRefused || to == StateWithheld || to == StateDropped
	case StateReserved:
		return to == StateExecuting || to == StateFailed || to == StateQueued || to == StateObserved
	case StateExecuting:
		return to == StateVerified || to == StateFailed || to == StateUnknown || to == StateQueued
	}
	return false
}

// terminalDisposition reports whether a record in state s may carry d. Only
// terminal states carry a disposition; a queued deferral is a reason alone.
func terminalDisposition(s State, d Disposition) bool {
	switch s {
	case StateQueued, StateReserved, StateExecuting:
		return d == 0
	case StateVerified:
		return d == DispositionApplied || d == DispositionNarrowed
	case StateFailed:
		return d == DispositionFailed
	case StateUnknown:
		return d == DispositionUnknown
	case StateRefused:
		return d == DispositionRefused
	case StateWithheld:
		return d == DispositionWithheld
	case StateDropped:
		return d == DispositionDropped
	case StateObserved:
		return d == DispositionObserve
	}
	return false
}

// stateReason reports whether a record in state s may carry reason r. A
// queued candidate may wait for a deferral reason; a pre-attempt ending
// needs a reason of its own group; outcomes carry none.
func stateReason(s State, r Reason) bool {
	switch s {
	case StateQueued:
		return r == 0 || r.Disposition() == DispositionDeferred
	case StateRefused, StateWithheld, StateDropped:
		return r.Valid() && terminalDisposition(s, r.Disposition())
	}
	return r == 0
}
