package reporting

import (
	"context"
	"sync/atomic"
)

// Action is the node's policy for acting on central scored-set data. It is
// deliberately conservative: central data never hard-blocks on its own.
type Action string

const (
	// ActionOff consumes the set for visibility only; never acts.
	ActionOff Action = "off"
	// ActionChallenge elevates suspicion / serves a challenge for listed IPs.
	ActionChallenge Action = "challenge"
	// ActionBlockIfLocalCorroborated hard-blocks only when this node also saw
	// abuse from the IP and the distributed score meets the threshold.
	ActionBlockIfLocalCorroborated Action = "block_if_local_corroborated"
)

// ParseAction maps a config string to an Action, defaulting to challenge for
// any unknown value (the safe default; never silently block).
func ParseAction(s string) Action {
	switch Action(s) {
	case ActionOff:
		return ActionOff
	case ActionBlockIfLocalCorroborated:
		return ActionBlockIfLocalCorroborated
	default:
		return ActionChallenge
	}
}

// Decision is what the node should do about an IP given central data.
type Decision int

const (
	// DecisionIgnore takes no central-driven action.
	DecisionIgnore Decision = iota
	// DecisionChallenge elevates suspicion / serves a challenge.
	DecisionChallenge
	// DecisionBlock hard-blocks (only reachable with local corroboration).
	DecisionBlock
)

// DecisionInput is the per-IP context for a central-data decision.
type DecisionInput struct {
	Found               bool // IP present in the central scored-set
	Score               int  // distributed score 0-100
	Protected           bool // firebreak: infra/CF/crawler/RFC5737/allowlist
	LocallyCorroborated bool // this node independently observed abuse from the IP
}

// Decide returns the node action for an IP. Firebreaks always win: a protected
// IP is never acted on from central data. A central-only signal can at most
// challenge; a hard block requires local corroboration, the action policy, and
// the score meeting blockThreshold.
func Decide(in DecisionInput, action Action, blockThreshold int) Decision {
	if in.Protected || !in.Found || action == ActionOff {
		return DecisionIgnore
	}
	if action == ActionBlockIfLocalCorroborated && in.LocallyCorroborated && in.Score >= blockThreshold {
		return DecisionBlock
	}
	return DecisionChallenge
}

// CentralStore holds the current verified scored-set for concurrent lookups and
// is refreshed by a Puller. The set pointer is swapped atomically so readers on
// the block/challenge path never block on a refresh.
type CentralStore struct {
	puller *Puller
	snap   atomic.Pointer[ScoredSnapshot]
	set    atomic.Pointer[Set]
}

// NewCentralStore builds an empty store backed by puller.
func NewCentralStore(puller *Puller) *CentralStore {
	cs := &CentralStore{puller: puller}
	empty := ScoredSnapshot{}
	cs.snap.Store(&empty)
	cs.set.Store(NewSet(empty))
	return cs
}

// Lookup returns the scored entry for ip from the current set.
func (cs *CentralStore) Lookup(ip string) (ScoredEntry, bool) {
	return cs.set.Load().Lookup(ip)
}

// Version returns the current set version.
func (cs *CentralStore) Version() uint64 { return cs.set.Load().Version() }

// Refresh pulls an update and swaps in the new set on change. On a version gap
// it retries once from a cold pull (since=0) so a node that fell behind the
// diff window recovers with a full snapshot.
func (cs *CentralStore) Refresh(ctx context.Context) error {
	cur := *cs.snap.Load()
	next, changed, err := cs.puller.Refresh(ctx, cur)
	if err == ErrSetVersionGap {
		next, changed, err = cs.puller.Refresh(ctx, ScoredSnapshot{})
	}
	if err != nil {
		return err
	}
	if changed {
		cs.snap.Store(&next)
		cs.set.Store(NewSet(next))
	}
	return nil
}
