package admission

import "time"

// ActionView is one admitted candidate and its attempts as `csm action
// show` prints them: what the ledger decided and, for a candidate refused
// as an existing effect, the block that already enforced it.
type ActionView struct {
	Candidate   CandidateID   `json:"candidate_id"`
	Kind        string        `json:"kind"`
	Target      string        `json:"target"`
	Check       string        `json:"check,omitempty"`
	FindingID   string        `json:"finding_id,omitempty"`
	State       string        `json:"state"`
	Reason      string        `json:"reason,omitempty"`
	Disposition string        `json:"disposition,omitempty"`
	ExpiresAt   time.Time     `json:"expires_at,omitzero"`
	Link        *LinkView     `json:"link,omitempty"`
	Attempts    []AttemptView `json:"attempts"`
}

// LinkView names the block that already enforced a refused candidate's
// effect, and when it ends (zero: permanent).
type LinkView struct {
	Effect    string    `json:"effect"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// AttemptView is one attempt of an ActionView, in sequence order.
type AttemptView struct {
	Action      ActionID  `json:"action_id"`
	Seq         uint32    `json:"seq"`
	State       string    `json:"state"`
	Disposition string    `json:"disposition,omitempty"`
	Lane        string    `json:"lane,omitempty"`
	Reserved    time.Time `json:"reserved"`
	Finished    time.Time `json:"finished,omitzero"`
	ExpiresAt   time.Time `json:"expires_at"`
	Retired     bool      `json:"retired,omitempty"`
}

// NewActionView is the view of candidate c, named id, with its attempts
// in sequence order.
func NewActionView(id CandidateID, c Candidate, attempts []AttemptRecord) ActionView {
	v := ActionView{
		Candidate: id, Kind: c.Key.Kind.String(), Target: c.Key.Target.Key(), Check: c.Check, FindingID: c.FindingID,
		State: c.State.String(), ExpiresAt: c.ExpiresAt, Attempts: make([]AttemptView, 0, len(attempts)),
	}
	if c.Reason != 0 {
		v.Reason = c.Reason.String()
	}
	if c.Disposition != 0 {
		v.Disposition = c.Disposition.String()
	}
	if c.Link != (EffectLink{}) {
		v.Link = &LinkView{Effect: c.Link.Effect, ExpiresAt: c.Link.ExpiresAt}
	}
	for _, a := range attempts {
		av := AttemptView{
			Action: a.Attempt.ID, Seq: a.Attempt.Seq, State: a.State.String(),
			Reserved: a.Reserved, Finished: a.Finished, ExpiresAt: a.ExpiresAt, Retired: a.Retired,
		}
		if a.Disposition != 0 {
			av.Disposition = a.Disposition.String()
		}
		if a.Lane != 0 {
			av.Lane = a.Lane.String()
		}
		v.Attempts = append(v.Attempts, av)
	}
	return v
}
