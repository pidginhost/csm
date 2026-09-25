package admission

import (
	"sort"
	"time"
)

const (
	// RootFreshness is how long a root observation can justify a response.
	RootFreshness = 2 * time.Hour
	// SupportLookback is how far back an independent root may corroborate.
	// It never refreshes the fresh root it supports.
	SupportLookback = 24 * time.Hour
	// MaxRoots bounds the root references one assessment reads.
	MaxRoots = 16
	// maxFutureSkew tolerates producer and engine clocks disagreeing by
	// less than a second.
	maxFutureSkew = time.Second
)

// Assessment is the priority of one candidate at one instant. Admission
// recomputes it on dequeue, reload and recovery; it is never stored as
// proof.
type Assessment struct {
	Tier Tier
	// DirectC3: a fresh root carries reviewed compromise evidence.
	DirectC3 bool
	// Corroborated: an independent root of another family raised the class
	// by one. Never set together with DirectC3.
	Corroborated bool
	// EvidenceExpiry is when the last fresh root stops being fresh; the
	// candidate ages out then.
	EvidenceExpiry time.Time
	// ReassessBy is the earliest instant the class or severity drops, or
	// all roots become stale, if no new evidence arrives.
	ReassessBy time.Time
	// Roots are the validated root IDs, sorted and deduplicated.
	Roots []EvidenceID
}

// Reserved reports whether the candidate may use the reserved lane.
func (a Assessment) Reserved() bool { return a.DirectC3 || a.Corroborated }

func rootExpiry(e Evidence) time.Time {
	exp := e.ObservedAt().Add(RootFreshness)
	if intel, ok := e.Intel(); ok && intel.Expires.Before(exp) {
		exp = intel.Expires
	}
	return exp
}

func sameObservation(a, b Evidence) bool {
	return a.rec.Stream == b.rec.Stream && a.rec.Cursor == b.rec.Cursor
}

// Assess derives the tier of a candidate aimed at target from its roots at
// now. Every root must name target, or lie inside a prefix target. The base
// class is the highest class a fresh root supports; a fresh local attack
// root and an independent root of another family seen within the lookback
// raise an address candidate by one class, once. Prefix candidates are not
// raised: range corroboration has its own rules.
func Assess(target Target, roots []Evidence, now time.Time) (Assessment, error) {
	if _, isService := target.Service(); isService {
		return Assessment{}, refuse(ReasonUnsupportedContainment, "service targets cannot be assessed yet")
	}
	switch {
	case target.IsZero():
		return Assessment{}, refuse(ReasonInvalid, "assessment has no target")
	case len(roots) == 0:
		return Assessment{}, refuse(ReasonInvalid, "assessment has no evidence")
	case len(roots) > MaxRoots:
		return Assessment{}, refuse(ReasonInvalid, "assessment has too many roots")
	}
	now = now.UTC()
	byID := make(map[EvidenceID]Evidence, len(roots))
	for _, r := range roots {
		if r.Family() == FamilyNone {
			return Assessment{}, refuse(ReasonInvalid, "root is not minted evidence")
		}
		rt := r.Target()
		if (target.IsAddress() && rt != target) || (!target.IsAddress() && !target.Covers(rt)) {
			return Assessment{}, refuse(ReasonInvalid, "root names a different target")
		}
		if r.ObservedAt().After(now.Add(maxFutureSkew)) {
			return Assessment{}, refuse(ReasonInvalid, "root is dated in the future")
		}
		if prev, dup := byID[r.ID()]; dup && !prev.Equal(r) {
			return Assessment{}, refuse(ReasonInvalid, "two different roots share one ID")
		}
		byID[r.ID()] = r
	}
	ids := make([]EvidenceID, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	all := make([]Evidence, len(ids))
	var fresh []Evidence
	for i, id := range ids {
		all[i] = byID[id]
		if now.Before(rootExpiry(all[i])) {
			fresh = append(fresh, all[i])
		}
	}
	if len(fresh) == 0 {
		return Assessment{}, refuse(ReasonStale, "no root is fresh")
	}
	a := Assessment{Roots: ids}
	for _, r := range fresh {
		if c, _ := r.Basis().Class(); c > a.Tier.Class {
			a.Tier.Class = c
		}
		if r.Severity() > a.Tier.Severity {
			a.Tier.Severity = r.Severity()
		}
		exp := rootExpiry(r)
		if exp.After(a.EvidenceExpiry) {
			a.EvidenceExpiry = exp
		}
	}
	a.DirectC3 = a.Tier.Class == ClassC3
	var classEnd, severityEnd time.Time
	if target.IsAddress() {
		classEnd = corroborationExpiry(fresh, all, now)
		if !classEnd.IsZero() && !a.DirectC3 {
			a.Tier.Class = ClassC3
			a.Corroborated = true
		}
	}
	// Independent proofs can outlive each other, including corroboration
	// that keeps C3 after direct compromise evidence stops being fresh.
	for _, r := range fresh {
		exp := rootExpiry(r)
		if c, _ := r.Basis().Class(); c == a.Tier.Class && exp.After(classEnd) {
			classEnd = exp
		}
		if r.Severity() == a.Tier.Severity && exp.After(severityEnd) {
			severityEnd = exp
		}
	}
	a.ReassessBy = classEnd
	if severityEnd.Before(a.ReassessBy) {
		a.ReassessBy = severityEnd
	}
	return a, nil
}

// corroborationExpiry is the last instant until which any fresh local attack
// root has independent support from a different family and observation.
// Each pair ends at the earlier of local freshness and support expiry.
// Only the deadline matters, so tied pairs need no evidence-ID selection.
func corroborationExpiry(fresh, all []Evidence, now time.Time) time.Time {
	var last time.Time
	for _, a := range fresh {
		if !a.Family().LocalAttack() {
			continue
		}
		for _, b := range all {
			if !b.Family().Independent() || b.Family() == a.Family() || sameObservation(a, b) {
				continue
			}
			end := supportExpiry(b)
			if exp := rootExpiry(a); exp.Before(end) {
				end = exp
			}
			if now.Before(end) && end.After(last) {
				last = end
			}
		}
	}
	return last
}

func supportExpiry(e Evidence) time.Time {
	exp := e.ObservedAt().Add(SupportLookback)
	if intel, ok := e.Intel(); ok && intel.Expires.Before(exp) {
		exp = intel.Expires
	}
	return exp
}
