package learn

import (
	"math"
	"slices"
)

// JoinBoundary is the probability at which a near match joins a live anchor.
const JoinBoundary = 0.75

// Contribution weights (spec 7.4 rule 5).
const (
	UIDWeight      = 2
	OperatorWeight = 18
)

// Per-account and operator state allowances. Provisional until Plan C's
// benchmark records a measurement.
const (
	AccountBodyBytes  = 64 << 20
	AccountAliases    = 4096
	OperatorBodyBytes = 512 << 20
	OperatorAliases   = 8 * AccountAliases
)

// Skip reasons: terminal outcomes for one digest of a report.
const (
	SkipDuplicate        = "duplicate"
	SkipBelowJoin        = "below_join"
	SkipMultipartSeed    = "multipart_seed"
	SkipNoDigest         = "no_digest"
	SkipAccountCapacity  = "account_capacity"
	SkipOperatorCapacity = "operator_capacity"
	SkipOverflow         = "overflow"
)

// Source is who reports and how large the snapshot is. Operator is a source
// kind, never a tenant UID.
type Source struct {
	UID      int
	Operator bool
	MarkID   string
	BodyLen  int64
}

// Join is one new contribution to an existing cluster.
type Join struct {
	ClusterID uint64
	Aliases   []Digest
	NewT      int32
}

// Skip is a terminal outcome for one digest; an empty digest means the
// whole report.
type Skip struct {
	Digest Digest
	Reason string
}

// Admission is what a report may reserve. Duplicates names clusters the
// reporter already voted on. Defer means reserve nothing and re-inspect
// later; Mismatch names unknown stored digests (state_mismatch); DeleteZero
// names zero-target digests that reappeared.
type Admission struct {
	Joins      []Join
	Seed       *Seed
	Skips      []Skip
	Duplicates []uint64
	Defer      bool
	Mismatch   []Digest
	DeleteZero []Digest
}

// LedgerReader is what assignment reads; LedgerView implements it.
type LedgerReader interface {
	Alias(d Digest) (uint64, bool, error)
	Cluster(id uint64) (Cluster, bool, error)
	Target(d Digest) (Target, bool, error)
	Usage(uid int, operator bool) (Usage, error)
}

var _ LedgerReader = LedgerView{}

// resolved is one digest's assignment before votes are counted.
type resolved struct {
	digest  Digest
	cluster uint64
	alias   bool // an accepted alias, not a fresh match
	skip    string
	miss    bool
}

// Assign applies spec 7.4's assignment rules to a complete inspection.
// gaps holds clusters with a known publication gap (anchor missing, being
// deleted and re-added, or awaiting first publication); while any exists no
// fresh match or seed is resolved, since a miss may be that anchor. A ledger
// read error defers the whole report.
func Assign(insp Inspection, src Source, v LedgerReader, gaps map[uint64]bool) (Admission, error) {
	var a Admission
	if insp.Distinct == 0 {
		a.Skips = []Skip{{Reason: SkipNoDigest}}
		return a, nil
	}
	parts := make([]resolved, 0, len(insp.Results))
	for _, r := range insp.Results {
		p, err := resolve(r, v, &a)
		if err != nil {
			return Admission{}, err
		}
		parts = append(parts, p)
	}
	if len(a.Mismatch) > 0 || len(a.DeleteZero) > 0 {
		return Admission{Mismatch: a.Mismatch, DeleteZero: a.DeleteZero, Defer: true}, nil
	}
	hasGap := false
	for _, gap := range gaps {
		if gap {
			hasGap = true
			break
		}
	}
	for _, p := range parts {
		// A below-boundary hit may be a fallback for a missing anchor.
		if gaps[p.cluster] || (!p.alias && hasGap) {
			return Admission{Defer: true}, nil
		}
	}
	if len(parts) == 1 && parts[0].miss {
		t := int32(UIDWeight)
		if src.Operator {
			t = OperatorWeight
		}
		a.Seed = &Seed{Anchor: parts[0].digest, T: t}
		return capacity(a, src, v, 1, src.BodyLen, parts)
	}
	newAliases := 0
	for _, id := range clusterOrder(parts) {
		c, ok, err := v.Cluster(id)
		if err != nil {
			return Admission{}, err
		}
		if !ok {
			// An alias or target names a cluster the ledger lacks.
			var named []Digest
			for _, p := range parts {
				if p.cluster == id {
					named = append(named, p.digest)
				}
			}
			return Admission{Mismatch: named, Defer: true}, nil
		}
		voted := slices.Contains(c.UIDs, src.UID) && !src.Operator || src.Operator && slices.Contains(c.Marks, src.MarkID)
		if voted {
			a.Duplicates = append(a.Duplicates, id)
			for _, p := range parts {
				if p.cluster == id {
					a.Skips = append(a.Skips, Skip{Digest: p.digest, Reason: SkipDuplicate})
				}
			}
			continue
		}
		t, ok, err := v.Target(c.Anchor)
		if err != nil {
			return Admission{}, err
		}
		if !ok || t.T <= 0 {
			// Retirement or forget is under way: wait for it to finish.
			return Admission{Defer: true}, nil
		}
		weight := int64(UIDWeight)
		if src.Operator {
			weight = OperatorWeight
		}
		if int64(t.T)+weight > math.MaxInt32 {
			return rejectAll(parts, SkipOverflow), nil
		}
		j := Join{ClusterID: id, NewT: t.T + int32(weight)}
		for _, p := range parts {
			if p.cluster == id && !p.alias {
				j.Aliases = append(j.Aliases, p.digest)
			}
		}
		newAliases += len(j.Aliases)
		a.Joins = append(a.Joins, j)
	}
	for _, p := range parts {
		switch {
		case p.skip != "":
			a.Skips = append(a.Skips, Skip{Digest: p.digest, Reason: p.skip})
		case p.miss:
			a.Skips = append(a.Skips, Skip{Digest: p.digest, Reason: SkipMultipartSeed})
		}
	}
	return capacity(a, src, v, newAliases, 0, parts)
}

// resolve maps one digest: accepted aliases first, then a live anchor
// matched at or above the join boundary.
func resolve(r Result, v LedgerReader, a *Admission) (resolved, error) {
	p := resolved{digest: r.Queried}
	id, ok, err := v.Alias(r.Queried)
	if err != nil || ok {
		p.cluster, p.alias = id, ok
		return p, err
	}
	if !r.Found {
		p.miss = true
		return p, nil
	}
	t, ok, err := v.Target(r.Stored)
	switch {
	case err != nil:
		return p, err
	case !ok:
		a.Mismatch = append(a.Mismatch, r.Stored)
	case t.T == 0:
		a.DeleteZero = append(a.DeleteZero, r.Stored)
	case r.Prob < JoinBoundary:
		p.skip = SkipBelowJoin
	default:
		p.cluster = t.ClusterID
	}
	return p, nil
}

func clusterOrder(parts []resolved) []uint64 {
	var ids []uint64
	for _, p := range parts {
		if p.cluster != 0 && !slices.Contains(ids, p.cluster) {
			ids = append(ids, p.cluster)
		}
	}
	return ids
}

func rejectAll(parts []resolved, reason string) Admission {
	var a Admission
	for _, p := range parts {
		a.Skips = append(a.Skips, Skip{Digest: p.digest, Reason: reason})
	}
	return a
}

// capacity rejects the whole admission when it would pass the reporter's
// allowance; existing guards stay.
func capacity(a Admission, src Source, v LedgerReader, aliases int, bodyBytes int64, parts []resolved) (Admission, error) {
	if len(a.Joins) == 0 && a.Seed == nil {
		return a, nil
	}
	u, err := v.Usage(src.UID, src.Operator)
	if err != nil {
		return Admission{}, err
	}
	maxBody, maxAliases, reason := int64(AccountBodyBytes), AccountAliases, SkipAccountCapacity
	if src.Operator {
		maxBody, maxAliases, reason = OperatorBodyBytes, OperatorAliases, SkipOperatorCapacity
	}
	if u.BodyBytes+bodyBytes > maxBody || (aliases > 0 && u.Aliases+aliases > maxAliases) {
		return rejectAll(parts, reason), nil
	}
	return a, nil
}
