package phptaint

// grade is the analyzer's internal lattice element. The public Confidence is
// its first component and keeps its meaning; basis and offset only explain
// which proof produced that confidence, so a stronger flow must carry its own
// explanation rather than an older, weaker one.
type grade struct {
	conf   Confidence
	basis  Basis
	offset int
}

func directGrade(c Confidence, b Basis) grade {
	return grade{conf: c, basis: b, offset: -1}
}

// basisRank is the spec's fixed tie priority; -1 means undefined.
func basisRank(b Basis) int {
	switch b {
	case BasisAlwaysRemote:
		return 0
	case BasisLiteral:
		return 1
	case BasisDecoded:
		return 2
	case BasisRequest:
		return 3
	case BasisCallArgument:
		return 4
	case BasisUnresolved:
		return 5
	}
	return -1
}

// stronger orders by confidence, then basis priority, then the lowest
// resolution offset, with -1 (direct) lowest. The order is total over valid
// grades so every join is deterministic regardless of worklist order.
func (g grade) stronger(o grade) bool {
	if g.conf != o.conf {
		return g.conf > o.conf
	}
	if rg, ro := basisRank(g.basis), basisRank(o.basis); rg != ro {
		return rg < ro
	}
	return g.offset < o.offset
}

// directGradeOf rebuilds the ordering key from a finished Result.
func directGradeOf(r Result) grade {
	return grade{conf: r.Confidence, basis: r.Basis, offset: r.ResolutionOffset}
}
