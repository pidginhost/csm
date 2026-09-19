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

// rankedBases is the spec's fixed tie priority, strongest first. It is also
// the index order of gradeSet, so the two can never disagree.
var rankedBases = [...]Basis{
	BasisAlwaysRemote,
	BasisLiteral,
	BasisDecoded,
	BasisRequest,
	BasisCallArgument,
	BasisUnresolved,
}

// basisRank is the position of b in rankedBases; -1 means undefined.
func basisRank(b Basis) int {
	for i, r := range rankedBases {
		if r == b {
			return i
		}
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

// gradeSet is the value the fixpoints store for a variable, an assignment,
// an origin and a summary: for each basis, the best confidence and offset
// any proof on that basis reached. A single grade cannot be stored there,
// because the decoder upgrade is not monotone under stronger: High
// always-remote is weaker than Certain literal, yet after both are decoded
// Certain always-remote wins. Kept as one maximum, the answer would depend on
// which value the worklist saw first. Per basis the upgrade is monotone, the
// join is pointwise, and at most len(rankedBases) entries exist, so every
// fixpoint over gradeSet still terminates and has one answer. The single
// strongest grade is chosen only when a Result is emitted.
type gradeSet struct {
	entries [len(rankedBases)]gradeEntry
}

type gradeEntry struct {
	present bool
	conf    Confidence
	offset  int
}

// better orders two proofs on the same basis: higher confidence, then the
// lower resolution offset.
func (e gradeEntry) better(o gradeEntry) bool {
	if e.present != o.present {
		return e.present
	}
	if e.conf != o.conf {
		return e.conf > o.conf
	}
	return e.offset < o.offset
}

// setOf is the set holding one proof. An undefined basis yields the empty
// set; sourceGrade never produces one.
func setOf(g grade) gradeSet {
	var s gradeSet
	if r := basisRank(g.basis); r >= 0 {
		s.entries[r] = gradeEntry{present: true, conf: g.conf, offset: g.offset}
	}
	return s
}

func (s gradeSet) isEmpty() bool {
	for _, e := range s.entries {
		if e.present {
			return false
		}
	}
	return true
}

// add joins o into s pointwise and reports whether s grew.
func (s *gradeSet) add(o gradeSet) bool {
	grew := false
	for i, e := range o.entries {
		if e.better(s.entries[i]) {
			s.entries[i] = e
			grew = true
		}
	}
	return grew
}

// decoded applies the decoder upgrade to every proof: confidence becomes
// Certain and each basis still explains its own acquisition.
func (s gradeSet) decoded() gradeSet {
	for i := range s.entries {
		if s.entries[i].present {
			s.entries[i].conf = ConfidenceCertain
		}
	}
	return s
}

// strongest selects the proof a Result reports, by the stronger order. The
// empty set yields the zero grade; callers emit only non-empty sets.
func (s gradeSet) strongest() grade {
	var best grade
	found := false
	for i, e := range s.entries {
		if !e.present {
			continue
		}
		g := grade{conf: e.conf, basis: rankedBases[i], offset: e.offset}
		if !found || g.stronger(best) {
			best = g
		}
		found = true
	}
	return best
}
