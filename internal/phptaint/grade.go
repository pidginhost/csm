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

// confidenceLevels is the number of Confidence values, the second index of
// a gradeSet.
const confidenceLevels = int(ConfidenceCertain) + 1

// gradeSet is the value the fixpoints store for a variable, an assignment,
// an origin and a summary: for each (basis, confidence) pair, the lowest
// resolution offset any proof with that key reached. A single grade cannot
// be stored there, because the decoder upgrade is not monotone under
// stronger: High always-remote is weaker than Certain literal, yet after
// both are decoded Certain always-remote wins. Keying by basis alone is not
// enough either: (High, 3) is weaker than (Certain, 9) on one basis, yet
// after the upgrade offset 3 wins. With confidence in the key, the upgrade
// just moves each entry to its basis's Certain key and joins it there, which
// distributes over the join. The join keeps the lowest offset per key, there
// are at most len(rankedBases) x confidenceLevels keys, so every fixpoint
// over gradeSet still terminates and has one answer. The single strongest
// grade is chosen only when a Result is emitted.
type gradeSet struct {
	entries [len(rankedBases)][confidenceLevels]gradeEntry
}

// gradeEntry is one key's lowest resolution offset, stored biased by
// entryBias so the zero value means absent and the zero gradeSet is the
// empty set. A resolution offset is -1 or a position inside the source,
// which MaxSourceBytes bounds far below int32. The solver keeps one gradeSet
// per variable, assignment output and summary, so the entry stays four
// bytes rather than a padded (bool, int) pair.
type gradeEntry int32

const entryBias = 2

// entryAt encodes offset. An offset outside [-1, MaxSourceBytes] is an
// analyzer defect: it panics, which the package boundary recovers into a
// visible coverage gap, rather than storing a value that decodes to a
// different proof.
func entryAt(offset int) gradeEntry {
	if offset < -1 || offset > MaxSourceBytes {
		panic("phptaint: resolution offset out of range")
	}
	return gradeEntry(offset + entryBias)
}

func (e gradeEntry) present() bool { return e != 0 }

func (e gradeEntry) offset() int { return int(e) - entryBias }

// joinEntry keeps the lower offset for one key and reports whether it grew.
// The bias preserves order, so present entries compare directly.
func joinEntry(cur *gradeEntry, e gradeEntry) bool {
	if !e.present() || (cur.present() && *cur <= e) {
		return false
	}
	*cur = e
	return true
}

// setOf is the set holding one proof. An undefined basis or confidence
// yields the empty set; sourceGrade never produces one.
func setOf(g grade) gradeSet {
	var s gradeSet
	if r := basisRank(g.basis); r >= 0 && int(g.conf) < confidenceLevels {
		s.entries[r][g.conf] = entryAt(g.offset)
	}
	return s
}

func (s gradeSet) isEmpty() bool {
	return s == gradeSet{}
}

// add joins o into s per key and reports whether s grew: a key appeared or
// an existing key's offset dropped.
func (s *gradeSet) add(o gradeSet) bool {
	grew := false
	for b := range o.entries {
		for c := range o.entries[b] {
			if joinEntry(&s.entries[b][c], o.entries[b][c]) {
				grew = true
			}
		}
	}
	return grew
}

// decoded applies the decoder upgrade to every proof: each entry moves to
// its basis's Certain key, and each basis still explains its own
// acquisition.
func (s gradeSet) decoded() gradeSet {
	var out gradeSet
	for b := range s.entries {
		for c := range s.entries[b] {
			joinEntry(&out.entries[b][ConfidenceCertain], s.entries[b][c])
		}
	}
	return out
}

// strongest selects the proof a Result reports, by the stronger order. The
// empty set yields the zero grade; callers emit only non-empty sets.
func (s gradeSet) strongest() grade {
	var best grade
	found := false
	for b := range s.entries {
		for c, e := range s.entries[b] {
			if !e.present() {
				continue
			}
			g := grade{conf: Confidence(c), basis: rankedBases[b], offset: e.offset()}
			if !found || g.stronger(best) {
				best = g
			}
			found = true
		}
	}
	return best
}
