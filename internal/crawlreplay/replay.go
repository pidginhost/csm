package crawlreplay

import (
	"cmp"
	"errors"
	"math"
	"math/rand/v2"
	"slices"
)

// ErrSite reports a replay input that is not one site's covered records.
var ErrSite = errors.New("crawlreplay: invalid site input")

// Params are the detector settings a sweep varies (spec 6.3-6.5).
type Params struct {
	W        int            `json:"w"` // window, complete minutes
	R        float64        `json:"r"` // residual rate multiple of the baseline
	F        float64        `json:"f"` // residual floor, requests per minute
	K        int            `json:"k"` // largest bindings removed
	D        int            `json:"d"` // residual distinct bindings required
	C        float64        `json:"c"` // scope coverage, percent of anomalous traffic
	Baseline BaselineParams `json:"baseline"`
}

// Validate checks the domain constraints of spec 10; it approves no value.
func (p Params) Validate() error {
	switch {
	case p.W < 1, p.K < 1, p.D <= p.K,
		math.IsNaN(p.R) || math.IsInf(p.R, 0) || p.R <= 1,
		math.IsNaN(p.F) || math.IsInf(p.F, 0) || p.F <= 0,
		math.IsNaN(p.C) || p.C <= 0 || p.C > 100:
		return ErrParams
	}
	return p.Baseline.Validate()
}

// Span is an inclusive range of Unix minutes a site's logs cover.
type Span struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
}

// Site is one site's records and the minutes its logs cover. A minute
// outside Coverage is unknown, never zero traffic.
type Site struct {
	Records  []Record
	Coverage []Span
}

// Options choose how a replay decides.
type Options struct {
	// Sketch decides with the prototype sketch bounds; nil uses exact
	// residuals. Exact values are always reported beside the bounds.
	Sketch *SketchParams
	// Shuffle, when nonzero, permutes arrivals inside each minute with this
	// seed, to measure how sketch bounds depend on arrival order.
	Shuffle uint64
}

// KeyID names a detector key inside one site's replay: level 3 is the
// site's dynamic traffic, level 2 an L2 key and level 1 an L1 key whose
// L2 ancestor is Parent.
type KeyID struct {
	Level  uint8  `json:"level"`
	Key    string `json:"key,omitempty"`
	Parent string `json:"parent,omitempty"`
}

func keyOrder(a, b KeyID) int {
	return cmp.Or(cmp.Compare(b.Level, a.Level), cmp.Compare(a.Parent, b.Parent), cmp.Compare(a.Key, b.Key))
}

// keysOf lists every level a record contributes to, broadest first.
func keysOf(r *Record) []KeyID {
	keys := []KeyID{{Level: 3}}
	if r.Class == ClassExpensive {
		keys = append(keys, KeyID{Level: 2, Key: r.L2}, KeyID{Level: 1, Key: r.L1, Parent: r.L2})
	}
	return keys
}

// Evaluation is one key's complete window at one minute.
type Evaluation struct {
	Key            KeyID            `json:"key"`
	Total          int64            `json:"total"`     // window requests, bound or not
	Expensive      int64            `json:"expensive"` // window requests with a query
	Bindings       int64            `json:"bindings"`  // distinct bindings in the window
	Residual       int64            `json:"residual"`  // residual requests the decision used
	Distinct       int64            `json:"distinct"`  // residual bindings the decision used
	ExactResidual  int64            `json:"exact_residual"`
	ExactDistinct  int64            `json:"exact_distinct"`
	Expected       float64          `json:"expected"` // sum of per-minute expectations over the window
	Anomalous      bool             `json:"anomalous"`
	ExactAnomalous bool             `json:"exact_anomalous"`
	Labels         map[string]int64 `json:"labels"`
}

// Margins are how far a window is past A1 and A2; both at least 1 means
// anomalous.
func (p Params) Margins(residual, distinct int64, expected float64) (a1, a2 float64) {
	need := max(p.R*expected, p.F*float64(p.W))
	return float64(residual) / need, float64(distinct) / float64(p.D)
}

func (p Params) anomalous(residual, distinct int64, expected float64) bool {
	a1, a2 := p.Margins(residual, distinct, expected)
	return a1 >= 1 && a2 >= 1
}

// Count bases of a scope selection (spec 6.3).
const (
	// BasisExpensive counts only requests with a query.
	BasisExpensive = "expensive"
	// BasisDynamic counts queryless dynamic requests too: the anomalous
	// site key includes them, so every level is measured against them.
	BasisDynamic = "dynamic"
)

// Reasons a scope selection refuses to name keys.
const (
	// RefusedZero: the anomalous keys hold no requests.
	RefusedZero = "zero_denominator"
	// RefusedUnknown: a key whose window is incomplete may be anomalous
	// outside every known anomalous ancestor, or may be the maximal
	// ancestor of one, so the anomalous traffic is not known.
	RefusedUnknown = "unknown_denominator"
)

// Scope is the narrowest level whose disjoint anomalous keys cover C
// percent of the anomalous traffic (spec 6.3).
type Scope struct {
	Level       uint8   `json:"level"` // 0 when nothing qualifies
	Keys        []KeyID `json:"keys,omitempty"`
	Covered     int64   `json:"covered"`
	Denominator int64   `json:"denominator"`
	Basis       string  `json:"basis,omitempty"`
	Refused     string  `json:"refused,omitempty"`
}

// Tick is one minute whose windows are complete.
type Tick struct {
	Minute      int64
	Evaluations []Evaluation
	Scope       Scope
}

type keyState struct {
	baseline   *Baseline
	window     *Window
	minutes    map[int64]*minuteCounts
	sketches   map[int64]*keySketch
	observedTo int64
	active     bool
}

// ReplaySite runs the detector over one site, minute by minute, and calls fn
// for every covered minute whose W-minute window is complete. Each minute is
// evaluated against the baseline learned before it; anomalous minutes do
// not train the baseline, and missing minutes are never learned as zero.
func ReplaySite(site Site, p Params, o Options, fn func(Tick)) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if o.Sketch != nil && (o.Sketch.M <= p.K || o.Sketch.H < p.D+p.K) {
		return ErrParams
	}
	buckets, err := bucketSite(site, o.Shuffle)
	if err != nil {
		return err
	}
	keys := map[KeyID]*keyState{}
	active := map[KeyID]*keyState{}
	var coveredFrom int64
	for i, span := range site.Coverage {
		if i == 0 || span.From-1 != site.Coverage[i-1].To {
			coveredFrom = span.From
			// Only missing minutes break windows; adjacent spans describe
			// the same continuous coverage as a single joined span.
			for id, ks := range active {
				ks.active, ks.window, ks.minutes, ks.sketches = false, newWindow(), nil, nil
				delete(active, id)
			}
		}
		for m := span.From; m <= span.To; m++ {
			for _, r := range buckets[m] {
				for _, id := range keysOf(r) {
					ks := keys[id]
					if ks == nil {
						ks = &keyState{baseline: NewBaseline(p.Baseline, m), window: newWindow(), observedTo: m - 1}
						keys[id] = ks
					}
					if !ks.active {
						foldIdle(ks, site.Coverage, m)
						ks.active, ks.minutes, ks.sketches = true, map[int64]*minuteCounts{}, map[int64]*keySketch{}
						active[id] = ks
					}
					mc := ks.minutes[m]
					if mc == nil {
						mc = newMinuteCounts()
						ks.minutes[m] = mc
					}
					mc.add(r)
					if o.Sketch != nil && r.Binding != "" {
						sk := ks.sketches[m]
						if sk == nil {
							sk = newKeySketch(*o.Sketch)
							ks.sketches[m] = sk
						}
						sk.add(*o.Sketch, r.Binding)
					}
				}
			}
			ids := make([]KeyID, 0, len(active))
			for id, ks := range active {
				ids = append(ids, id)
				if mc := ks.minutes[m]; mc != nil {
					ks.window.apply(mc, 1)
				}
				if mc := ks.minutes[m-int64(p.W)]; mc != nil {
					ks.window.apply(mc, -1)
					delete(ks.minutes, m-int64(p.W))
				}
				delete(ks.sketches, m-int64(p.W))
			}
			slices.SortFunc(ids, keyOrder)
			complete := m-coveredFrom+1 >= int64(p.W)
			tick := Tick{Minute: m}
			for _, id := range ids {
				ks := active[id]
				anomalous := false
				if complete && ks.window.Total() > 0 {
					e := evaluate(ks, id, m, p, o)
					anomalous = e.Anomalous
					tick.Evaluations = append(tick.Evaluations, e)
				}
				if !anomalous {
					var total int64
					if mc := ks.minutes[m]; mc != nil {
						total = mc.total
					}
					ks.baseline.Observe(m, total)
				}
				ks.observedTo = m
				if ks.window.Total() == 0 {
					ks.active = false
					delete(active, id)
				}
			}
			if complete {
				tick.Scope = selectScope(tick.Evaluations, p.C, nil)
				fn(tick)
			}
		}
	}
	return nil
}

// bucketSite checks the input and groups eligible records by minute in
// logged order.
func bucketSite(site Site, shuffle uint64) (map[int64][]*Record, error) {
	for i, s := range site.Coverage {
		if s.From <= 0 || s.To < s.From || (i > 0 && s.From <= site.Coverage[i-1].To) {
			return nil, ErrSite
		}
	}
	covered := func(m int64) bool {
		i, found := slices.BinarySearchFunc(site.Coverage, m, func(s Span, m int64) int { return cmp.Compare(s.To, m) })
		return found || (i < len(site.Coverage) && site.Coverage[i].From <= m)
	}
	buckets := map[int64][]*Record{}
	for i := range site.Records {
		r := &site.Records[i]
		if r.Validate() != nil || r.Site != site.Records[0].Site || !covered(r.T/60) {
			return nil, ErrSite
		}
		if r.Class == ClassOther || r.Infra {
			continue
		}
		buckets[r.T/60] = append(buckets[r.T/60], r)
	}
	for m, rs := range buckets {
		slices.SortStableFunc(rs, func(a, b *Record) int {
			return cmp.Or(cmp.Compare(a.File, b.File), cmp.Compare(a.Seq, b.Seq))
		})
		if shuffle != 0 {
			// #nosec G115 G404 -- positive Unix minute; a reproducible permutation, not a secret.
			rng := rand.New(rand.NewPCG(shuffle, uint64(m)))
			rng.Shuffle(len(rs), func(i, j int) { rs[i], rs[j] = rs[j], rs[i] })
		}
	}
	return buckets, nil
}

// foldIdle learns the zero-traffic covered minutes a key sat idle through.
func foldIdle(ks *keyState, coverage []Span, until int64) {
	for _, s := range coverage {
		for m := max(ks.observedTo+1, s.From); m <= min(until-1, s.To); m++ {
			ks.baseline.Observe(m, 0)
		}
	}
	ks.observedTo = until - 1
}

func evaluate(ks *keyState, id KeyID, m int64, p Params, o Options) Evaluation {
	e := Evaluation{Key: id, Total: ks.window.Total(), Expensive: ks.window.Expensive(), Bindings: int64(len(ks.window.bindings)), Labels: ks.window.Labels()}
	e.ExactResidual, e.ExactDistinct = ks.window.Residual(p.K)
	for j := m - int64(p.W) + 1; j <= m; j++ {
		e.Expected += ks.baseline.Expected(j)
	}
	e.ExactAnomalous = p.anomalous(e.ExactResidual, e.ExactDistinct, e.Expected)
	e.Residual, e.Distinct, e.Anomalous = e.ExactResidual, e.ExactDistinct, e.ExactAnomalous
	if o.Sketch != nil {
		minutes := make([]*keySketch, 0, p.W)
		for j := m - int64(p.W) + 1; j <= m; j++ {
			if sk := ks.sketches[j]; sk != nil {
				minutes = append(minutes, sk)
			}
		}
		bounds := composeSketches(minutes, p.K, o.Sketch.H)
		e.Residual, e.Distinct = bounds.LN, bounds.LD
		e.Anomalous = p.anomalous(e.Residual, e.Distinct, e.Expected)
	}
	return e
}

// ancestors lists the keys whose traffic contains id's, nearest first.
func ancestors(id KeyID) []KeyID {
	switch id.Level {
	case 1:
		return []KeyID{{Level: 2, Key: id.Parent}, {Level: 3}}
	case 2:
		return []KeyID{{Level: 3}}
	}
	return nil
}

// selectScope evaluates anomalous L1 keys, then L2, then L3; the first
// level whose union covers C percent of the maximal anomalous traffic
// supplies the disjoint key set. unknown lists keys with traffic whose
// window is incomplete; unless an anomalous ancestor already holds one,
// the anomalous traffic is not known and no scope is chosen.
func selectScope(evals []Evaluation, c float64, unknown []KeyID) Scope {
	anomalous := map[KeyID]Evaluation{}
	for _, e := range evals {
		if e.Anomalous {
			anomalous[e.Key] = e
		}
	}
	subsumed := func(id KeyID) bool {
		for _, a := range ancestors(id) {
			if _, ok := anomalous[a]; ok {
				return true
			}
		}
		return false
	}
	for _, id := range unknown {
		if !subsumed(id) {
			return Scope{Refused: RefusedUnknown}
		}
	}
	if len(anomalous) == 0 {
		return Scope{}
	}
	basis := BasisExpensive
	if site, ok := anomalous[KeyID{Level: 3}]; ok && site.Total > site.Expensive {
		basis = BasisDynamic
	}
	count := func(e Evaluation) int64 {
		if basis == BasisDynamic {
			return e.Total
		}
		return e.Expensive
	}
	var denominator int64
	for id, e := range anomalous {
		if !subsumed(id) {
			denominator += count(e)
		}
	}
	if denominator <= 0 {
		return Scope{Refused: RefusedZero}
	}
	for level := uint8(1); level <= 3; level++ {
		var keys []KeyID
		var covered int64
		for id, e := range anomalous {
			if id.Level == level {
				keys = append(keys, id)
				covered += count(e)
			}
		}
		if len(keys) > 0 && float64(covered)*100 >= c*float64(denominator) {
			slices.SortFunc(keys, keyOrder)
			return Scope{Level: level, Keys: keys, Covered: covered, Denominator: denominator, Basis: basis}
		}
	}
	return Scope{Denominator: denominator, Basis: basis}
}
