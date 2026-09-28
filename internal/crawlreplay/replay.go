package crawlreplay

import (
	"cmp"
	"errors"
	"math"
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
	Trusted        bool             `json:"trusted"` // some window minute used a trained slot, not the floor
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

// Tick is one covered minute of one site. Evaluations hold every key whose
// window is complete and holds traffic or an active finding; Events hold the
// High transitions of this minute and Active every finding still active
// after it.
type Tick struct {
	Site        string
	Minute      int64
	Complete    bool // the site's last W covered minutes are known
	Scored      bool
	Evaluations []Evaluation
	Scope       Scope
	Events      []FindingEvent
	Active      []ActiveFinding
}

// ReplaySite runs a cold session over one site whose every covered minute
// is in normal learning state, and calls fn for every minute whose W-minute
// window is complete. It suits synthetic fixtures; recorded data declares
// its states through a session.
func ReplaySite(site Site, p Params, o Options, fn func(Tick)) error {
	s, err := NewReplaySession(SessionConfig{Params: p, Sketch: o.Sketch, Shuffle: o.Shuffle})
	if err != nil {
		return err
	}
	name := fixtureSiteName
	if len(site.Records) > 0 {
		name = site.Records[0].Site
	}
	seg := ReplaySegment{Site: name, Records: site.Records, Coverage: site.Coverage, Score: site.Coverage}
	if n := len(site.Coverage); n > 0 {
		seg.States = []StateSpan{{From: site.Coverage[0].From, To: site.Coverage[n-1].To, State: StateNormal}}
	}
	return s.Feed(seg, func(t Tick) error {
		if t.Complete {
			fn(t)
		}
		return nil
	})
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
