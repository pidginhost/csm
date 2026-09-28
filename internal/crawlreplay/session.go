package crawlreplay

import (
	"cmp"
	"errors"
	"math/rand/v2"
	"slices"
)

// ErrSession reports a segment, state declaration, snapshot or call that a
// replay session cannot accept. After a failed Feed callback the session
// refuses every further call: its state may be partly advanced.
var ErrSession = errors.New("crawlreplay: invalid replay session input")

// Learning states a segment declares for a site's or key's minutes (spec
// 6.4). The detector freezes learning in every state but normal, and the
// harness also freezes it for anomalous minutes and while a finding is
// active. A minute no declaration covers is unknown and never learned.
const (
	StateNormal       = "normal"
	StateProtected    = "protected"
	StateDegraded     = "degraded"
	StateRecoveryHold = "recovery_hold"
)

var learningStates = map[string]bool{StateNormal: true, StateProtected: true, StateDegraded: true, StateRecoveryHold: true}

// StateSpan declares the learning state over inclusive minutes, for one key
// or, when Key is nil, for every key of the segment's site. A key's own
// declaration wins over the site's.
type StateSpan struct {
	Key   *KeyID `json:"key,omitempty"`
	From  int64  `json:"from"`
	To    int64  `json:"to"`
	State string `json:"state"`
}

// ReplaySegment is one site's validated records over its coverage. A
// session takes each site's segments in chronological order; windows run on
// across adjacent segments exactly as within one.
type ReplaySegment struct {
	Site     string
	Records  []Record    // records in Coverage minutes only (RestrictToCoverage)
	Coverage []Span      // certified minutes without unknown loss
	Score    []Span      // minutes whose ticks are scored; nil trains only
	States   []StateSpan // after every minute this site was already fed
}

// SessionConfig fixes what a session's state means. A restored snapshot
// keeps only the state this configuration can still interpret.
type SessionConfig struct {
	Params          Params
	Sketch          *SketchParams // nil decides with exact residuals
	Shuffle         uint64        // nonzero permutes arrivals within each minute
	IdentityVersion int           // the key and binding pseudonym contract
}

func (c SessionConfig) validate() error {
	if err := c.Params.Validate(); err != nil {
		return err
	}
	if c.Sketch != nil && (c.Sketch.M <= c.Params.K || c.Sketch.H < c.Params.D+c.Params.K) {
		return ErrParams
	}
	if c.IdentityVersion < 0 {
		return ErrParams
	}
	return nil
}

func (c SessionConfig) clone() SessionConfig {
	if c.Sketch != nil {
		sketch := *c.Sketch
		c.Sketch = &sketch
	}
	return c
}

// ActiveFinding is a key whose High finding has not cleared. Uncertain
// means its evidence was interrupted, by a coverage gap or an incompatible
// restore, and no complete window has judged it since.
type ActiveFinding struct {
	Key       KeyID `json:"key"`
	Since     int64 `json:"since"`
	Uncertain bool  `json:"uncertain,omitempty"`
}

// FindingEvent is one pseudonymous High transition: a key without an active
// finding whose complete window is anomalous. It carries the window's
// evidence as the detector saw it at that minute.
type FindingEvent struct {
	Site      string  `json:"site"`
	Key       KeyID   `json:"key"`
	Minute    int64   `json:"minute"`
	Total     int64   `json:"total"`
	Expensive int64   `json:"expensive"`
	Expected  float64 `json:"expected"`
	// Exact is the margin of the exact window residuals; Bound is the
	// margin the decision used, the sketch bounds when a sketch decides.
	Exact  Margin           `json:"exact"`
	Bound  Margin           `json:"bound"`
	Scope  Scope            `json:"scope"`
	Labels map[string]int64 `json:"labels"` // window requests per label and episode
	// CoveredFrom is the first minute of the continuous coverage the window
	// lies in; Trusted reports that some window minute was judged against a
	// trained slot rather than the cold floor.
	CoveredFrom int64 `json:"covered_from"`
	Trusted     bool  `json:"trusted"`
}

// ReplaySession replays sites minute by minute and keeps, per site, the
// state a detector would: hour-of-week baselines with their learned-minute
// watermarks, W-minute windows and summaries, active findings with their
// pinned profiles, and keys whose detail was evicted.
type ReplaySession struct {
	cfg    SessionConfig
	sites  map[string]*siteSession
	broken bool
}

type siteSession struct {
	processedTo int64 // latest minute fed; 0 before the first
	coveredFrom int64 // first minute of the current continuous coverage
	windowFrom  int64 // first minute a window may count: coveredFrom, or later after an incompatible restore
	covered     []Span
	siteStates  []StateSpan
	keyStates   map[KeyID][]StateSpan
	keys        map[KeyID]*keyState
	active      map[KeyID]*keyState
	retired     map[KeyID]bool
}

type keyState struct {
	baseline  *Baseline
	window    *Window
	minutes   map[int64]*minuteCounts
	sketches  map[int64]*keySketch
	learnedTo int64 // latest minute learned, frozen or passed over
	// from is the first minute this key's own detail counts from: zero for
	// a key whose earlier zero minutes are known, the reintroduction minute
	// for a key whose detail was evicted.
	from    int64
	active  bool
	finding *finding
}

type finding struct {
	since     int64
	pin       Profile
	uncertain bool
}

// NewReplaySession starts a cold session with its own copy of cfg.
func NewReplaySession(cfg SessionConfig) (*ReplaySession, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &ReplaySession{cfg: cfg.clone(), sites: map[string]*siteSession{}}, nil
}

func newSiteSession() *siteSession {
	return &siteSession{keyStates: map[KeyID][]StateSpan{}, keys: map[KeyID]*keyState{},
		active: map[KeyID]*keyState{}, retired: map[KeyID]bool{}}
}

// Feed replays one segment and calls fn for every covered minute, scored
// or not. Each minute is judged against the state learned before it and
// only then learned, so nothing later in the segment informs an earlier
// decision. Coverage must start after every minute this site was fed.
func (s *ReplaySession) Feed(seg ReplaySegment, fn func(Tick) error) error {
	if s.broken {
		return ErrSession
	}
	if !ValidSite(seg.Site) {
		return ErrSite
	}
	buckets, err := bucketSite(seg.Site, seg.Records, seg.Coverage, s.cfg.Shuffle)
	if err != nil {
		return err
	}
	site := s.sites[seg.Site]
	if site == nil {
		site = newSiteSession()
	}
	if err = checkSegment(seg, site); err != nil {
		return err
	}
	s.sites[seg.Site] = site
	for _, st := range seg.States {
		if st.Key == nil {
			site.siteStates = append(site.siteStates, st)
		} else {
			// Keep the declaration's serialized key independent of a caller
			// reusing the variable that identified this scope.
			id := *st.Key
			st.Key = &id
			site.keyStates[id] = append(site.keyStates[id], st)
		}
	}
	slices.SortFunc(site.siteStates, func(a, b StateSpan) int { return cmp.Compare(a.From, b.From) })
	for id := range site.keyStates {
		slices.SortFunc(site.keyStates[id], func(a, b StateSpan) int { return cmp.Compare(a.From, b.From) })
	}
	s.broken = true
	for _, span := range seg.Coverage {
		for m := span.From; m <= span.To; m++ {
			tick := s.minute(seg.Site, site, m, buckets[m], inSpans(seg.Score, m))
			if err := fn(tick); err != nil {
				return err
			}
		}
	}
	s.broken = false
	return nil
}

// checkSegment validates scoring spans and state declarations before the
// session changes: every declared minute lies after the minutes already
// fed, and no two declarations for the same scope overlap, including the
// site's earlier ones.
func checkSegment(seg ReplaySegment, site *siteSession) error {
	processedTo := site.processedTo
	if len(seg.Coverage) > 0 && seg.Coverage[0].From <= processedTo {
		return ErrSession
	}
	for i, sp := range seg.Score {
		if sp.From <= 0 || sp.To < sp.From || (i > 0 && sp.From <= seg.Score[i-1].To) {
			return ErrSession
		}
	}
	byScope := map[KeyID][]StateSpan{{}: slices.Clone(site.siteStates)}
	for id, spans := range site.keyStates {
		byScope[id] = slices.Clone(spans)
	}
	siteScope := KeyID{}
	for _, st := range seg.States {
		if !learningStates[st.State] || st.From <= processedTo || st.To < st.From {
			return ErrSession
		}
		scope := siteScope
		if st.Key != nil {
			if !validKeyID(*st.Key) {
				return ErrSession
			}
			scope = *st.Key
		}
		for _, other := range byScope[scope] {
			if st.From <= other.To && other.From <= st.To {
				return ErrSession
			}
		}
		byScope[scope] = append(byScope[scope], st)
	}
	return nil
}

// ValidateStates checks declarations independently of replay coverage. This
// also validates diagnostic experiments, which never create a session.
func ValidateStates(states []StateSpan) error {
	return checkSegment(ReplaySegment{States: states}, newSiteSession())
}

// validKeyID reports a key of the closed stream format: the site key, an
// L2 key, or an L1 key with its L2 parent.
func validKeyID(id KeyID) bool {
	switch id.Level {
	case 3:
		return id.Key == "" && id.Parent == ""
	case 2:
		return keyPseudonym.MatchString(id.Key) && id.Parent == ""
	case 1:
		return keyPseudonym.MatchString(id.Key) && keyPseudonym.MatchString(id.Parent)
	}
	return false
}

func inSpans(spans []Span, m int64) bool {
	i, found := slices.BinarySearchFunc(spans, m, func(s Span, m int64) int { return cmp.Compare(s.To, m) })
	return found || (i < len(spans) && spans[i].From <= m)
}

// bucketSite checks one site's records against its coverage and groups the
// eligible ones by minute in logged order, before anything is replayed.
func bucketSite(name string, records []Record, coverage []Span, shuffle uint64) (map[int64][]*Record, error) {
	for i, s := range coverage {
		if s.From <= 0 || s.To < s.From || (i > 0 && s.From <= coverage[i-1].To) {
			return nil, ErrSite
		}
	}
	buckets := map[int64][]*Record{}
	for i := range records {
		r := &records[i]
		if r.Validate() != nil || r.Site != name || !inSpans(coverage, r.T/60) {
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

// state is the learning state of key id at minute m.
func (site *siteSession) state(id KeyID, m int64) string {
	for _, spans := range [][]StateSpan{site.keyStates[id], site.siteStates} {
		i, found := slices.BinarySearchFunc(spans, m, func(s StateSpan, m int64) int { return cmp.Compare(s.To, m) })
		if found || (i < len(spans) && spans[i].From <= m) {
			return spans[i].State
		}
	}
	return ""
}

// restart empties every window; findings stay active but uncertain until a
// complete window judges them.
func (site *siteSession) restart() {
	for id, ks := range site.active {
		ks.window, ks.minutes, ks.sketches = newWindow(), map[int64]*minuteCounts{}, map[int64]*keySketch{}
		if ks.finding != nil {
			ks.finding.uncertain = true
			continue
		}
		ks.active = false
		ks.minutes, ks.sketches = nil, nil
		delete(site.active, id)
	}
}

// key returns id's state, creating a cold key or reintroducing an evicted
// one, and activates it, first learning the zero minutes it sat idle through.
func (s *ReplaySession) key(site *siteSession, id KeyID, m int64) *keyState {
	ks := site.keys[id]
	if ks == nil {
		ks = &keyState{baseline: NewBaseline(s.cfg.Params.Baseline, m), window: newWindow(), learnedTo: m - 1}
		if site.retired[id] {
			// Evicted detail lost the minutes it was not tracked, so it
			// needs W observed minutes of its own before it can act.
			delete(site.retired, id)
			ks.from = m
		}
		site.keys[id] = ks
	}
	if !ks.active {
		site.foldIdle(ks, id, m)
		ks.active, ks.minutes, ks.sketches = true, map[int64]*minuteCounts{}, map[int64]*keySketch{}
		site.active[id] = ks
	}
	return ks
}

// foldIdle learns the covered minutes in normal state a key had no traffic
// in, before minute until. Uncovered and frozen minutes are passed over.
func (site *siteSession) foldIdle(ks *keyState, id KeyID, until int64) {
	for _, span := range site.covered {
		for m := max(ks.learnedTo+1, span.From); m <= min(until-1, span.To); m++ {
			if site.state(id, m) == StateNormal {
				ks.baseline.Observe(m, 0)
			}
		}
	}
	ks.learnedTo = max(ks.learnedTo, until-1)
}

func (s *ReplaySession) minute(name string, site *siteSession, m int64, records []*Record, scored bool) Tick {
	p := s.cfg.Params
	if site.processedTo == 0 || m != site.processedTo+1 {
		site.coveredFrom, site.windowFrom = m, m
		site.restart()
	}
	if n := len(site.covered); n > 0 && site.covered[n-1].To == m-1 {
		site.covered[n-1].To = m
	} else {
		site.covered = append(site.covered, Span{From: m, To: m})
	}
	for _, r := range records {
		var h uint64
		if s.cfg.Sketch != nil && r.Binding != "" {
			h = s.cfg.Sketch.hash(r.Binding)
		}
		for _, id := range keysOf(r) {
			ks := s.key(site, id, m)
			mc := ks.minutes[m]
			if mc == nil {
				mc = newMinuteCounts()
				ks.minutes[m] = mc
			}
			mc.add(r)
			if s.cfg.Sketch != nil && r.Binding != "" {
				sk := ks.sketches[m]
				if sk == nil {
					sk = newKeySketch(*s.cfg.Sketch)
					ks.sketches[m] = sk
				}
				sk.insert(r.Binding, h)
			}
		}
	}
	ids := make([]KeyID, 0, len(site.active))
	for id, ks := range site.active {
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
	tick := Tick{Site: name, Minute: m, Complete: m-site.windowFrom+1 >= int64(p.W), Scored: scored}
	var unknown []KeyID
	judged := map[KeyID]bool{}
	for _, id := range ids {
		ks := site.active[id]
		if m-max(site.windowFrom, ks.from)+1 < int64(p.W) {
			if ks.window.Total() > 0 {
				unknown = append(unknown, id)
			}
			continue
		}
		judged[id] = true
		if ks.window.Total() > 0 || ks.finding != nil {
			tick.Evaluations = append(tick.Evaluations, s.evaluate(ks, id, m))
		}
	}
	tick.Scope = selectScope(tick.Evaluations, p.C, unknown)
	for _, e := range tick.Evaluations {
		ks := site.active[e.Key]
		switch {
		case e.Anomalous && ks.finding == nil:
			ks.finding = &finding{since: m, pin: ks.baseline.Pin(m)}
			tick.Events = append(tick.Events, s.event(name, site, e, tick.Scope, m))
		case e.Anomalous:
			ks.finding.uncertain = false
		case ks.finding != nil:
			ks.finding = nil
		}
	}
	// An anomalous minute always leaves an active finding, so the finding
	// freezes learning for it as well as for every later minute until a
	// complete window clears it. Traffic no complete window judged may be an
	// attack and is never learned; a covered minute without traffic is.
	for _, id := range ids {
		ks := site.active[id]
		var total int64
		if mc := ks.minutes[m]; mc != nil {
			total = mc.total
		}
		if ks.finding == nil && (judged[id] || total == 0) && site.state(id, m) == StateNormal {
			ks.baseline.Observe(m, total)
		}
		ks.learnedTo = m
		if ks.finding != nil {
			tick.Active = append(tick.Active, ActiveFinding{Key: id, Since: ks.finding.since, Uncertain: ks.finding.uncertain})
		} else if ks.window.Total() == 0 {
			ks.active, ks.minutes, ks.sketches = false, nil, nil
			delete(site.active, id)
		}
	}
	site.processedTo = m
	return tick
}

func (s *ReplaySession) evaluate(ks *keyState, id KeyID, m int64) Evaluation {
	p := s.cfg.Params
	e := Evaluation{Key: id, Total: ks.window.Total(), Expensive: ks.window.Expensive(), Bindings: int64(len(ks.window.bindings)), Labels: ks.window.Labels()}
	e.ExactResidual, e.ExactDistinct = ks.window.Residual(p.K)
	expect := ks.baseline.expected
	if ks.finding != nil {
		expect = ks.finding.pin.expected
	}
	for j := m - int64(p.W) + 1; j <= m; j++ {
		v, trusted := expect(j)
		e.Expected += v
		e.Trusted = e.Trusted || trusted
	}
	e.ExactAnomalous = p.anomalous(e.ExactResidual, e.ExactDistinct, e.Expected)
	e.Residual, e.Distinct, e.Anomalous = e.ExactResidual, e.ExactDistinct, e.ExactAnomalous
	if s.cfg.Sketch != nil {
		minutes := make([]*keySketch, 0, p.W)
		for j := m - int64(p.W) + 1; j <= m; j++ {
			if sk := ks.sketches[j]; sk != nil {
				minutes = append(minutes, sk)
			}
		}
		bounds := composeSketches(minutes, p.K, s.cfg.Sketch.H)
		e.Residual, e.Distinct = bounds.LN, bounds.LD
		e.Anomalous = p.anomalous(e.Residual, e.Distinct, e.Expected)
	}
	return e
}

func (s *ReplaySession) event(name string, site *siteSession, e Evaluation, scope Scope, m int64) FindingEvent {
	p := s.cfg.Params
	exactA1, exactA2 := p.Margins(e.ExactResidual, e.ExactDistinct, e.Expected)
	a1, a2 := p.Margins(e.Residual, e.Distinct, e.Expected)
	return FindingEvent{Site: name, Key: e.Key, Minute: m, Total: e.Total, Expensive: e.Expensive, Expected: e.Expected,
		Exact: Margin{A1: exactA1, A2: exactA2}, Bound: Margin{A1: a1, A2: a2}, Scope: scope, Labels: e.Labels,
		CoveredFrom: site.coveredFrom, Trusted: e.Trusted}
}

// Evict drops a key's detail as a bounded detector would: its baseline,
// windows and summaries go, and when its traffic returns it starts cold and
// cannot act before W observed minutes of its own. The site key and keys
// with an active finding are never evicted.
func (s *ReplaySession) Evict(site string, id KeyID) error {
	ss := s.sites[site]
	if s.broken || ss == nil || id.Level == 3 || !validKeyID(id) {
		return ErrSession
	}
	ks := ss.keys[id]
	if ks == nil || ks.finding != nil {
		return ErrSession
	}
	delete(ss.keys, id)
	delete(ss.active, id)
	ss.retired[id] = true
	return nil
}
