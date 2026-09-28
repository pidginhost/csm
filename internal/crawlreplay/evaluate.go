package crawlreplay

import (
	"cmp"
	"errors"
	"maps"
	"math"
	"slices"
	"strings"
)

// Margin is a window's distance past A1 and A2; both at least 1 is anomalous.
type Margin struct {
	A1 float64 `json:"a1"`
	A2 float64 `json:"a2"`
}

func (m Margin) least() float64 { return min(m.A1, m.A2) }

// ErrTruth reports an episode truth table that is malformed or disagrees
// with itself or with the labeled records.
var ErrTruth = errors.New("crawlreplay: invalid episode truth")

// Outcomes of one episode on one site.
const (
	OutcomeDetected = "detected"   // a correct High transition at or after onset
	OutcomeMissed   = "missed"     // onset scored, no correct transition
	OutcomeUnscored = "not_scored" // onset outside every scored minute
	OutcomeAbsent   = "absent"     // the site logged no request of the episode
)

// How the scope selected at a detection relates to the detecting key.
const (
	ScopeExact    = "exact"    // the scope names the detecting key
	ScopeBroader  = "broader"  // the scope is a wider level
	ScopeNarrower = "narrower" // the scope is a narrower level
	ScopeOther    = "other"    // same level, other keys
	ScopeNone     = "none"     // no scope, or selection refused
)

// EpisodeTruth is the operator's predeclared truth for one episode on one
// site: the keys whose High transition correctly detects it. It is private
// and fixed before replay; the majority label of a window is only a
// suggestion for review, never this truth.
type EpisodeTruth struct {
	Episode string  `json:"episode"`
	Label   string  `json:"label"`
	Site    string  `json:"site"`
	Keys    []KeyID `json:"keys"`
}

// EpisodeResult is one episode's outcome on one site. Detection is the
// first correct High transition in a scored minute at or after the onset
// minute; DelaySeconds runs from onset to the end of that minute and
// excludes log flush, lateness watermark and tick delay, which the ledger
// adds from their own measurements.
type EpisodeResult struct {
	Episode          string  `json:"episode"`
	Label            string  `json:"label"`
	Site             string  `json:"site"`
	Status           string  `json:"status"`
	Onset            int64   `json:"onset,omitempty"` // first labeled request, Unix seconds
	Detected         bool    `json:"detected"`
	DetectMinute     int64   `json:"detect_minute,omitempty"`
	DelaySeconds     int64   `json:"delay_seconds,omitempty"`
	Key              *KeyID  `json:"key,omitempty"`
	AtDetection      Margin  `json:"at_detection"`       // margin the decision used
	ExactAtDetection Margin  `json:"exact_at_detection"` // margin of the exact residuals
	Scope            *Scope  `json:"scope,omitempty"`
	ScopeMatch       string  `json:"scope_match,omitempty"`
	ActiveAtOnset    []KeyID `json:"active_at_onset,omitempty"` // relevant findings already active: no credit
	// Best is the relevant scored window after onset closest to anomalous;
	// Worst is the least anomalous among anomalous ones.
	Best  Margin `json:"best"`
	Worst Margin `json:"worst"`
}

// ScoredEvent is a High transition in a scored minute with its review
// fields: the machine-suggested majority class of its window and the
// episodes it correctly detects.
type ScoredEvent struct {
	FindingEvent
	Class    string   `json:"class"`
	Credited []string `json:"credited,omitempty"`
}

// SiteDay is one site's scored evidence for one UTC day: the denominators
// a false-positive rate needs, and every transition.
type SiteDay struct {
	Site     string           `json:"site"`
	Day      int64            `json:"day"`      // Unix day
	Minutes  int64            `json:"minutes"`  // scored covered minutes
	Judged   int64            `json:"judged"`   // of those, with a complete window
	Requests map[string]int64 `json:"requests"` // eligible requests by label, "" unlabeled
	Events   int              `json:"events"`   // High transitions
	Credited int              `json:"credited"` // of those, correct detections
}

// ScoreStart is a finding already active when a site's scoring began.
type ScoreStart struct {
	Site string `json:"site"`
	ActiveFinding
}

// Scoring is what a scorer found in the scored minutes.
type Scoring struct {
	Events      []ScoredEvent   `json:"events"`
	Episodes    []EpisodeResult `json:"episodes"`
	SiteDays    []SiteDay       `json:"site_days"`
	ScoreStarts []ScoreStart    `json:"active_at_score_start"`
}

type episodeSite struct{ episode, site string }

type siteDay struct {
	site string
	day  int64
}

type onset struct {
	t       int64
	minutes []int64 // every minute holding one of the episode's requests, ascending
	seen    bool    // the findings active at the onset minute are recorded
}

// Scorer turns a session's ticks into scored evidence. Without a truth
// table it credits a transition to the majority episode of its window: a
// suggestion for synthetic fixtures and review, not a qualified outcome.
type Scorer struct {
	p         Params
	suggest   bool
	truth     map[episodeSite]*EpisodeTruth
	labels    map[string]string // episode -> label
	onsets    map[episodeSite]*onset
	declared  map[string][]Span // scoring spans the segments declared
	scored    map[string][]Span // scored minutes actually replayed
	results   map[episodeSite]*EpisodeResult
	events    []ScoredEvent
	days      map[siteDay]*SiteDay
	wasScored map[string]bool
	starts    []ScoreStart
}

// NewScorer checks a truth table: pseudonymous sites, episodes and keys,
// episodic labels, and one definition per episode and site with one label
// per episode. It owns a copy of the table. A nil table scores by suggestion.
func NewScorer(p Params, truth []EpisodeTruth) (*Scorer, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	sc, err := newScorer(truth)
	if err != nil {
		return nil, err
	}
	sc.p = p
	return sc, nil
}

// ValidateTruth checks the declaration even when no replay was requested.
func ValidateTruth(truth []EpisodeTruth) error {
	_, err := newScorer(truth)
	return err
}

func newScorer(truth []EpisodeTruth) (*Scorer, error) {
	sc := &Scorer{suggest: truth == nil, truth: map[episodeSite]*EpisodeTruth{}, labels: map[string]string{},
		onsets: map[episodeSite]*onset{}, declared: map[string][]Span{}, scored: map[string][]Span{}, results: map[episodeSite]*EpisodeResult{},
		days: map[siteDay]*SiteDay{}, wasScored: map[string]bool{}}
	for _, tr := range truth {
		es := episodeSite{tr.Episode, tr.Site}
		if !episodeID.MatchString(tr.Episode) || !ValidSite(tr.Site) || (tr.Label != LabelAttack && tr.Label != LabelOverload) ||
			len(tr.Keys) == 0 || sc.truth[es] != nil {
			return nil, ErrTruth
		}
		if l, ok := sc.labels[tr.Episode]; ok && l != tr.Label {
			return nil, ErrTruth
		}
		seen := map[KeyID]bool{}
		for _, k := range tr.Keys {
			if !validKeyID(k) || seen[k] {
				return nil, ErrTruth
			}
			seen[k] = true
		}
		sc.labels[tr.Episode] = tr.Label
		tr.Keys = slices.Clone(tr.Keys)
		sc.truth[es] = &tr
	}
	return sc, nil
}

// Observe takes a segment's validated records, including those in minutes
// its coverage excludes, before its ticks: an episode's onset is its first
// labeled request whether or not that minute can be replayed. With a truth
// table, every episode in a segment with scored minutes needs an entry for
// its site, and a record's label must match its episode's. A rejected
// observation leaves the scorer unchanged.
func (sc *Scorer) Observe(site string, records []Record, score []Span) error {
	labels := maps.Clone(sc.labels)
	onsets := map[episodeSite]int64{}
	minutes := map[episodeSite][]int64{}
	for _, r := range records {
		if r.Validate() != nil || r.Site != site {
			return ErrSite
		}
		if r.Episode == "" {
			continue
		}
		es := episodeSite{r.Episode, site}
		if l, ok := labels[r.Episode]; ok && l != r.Label {
			return ErrTruth
		}
		if !sc.suggest && len(score) > 0 && sc.truth[es] == nil {
			return ErrTruth
		}
		labels[r.Episode] = r.Label
		if t, ok := onsets[es]; !ok || r.T < t {
			onsets[es] = r.T
		}
		minutes[es] = append(minutes[es], r.T/60)
	}
	sc.labels = labels
	for es, t := range onsets {
		o := sc.onsets[es]
		if o == nil {
			o = &onset{t: t}
			sc.onsets[es] = o
		}
		o.t = min(o.t, t)
		o.minutes = append(o.minutes, minutes[es]...)
		slices.Sort(o.minutes)
		o.minutes = slices.Compact(o.minutes)
	}
	sc.declared[site] = append(sc.declared[site], score...)
	return nil
}

// relevant reports whether a window of key speaks to episode es: a truth
// key holding the episode's requests or, by suggestion, a window whose
// majority is the episode.
func (sc *Scorer) relevant(es episodeSite, key KeyID, total int64, labels map[string]int64) bool {
	label := sc.labels[es.episode]
	if sc.suggest {
		class, episode := classify(total, labels)
		return class == label && episode == es.episode
	}
	tr := sc.truth[es]
	return tr != nil && slices.Contains(tr.Keys, key) && labels[labelKey(label, es.episode)] > 0
}

// near reports whether key is one of the episode's truth keys or an
// ancestor of one: a finding there already holds the episode's traffic.
func (sc *Scorer) near(es episodeSite, key KeyID) bool {
	if sc.suggest {
		return true
	}
	tr := sc.truth[es]
	if tr == nil {
		return false
	}
	for _, k := range tr.Keys {
		if k == key || slices.Contains(ancestors(k), key) {
			return true
		}
	}
	return false
}

func (sc *Scorer) result(es episodeSite) *EpisodeResult {
	r := sc.results[es]
	if r == nil {
		r = &EpisodeResult{Episode: es.episode, Label: sc.labels[es.episode], Site: es.site,
			Best: Margin{A1: math.Inf(-1), A2: math.Inf(-1)}, Worst: Margin{A1: math.Inf(1), A2: math.Inf(1)}}
		sc.results[es] = r
	}
	return r
}

// siteEpisodes lists the observed episodes of a site in a fixed order, so
// credit lists do not depend on map order.
func (sc *Scorer) siteEpisodes(site string) []episodeSite {
	var out []episodeSite
	for es := range sc.onsets {
		if es.site == site {
			out = append(out, es)
		}
	}
	slices.SortFunc(out, func(a, b episodeSite) int { return cmp.Compare(a.episode, b.episode) })
	return out
}

// Tick scores one tick of a session fed the observed segments, in order.
func (sc *Scorer) Tick(t Tick) {
	episodes := sc.siteEpisodes(t.Site)
	for _, es := range episodes {
		o := sc.onsets[es]
		if o.seen || t.Minute < o.t/60 {
			continue
		}
		o.seen = true
		for _, a := range t.Prior {
			if a.Since < o.t/60 && sc.near(es, a.Key) {
				r := sc.result(es)
				r.ActiveAtOnset = append(r.ActiveAtOnset, a.Key)
			}
		}
	}
	started := t.Scored && !sc.wasScored[t.Site]
	sc.wasScored[t.Site] = t.Scored
	if !t.Scored {
		return
	}
	// Declared scoring spans can include coverage gaps. Only a delivered
	// scored tick proves that its minute was actually replayed.
	spans := sc.scored[t.Site]
	if n := len(spans); n > 0 && spans[n-1].To == t.Minute-1 {
		spans[n-1].To = t.Minute
	} else {
		spans = append(spans, Span{From: t.Minute, To: t.Minute})
	}
	sc.scored[t.Site] = spans
	if started {
		for _, a := range t.Prior {
			if a.Since < t.Minute {
				sc.starts = append(sc.starts, ScoreStart{Site: t.Site, ActiveFinding: a})
			}
		}
	}
	day := siteDay{t.Site, t.Minute / 1440}
	d := sc.days[day]
	if d == nil {
		d = &SiteDay{Site: t.Site, Day: day.day, Requests: map[string]int64{}}
		sc.days[day] = d
	}
	d.Minutes++
	if t.Complete {
		d.Judged++
	}
	for label, n := range t.Requests {
		d.Requests[label] += n
	}
	for _, e := range t.Evaluations {
		a1, a2 := sc.p.Margins(e.Residual, e.Distinct, e.Expected)
		margin := Margin{A1: a1, A2: a2}
		for _, es := range episodes {
			if !sc.relevant(es, e.Key, e.Total, e.Labels) {
				continue
			}
			r := sc.result(es)
			if margin.least() > r.Best.least() {
				r.Best = margin
			}
			if e.Anomalous && margin.least() < r.Worst.least() {
				r.Worst = margin
			}
		}
	}
	for _, ev := range t.Events {
		ev = cloneFindingEvent(ev)
		class, _ := classify(ev.Total, ev.Labels)
		se := ScoredEvent{FindingEvent: ev, Class: class}
		for _, es := range episodes {
			// A window holding the episode's requests cannot precede its
			// first request, so relevance also places it after onset.
			if !sc.relevant(es, ev.Key, ev.Total, ev.Labels) {
				continue
			}
			se.Credited = append(se.Credited, es.episode)
			if r := sc.result(es); !r.Detected {
				key, scope := ev.Key, ev.Scope
				r.Detected, r.DetectMinute, r.Key, r.Scope = true, t.Minute, &key, &scope
				r.DelaySeconds = (t.Minute+1)*60 - sc.onsets[es].t
				r.AtDetection, r.ExactAtDetection = ev.Bound, ev.Exact
				r.ScopeMatch = scopeMatch(ev.Scope, ev.Key)
			}
		}
		d.Events++
		if len(se.Credited) > 0 {
			d.Credited++
		}
		sc.events = append(sc.events, se)
	}
}

func scopeMatch(s Scope, key KeyID) string {
	switch {
	case s.Level == 0:
		return ScopeNone
	case slices.Contains(s.Keys, key):
		return ScopeExact
	case s.Level > key.Level:
		return ScopeBroader
	case s.Level < key.Level:
		return ScopeNarrower
	}
	return ScopeOther
}

// Report finishes the scoring: every truth entry, or every observed episode
// by suggestion, gets an outcome. The returned evidence is independent of
// the scorer and remains unchanged by later ticks.
func (sc *Scorer) Report() Scoring {
	out := Scoring{Events: slices.Clone(sc.events), Episodes: []EpisodeResult{}, SiteDays: []SiteDay{}, ScoreStarts: slices.Clone(sc.starts)}
	if out.Events == nil {
		out.Events = []ScoredEvent{}
	}
	if out.ScoreStarts == nil {
		out.ScoreStarts = []ScoreStart{}
	}
	for i := range out.Events {
		out.Events[i].FindingEvent = cloneFindingEvent(out.Events[i].FindingEvent)
		out.Events[i].Credited = slices.Clone(out.Events[i].Credited)
	}
	keys := slices.Collect(maps.Keys(sc.onsets))
	if !sc.suggest {
		keys = slices.Collect(maps.Keys(sc.truth))
	}
	for _, es := range keys {
		r := *sc.result(es)
		r.ActiveAtOnset = slices.Clone(r.ActiveAtOnset)
		if r.Key != nil {
			key := *r.Key
			r.Key = &key
		}
		if r.Scope != nil {
			scope := cloneScope(*r.Scope)
			r.Scope = &scope
		}
		o := sc.onsets[es]
		switch {
		case o == nil:
			r.Status = OutcomeAbsent
		case r.Detected:
			r.Status, r.Onset = OutcomeDetected, o.t
		case !inSpans(sc.declared[es.site], o.t/60),
			!slices.ContainsFunc(o.minutes, func(m int64) bool { return inSpans(sc.scored[es.site], m) }):
			// It began outside scoring, or none of its requests was
			// replayed in a scored minute: not evidence of a miss.
			r.Status, r.Onset = OutcomeUnscored, o.t
		default:
			r.Status, r.Onset = OutcomeMissed, o.t
		}
		if math.IsInf(r.Worst.A1, 1) {
			r.Worst = Margin{}
		}
		if math.IsInf(r.Best.A1, -1) {
			r.Best = Margin{}
		}
		out.Episodes = append(out.Episodes, r)
	}
	slices.SortFunc(out.Episodes, func(a, b EpisodeResult) int {
		return cmp.Or(cmp.Compare(a.Site, b.Site), cmp.Compare(a.Episode, b.Episode))
	})
	for _, d := range sc.days {
		day := *d
		day.Requests = maps.Clone(day.Requests)
		out.SiteDays = append(out.SiteDays, day)
	}
	slices.SortFunc(out.SiteDays, func(a, b SiteDay) int { return cmp.Or(cmp.Compare(a.Site, b.Site), cmp.Compare(a.Day, b.Day)) })
	return out
}

func cloneFindingEvent(e FindingEvent) FindingEvent {
	e.Labels = maps.Clone(e.Labels)
	e.Scope = cloneScope(e.Scope)
	return e
}

func cloneScope(s Scope) Scope {
	s.Keys = slices.Clone(s.Keys)
	return s
}

// classify names the majority label of a window: attack or overload with
// the largest episode, healthy, or unlabeled when no label holds half.
func classify(total int64, labels map[string]int64) (class, episode string) {
	var attack, overload int64
	best := map[string]int64{}
	for key, n := range labels {
		label, _, found := strings.Cut(key, "/")
		if !found {
			continue
		}
		switch label {
		case LabelAttack:
			attack += n
		case LabelOverload:
			overload += n
		}
		best[key] = n
	}
	pick := func(label string) string {
		name, most := "", int64(-1)
		for key, n := range best {
			l, ep, _ := strings.Cut(key, "/")
			if l == label && (n > most || (n == most && ep < name)) {
				name, most = ep, n
			}
		}
		return name
	}
	switch {
	case total == 0:
		return "unlabeled", ""
	case attack >= total-attack:
		return LabelAttack, pick(LabelAttack)
	case overload >= total-overload:
		return LabelOverload, pick(LabelOverload)
	case labels[LabelHealthy] >= total-labels[LabelHealthy]:
		return LabelHealthy, ""
	}
	return "unlabeled", ""
}

// SketchAccuracy compares a sketch session with an exact session fed the
// same segments. The error fields compare bounds with the exact residuals
// of the same window; the decision fields compare the two sessions, whose
// baselines learn independently, so a sketch miss that trains its own
// baseline still counts as lost.
type SketchAccuracy struct {
	MaxResidualError int64 `json:"max_residual_error"`
	MaxDistinctError int64 `json:"max_distinct_error"`
	// Exceeded must stay zero: a bound above the exact value would make
	// the prototype unsound.
	Exceeded       int64 `json:"exceeded"`
	LostDecisions  int64 `json:"lost_decisions"`  // exact session anomalous, sketch session not
	ExtraDecisions int64 `json:"extra_decisions"` // sketch session anomalous, exact session not
	LostFindings   int64 `json:"lost_findings"`   // exact transitions with no sketch finding active then
}

// Pairing compares a sketch session's ticks with an exact session's ticks
// for the same segment, which the exact session is fed first.
type Pairing struct {
	anomalous   map[siteMinute]map[KeyID]bool
	transitions map[siteMinute][]KeyID
	acc         SketchAccuracy
}

// NewPairing starts an empty comparison.
func NewPairing() *Pairing {
	return &Pairing{anomalous: map[siteMinute]map[KeyID]bool{}, transitions: map[siteMinute][]KeyID{}}
}

// Exact records one exact-session tick.
func (pr *Pairing) Exact(t Tick) {
	sm := siteMinute{t.Site, t.Minute}
	for _, e := range t.Evaluations {
		if e.Anomalous {
			if pr.anomalous[sm] == nil {
				pr.anomalous[sm] = map[KeyID]bool{}
			}
			pr.anomalous[sm][e.Key] = true
		}
	}
	for _, ev := range t.Events {
		pr.transitions[sm] = append(pr.transitions[sm], ev.Key)
	}
}

// Sketch compares the sketch-session tick for the same site and minute.
func (pr *Pairing) Sketch(t Tick) {
	sm := siteMinute{t.Site, t.Minute}
	exact := pr.anomalous[sm]
	delete(pr.anomalous, sm)
	for _, e := range t.Evaluations {
		pr.acc.MaxResidualError = max(pr.acc.MaxResidualError, e.ExactResidual-e.Residual)
		pr.acc.MaxDistinctError = max(pr.acc.MaxDistinctError, e.ExactDistinct-e.Distinct)
		if e.Residual > e.ExactResidual || e.Distinct > e.ExactDistinct {
			pr.acc.Exceeded++
		}
		switch {
		case exact[e.Key] && !e.Anomalous:
			pr.acc.LostDecisions++
		case e.Anomalous && !exact[e.Key]:
			pr.acc.ExtraDecisions++
		}
		delete(exact, e.Key)
	}
	pr.acc.LostDecisions += int64(len(exact))
	for _, key := range pr.transitions[sm] {
		if !slices.ContainsFunc(t.Active, func(a ActiveFinding) bool { return a.Key == key }) {
			pr.acc.LostFindings++
		}
	}
	delete(pr.transitions, sm)
}

// Accuracy returns the comparison so far; exact decisions no sketch tick
// met count as lost.
func (pr *Pairing) Accuracy() SketchAccuracy {
	acc := pr.acc
	for _, keys := range pr.anomalous {
		acc.LostDecisions += int64(len(keys))
	}
	for _, keys := range pr.transitions {
		acc.LostFindings += int64(len(keys))
	}
	return acc
}

// Report is one site's replay outcome under one parameter set.
type Report struct {
	Episodes []EpisodeResult `json:"episodes"`
	Events   []ScoredEvent   `json:"events"`
	// Transitions counts High transitions by suggested class, and
	// FalsePositives the healthy-class ones per UTC day (Unix day number):
	// findings alert on transitions, not on minutes.
	Transitions    map[string]int  `json:"transitions"`
	FalsePositives map[int64]int   `json:"false_positives"`
	SiteDays       []SiteDay       `json:"site_days"`
	Evaluations    int64           `json:"evaluations"`
	Anomalous      int64           `json:"anomalous"`
	ScopeLevels    map[uint8]int   `json:"scope_levels"` // selected level at minutes with anomalies
	MaxActive      map[uint8]int   `json:"max_active"`   // most keys with traffic in one window, per level
	Keys           map[uint8]int   `json:"keys"`         // distinct keys seen, per level
	MaxBindings    int64           `json:"max_bindings"` // most distinct bindings in one key's window
	Sketch         *SketchAccuracy `json:"sketch,omitempty"`
}

// EvaluateSite replays one site cold, every covered minute scored and in
// normal learning state, and scores it against o.Truth or, without one, by
// suggestion. With a sketch it also runs an exact session and compares the
// two.
func EvaluateSite(site Site, p Params, o Options) (Report, error) {
	rep := Report{Transitions: map[string]int{}, FalsePositives: map[int64]int{}, ScopeLevels: map[uint8]int{},
		MaxActive: map[uint8]int{}, Keys: map[uint8]int{}}
	scorer, err := NewScorer(p, o.Truth)
	if err != nil {
		return Report{}, err
	}
	seg := normalSegment(site)
	if err = scorer.Observe(seg.Site, site.Records, seg.Score); err != nil {
		return Report{}, err
	}
	var pairing *Pairing
	if o.Sketch != nil {
		var exact *ReplaySession
		if exact, err = NewReplaySession(SessionConfig{Params: p, Shuffle: o.Shuffle}); err != nil {
			return Report{}, err
		}
		pairing = NewPairing()
		if err = exact.Feed(seg, func(t Tick) error { pairing.Exact(t); return nil }); err != nil {
			return Report{}, err
		}
	}
	s, err := NewReplaySession(SessionConfig{Params: p, Sketch: o.Sketch, Shuffle: o.Shuffle})
	if err != nil {
		return Report{}, err
	}
	seen := map[KeyID]bool{}
	err = s.Feed(seg, func(t Tick) error {
		scorer.Tick(t)
		if pairing != nil {
			pairing.Sketch(t)
		}
		perLevel := map[uint8]int{}
		anomalous := false
		for _, e := range t.Evaluations {
			rep.Evaluations++
			perLevel[e.Key.Level]++
			if !seen[e.Key] {
				seen[e.Key] = true
				rep.Keys[e.Key.Level]++
			}
			rep.MaxBindings = max(rep.MaxBindings, e.Bindings)
			if e.Anomalous {
				rep.Anomalous++
				anomalous = true
			}
		}
		for level, n := range perLevel {
			rep.MaxActive[level] = max(rep.MaxActive[level], n)
		}
		if anomalous {
			rep.ScopeLevels[t.Scope.Level]++
		}
		return nil
	})
	if err != nil {
		return Report{}, err
	}
	scoring := scorer.Report()
	rep.Episodes, rep.Events, rep.SiteDays = scoring.Episodes, scoring.Events, scoring.SiteDays
	for _, e := range scoring.Events {
		rep.Transitions[e.Class]++
		if e.Class == LabelHealthy {
			rep.FalsePositives[e.Minute/1440]++
		}
	}
	if pairing != nil {
		acc := pairing.Accuracy()
		rep.Sketch = &acc
	}
	return rep, nil
}
