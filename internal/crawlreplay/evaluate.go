package crawlreplay

import (
	"cmp"
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

// EpisodeResult is one labeled attack or overload episode's outcome.
type EpisodeResult struct {
	Episode      string `json:"episode"`
	Label        string `json:"label"`
	Onset        int64  `json:"onset"` // first labeled request, Unix seconds
	Detected     bool   `json:"detected"`
	DetectMinute int64  `json:"detect_minute,omitempty"`
	// DelaySeconds runs from onset to the end of the detecting minute. It
	// excludes log flush, lateness watermark and tick delay, which the
	// ledger adds from their own measurements.
	DelaySeconds int64  `json:"delay_seconds,omitempty"`
	Level        uint8  `json:"level,omitempty"`
	AtDetection  Margin `json:"at_detection"`
	// Best is the episode-majority window closest to detection, anomalous
	// or not; Worst is its least anomalous window among anomalous ones.
	Best  Margin `json:"best"`
	Worst Margin `json:"worst"`
}

// Report is one site's replay outcome under one parameter set.
type Report struct {
	Episodes    []EpisodeResult `json:"episodes"`
	Transitions map[string]int  `json:"transitions"` // by window class
	// FalsePositives counts healthy-majority transitions per UTC day
	// (Unix day number): findings alert on transitions, not on minutes.
	FalsePositives map[int64]int   `json:"false_positives"`
	Evaluations    int64           `json:"evaluations"`
	Anomalous      int64           `json:"anomalous"`
	ScopeLevels    map[uint8]int   `json:"scope_levels"` // selected level at minutes with anomalies
	MaxActive      map[uint8]int   `json:"max_active"`   // most keys with traffic in one window, per level
	Keys           map[uint8]int   `json:"keys"`         // distinct keys seen, per level
	MaxBindings    int64           `json:"max_bindings"` // most distinct bindings in one key's window
	Sketch         *SketchAccuracy `json:"sketch,omitempty"`
}

// SketchAccuracy compares sketch bounds with the exact oracle.
type SketchAccuracy struct {
	MaxResidualError int64 `json:"max_residual_error"`
	MaxDistinctError int64 `json:"max_distinct_error"`
	LostDecisions    int64 `json:"lost_decisions"` // exact anomalous, sketch not
	// Exceeded must stay zero: a bound above the exact value would make
	// the prototype unsound.
	Exceeded int64 `json:"exceeded"`
}

// classify names the majority label of a window: attack or overload with
// the largest episode, healthy, or unlabeled when no label holds half.
func classify(e Evaluation) (class, episode string) {
	var attack, overload int64
	best := map[string]int64{}
	for key, n := range e.Labels {
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
	case 2*attack >= e.Total:
		return LabelAttack, pick(LabelAttack)
	case 2*overload >= e.Total:
		return LabelOverload, pick(LabelOverload)
	case 2*e.Labels[LabelHealthy] >= e.Total:
		return LabelHealthy, ""
	}
	return "unlabeled", ""
}

// EvaluateSite replays one site and summarizes detection, margins, false
// positives, key counts and, with a sketch, bound accuracy.
func EvaluateSite(site Site, p Params, o Options) (Report, error) {
	rep := Report{
		Transitions: map[string]int{}, FalsePositives: map[int64]int{}, ScopeLevels: map[uint8]int{},
		MaxActive: map[uint8]int{}, Keys: map[uint8]int{},
	}
	if o.Sketch != nil {
		rep.Sketch = &SketchAccuracy{}
	}
	episodes := map[string]*EpisodeResult{}
	for _, r := range site.Records {
		if r.Episode == "" {
			continue
		}
		ep := episodes[r.Episode]
		if ep == nil {
			ep = &EpisodeResult{Episode: r.Episode, Label: r.Label, Onset: r.T,
				Best: Margin{A1: math.Inf(-1), A2: math.Inf(-1)}, Worst: Margin{A1: math.Inf(1), A2: math.Inf(1)}}
			episodes[r.Episode] = ep
		}
		ep.Onset = min(ep.Onset, r.T)
	}
	seen := map[KeyID]bool{}
	prev := map[KeyID]bool{}
	err := ReplaySite(site, p, o, func(t Tick) {
		now := map[KeyID]bool{}
		perLevel := map[uint8]int{}
		for _, e := range t.Evaluations {
			rep.Evaluations++
			perLevel[e.Key.Level]++
			if !seen[e.Key] {
				seen[e.Key] = true
				rep.Keys[e.Key.Level]++
			}
			rep.MaxBindings = max(rep.MaxBindings, e.Bindings)
			if rep.Sketch != nil {
				rep.Sketch.MaxResidualError = max(rep.Sketch.MaxResidualError, e.ExactResidual-e.Residual)
				rep.Sketch.MaxDistinctError = max(rep.Sketch.MaxDistinctError, e.ExactDistinct-e.Distinct)
				if e.ExactAnomalous && !e.Anomalous {
					rep.Sketch.LostDecisions++
				}
				if e.Residual > e.ExactResidual || e.Distinct > e.ExactDistinct {
					rep.Sketch.Exceeded++
				}
			}
			class, name := classify(e)
			a1, a2 := p.Margins(e.Residual, e.Distinct, e.Expected)
			margin := Margin{A1: a1, A2: a2}
			if ep := episodes[name]; ep != nil && margin.least() > ep.Best.least() {
				ep.Best = margin
			}
			if !e.Anomalous {
				continue
			}
			rep.Anomalous++
			now[e.Key] = true
			if ep := episodes[name]; ep != nil {
				if margin.least() < ep.Worst.least() {
					ep.Worst = margin
				}
				if !ep.Detected {
					ep.Detected, ep.DetectMinute, ep.Level, ep.AtDetection = true, t.Minute, e.Key.Level, margin
					ep.DelaySeconds = (t.Minute+1)*60 - ep.Onset
				}
			}
			if prev[e.Key] {
				continue
			}
			rep.Transitions[class]++
			if class == LabelHealthy {
				rep.FalsePositives[t.Minute/1440]++
			}
		}
		for level, n := range perLevel {
			rep.MaxActive[level] = max(rep.MaxActive[level], n)
		}
		if len(now) > 0 {
			rep.ScopeLevels[t.Scope.Level]++
		}
		prev = now
	})
	if err != nil {
		return Report{}, err
	}
	for _, ep := range episodes {
		if !ep.Detected {
			ep.Worst = Margin{}
		}
		if math.IsInf(ep.Best.A1, -1) {
			ep.Best = Margin{}
		}
		rep.Episodes = append(rep.Episodes, *ep)
	}
	slices.SortFunc(rep.Episodes, func(a, b EpisodeResult) int { return cmp.Compare(a.Episode, b.Episode) })
	return rep, nil
}
