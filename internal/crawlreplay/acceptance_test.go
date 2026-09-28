package crawlreplay

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const (
	siteA = "dom-00000a.example"
	siteB = "dom-00000b.example"
)

func key1(n, parent uint64) KeyID { return KeyID{Level: 1, Key: SynthKey(n), Parent: SynthKey(parent)} }
func key2(n uint64) KeyID         { return KeyID{Level: 2, Key: SynthKey(n)} }

var siteKey = KeyID{Level: 3}

// run feeds each site's records as one scored, normal segment through one
// session and scores the ticks.
func scoreSites(t *testing.T, cfg SessionConfig, truth []EpisodeTruth, sites map[string][]Record, coverage Span) (Scoring, []Tick) {
	t.Helper()
	s := mustSession(t, cfg)
	sc, err := NewScorer(cfg.Params, truth)
	if err != nil {
		t.Fatal(err)
	}
	var ticks []Tick
	for _, name := range slices.Sorted(maps.Keys(sites)) {
		seg := segment(name, sites[name], []Span{coverage}, coverage)
		if err := sc.Observe(name, sites[name], seg.Score); err != nil {
			t.Fatal(err)
		}
		ticks = append(ticks, feedTicks(t, s, seg)...)
	}
	for _, tk := range ticks {
		sc.Tick(tk)
	}
	return sc.Report(), ticks
}

func outcome(t *testing.T, sc Scoring, site, episode string) EpisodeResult {
	t.Helper()
	for _, r := range sc.Episodes {
		if r.Site == site && r.Episode == episode {
			return r
		}
	}
	t.Fatalf("no outcome for %s on %s", episode, site)
	return EpisodeResult{}
}

func scoredEventsFor(sc Scoring, site string, id KeyID) []ScoredEvent {
	var out []ScoredEvent
	for _, e := range sc.Events {
		if e.Site == site && e.Key == id {
			out = append(out, e)
		}
	}
	return out
}

func coldParams() Params {
	return Params{W: 5, R: 3, F: 1, K: 2, D: 4, C: 80, Baseline: BaselineParams{Alpha: 0.5, MinObs: 1, MinAge: 1 << 40, FloorPerMin: 1}}
}

func TestFindingTransitionEvidence(t *testing.T) {
	p := coldParams()
	start := weekStart + 3*60
	span := Span{From: start, To: start + 59}

	t.Run("event evidence", func(t *testing.T) {
		syn := NewSynth(siteA, 1)
		recs := syn.Pool(Traffic{From: start, To: start + 59, PerMinute: 4, L2: SynthKey(9), L1: SynthKey(8), Label: LabelHealthy}, 3)
		recs = append(recs, syn.Rotating(Traffic{From: start + 20, To: start + 40, PerMinute: 30, L2: SynthKey(1), L1: SynthKey(2),
			Label: LabelAttack, Episode: "e1"}, 1)...)
		sk := &SketchParams{M: 8, H: 16, Seed: 2}
		sc, ticks := scoreSites(t, SessionConfig{Params: p, Sketch: sk}, []EpisodeTruth{{Episode: "e1", Label: LabelAttack, Site: siteA, Keys: []KeyID{key1(2, 1)}}},
			map[string][]Record{siteA: recs}, span)
		events := scoredEventsFor(sc, siteA, key1(2, 1))
		if len(events) != 1 || events[0].Minute != start+20 {
			t.Fatalf("attack key events %+v, want one at minute 20", events)
		}
		ev := events[0]
		// Recount the window from the records, independently of the replay.
		labels := map[string]int64{}
		var window [][]string
		for m := ev.Minute - int64(p.W) + 1; m <= ev.Minute; m++ {
			var arrivals []string
			for _, r := range recs {
				if r.T/60 == m && r.L1 == SynthKey(2) {
					labels[labelKey(r.Label, r.Episode)]++
					arrivals = append(arrivals, r.Binding)
				}
			}
			window = append(window, arrivals)
		}
		exactN, exactD := exactOf(window, p.K)
		a1, a2 := p.Margins(exactN, exactD, float64(p.W)*p.Baseline.FloorPerMin)
		bounds := composeSketches(sketchesOf(*sk, window), p.K, sk.H)
		b1, b2 := p.Margins(bounds.LN, bounds.LD, float64(p.W)*p.Baseline.FloorPerMin)
		var tick Tick
		for _, tk := range ticks {
			if tk.Site == siteA && tk.Minute == ev.Minute {
				tick = tk
			}
		}
		want := FindingEvent{Site: siteA, Key: key1(2, 1), Minute: start + 20, Total: 30, Expensive: 30, Expected: float64(p.W) * p.Baseline.FloorPerMin,
			Exact: Margin{A1: a1, A2: a2}, Bound: Margin{A1: b1, A2: b2}, Scope: tick.Scope, Labels: labels, CoveredFrom: start}
		if !reflect.DeepEqual(ev.FindingEvent, want) {
			t.Fatalf("event %+v\nwant  %+v", ev.FindingEvent, want)
		}
		if ev.Class != LabelAttack || !slices.Equal(ev.Credited, []string{"e1"}) {
			t.Fatalf("class %s credited %v, want attack credited to e1", ev.Class, ev.Credited)
		}
		// Events persist as JSON with every field.
		raw, err := json.Marshal(sc)
		if err != nil {
			t.Fatal(err)
		}
		var back Scoring
		if err := json.Unmarshal(raw, &back); err != nil || !reflect.DeepEqual(back.Events, sc.Events) {
			t.Fatalf("events do not round-trip: %v", err)
		}
	})

	t.Run("a majority change on an anomalous key is not a finding", func(t *testing.T) {
		// A healthy campaign makes the key anomalous; an attack joins it
		// later and becomes the window majority. No transition happens, so
		// nothing detects the attack, by truth or by suggestion.
		syn := NewSynth(siteA, 2)
		recs := syn.Rotating(Traffic{From: start, To: start + 40, PerMinute: 30, L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 1)
		recs = append(recs, syn.Rotating(Traffic{From: start + 15, To: start + 40, PerMinute: 120, L2: SynthKey(1), L1: SynthKey(2),
			Label: LabelAttack, Episode: "e1"}, 1)...)
		for _, truth := range [][]EpisodeTruth{nil, {{Episode: "e1", Label: LabelAttack, Site: siteA, Keys: []KeyID{key1(2, 1), key2(1), siteKey}}}} {
			sc, _ := scoreSites(t, SessionConfig{Params: p}, truth, map[string][]Record{siteA: recs}, span)
			if ev := scoredEventsFor(sc, siteA, key1(2, 1)); len(ev) != 1 || ev[0].Minute != start+int64(p.W)-1 || ev[0].Class != LabelHealthy || len(ev[0].Credited) != 0 {
				t.Fatalf("truth %v: events %+v, want one healthy transition at the first complete window", truth != nil, ev)
			}
			if r := outcome(t, sc, siteA, "e1"); r.Detected || r.Status != OutcomeMissed || r.DetectMinute != 0 ||
				!slices.Contains(r.ActiveAtOnset, key1(2, 1)) {
				t.Fatalf("truth %v: outcome %+v, want missed with the key already active at onset", truth != nil, r)
			}
		}
	})

	t.Run("simultaneous and minority episodes", func(t *testing.T) {
		syn := NewSynth(siteA, 3)
		// e-big and e-small start together under one L2; only e-big is
		// anomalous on its own key. e-other runs at the same time on site B.
		a := syn.Rotating(Traffic{From: start + 10, To: start + 30, PerMinute: 100, L2: SynthKey(1), L1: SynthKey(2), Label: LabelAttack, Episode: "e-big"}, 1)
		a = append(a, syn.Pool(Traffic{From: start + 10, To: start + 30, PerMinute: 3, L2: SynthKey(1), L1: SynthKey(3), Label: LabelAttack, Episode: "e-small"}, 2)...)
		// Unlabeled and mixed traffic that turns anomalous stays for review.
		a = append(a, syn.Rotating(Traffic{From: start + 40, To: start + 50, PerMinute: 60, L2: SynthKey(7), L1: SynthKey(6)}, 1)...)
		a = append(a, syn.Rotating(Traffic{From: start + 40, To: start + 50, PerMinute: 30, L2: SynthKey(5), L1: SynthKey(4), Label: LabelHealthy}, 1)...)
		a = append(a, syn.Rotating(Traffic{From: start + 40, To: start + 50, PerMinute: 30, L2: SynthKey(5), L1: SynthKey(4), Label: LabelAttack, Episode: "e-mixed"}, 1)...)
		b := NewSynth(siteB, 4).Rotating(Traffic{From: start + 10, To: start + 30, PerMinute: 100, L2: SynthKey(1), L1: SynthKey(2), Label: LabelAttack, Episode: "e-other"}, 1)
		truth := []EpisodeTruth{
			{Episode: "e-big", Label: LabelAttack, Site: siteA, Keys: []KeyID{key1(2, 1), key2(1), siteKey}},
			// The unlabeled traffic's L2 key transitions after e-small's
			// onset but holds none of its requests: no credit.
			{Episode: "e-small", Label: LabelAttack, Site: siteA, Keys: []KeyID{key1(3, 1), key2(7)}},
			{Episode: "e-mixed", Label: LabelAttack, Site: siteA, Keys: []KeyID{key1(4, 5)}},
			{Episode: "e-other", Label: LabelAttack, Site: siteB, Keys: []KeyID{key1(2, 1)}},
		}
		sc, _ := scoreSites(t, SessionConfig{Params: p}, truth, map[string][]Record{siteA: a, siteB: b}, span)
		big, other := outcome(t, sc, siteA, "e-big"), outcome(t, sc, siteB, "e-other")
		for _, r := range []EpisodeResult{big, other} {
			if !r.Detected || r.DetectMinute != start+10 || r.DelaySeconds != (start+11)*60-r.Onset {
				t.Fatalf("%s on %s: %+v, want detection at minute 10", r.Episode, r.Site, r)
			}
		}
		small := outcome(t, sc, siteA, "e-small")
		if small.Detected || small.Status != OutcomeMissed {
			t.Fatalf("minority attack %+v, want missed rather than credited with its parent's finding", small)
		}
		parent := scoredEventsFor(sc, siteA, key2(1))
		if len(parent) != 1 || parent[0].Labels["attack/e-small"] == 0 || !slices.Equal(parent[0].Credited, []string{"e-big"}) {
			t.Fatalf("parent events %+v: the minority's requests must be counted but not credited", parent)
		}
		unlabeled := scoredEventsFor(sc, siteA, key1(6, 7))
		mixed := scoredEventsFor(sc, siteA, key1(4, 5))
		if len(unlabeled) != 1 || unlabeled[0].Class != "unlabeled" || len(unlabeled[0].Credited) != 0 {
			t.Fatalf("unlabeled transition %+v, want it kept for review uncredited", unlabeled)
		}
		if len(mixed) != 1 || !slices.Equal(mixed[0].Credited, []string{"e-mixed"}) {
			t.Fatalf("mixed transition %+v, want it kept and credited by truth", mixed)
		}
	})

	t.Run("truth tables are closed", func(t *testing.T) {
		good := EpisodeTruth{Episode: "e1", Label: LabelAttack, Site: siteA, Keys: []KeyID{key1(2, 1)}}
		for name, truth := range map[string][]EpisodeTruth{
			"duplicate episode and site": {good, good},
			"conflicting label":          {good, {Episode: "e1", Label: LabelOverload, Site: siteB, Keys: []KeyID{key1(2, 1)}}},
			"healthy label":              {{Episode: "e1", Label: LabelHealthy, Site: siteA, Keys: []KeyID{key1(2, 1)}}},
			"no keys":                    {{Episode: "e1", Label: LabelAttack, Site: siteA}},
			"malformed key":              {{Episode: "e1", Label: LabelAttack, Site: siteA, Keys: []KeyID{{Level: 1, Key: SynthKey(2)}}}},
			"repeated key":               {{Episode: "e1", Label: LabelAttack, Site: siteA, Keys: []KeyID{key2(1), key2(1)}}},
			"site not a pseudonym":       {{Episode: "e1", Label: LabelAttack, Site: "example.com", Keys: []KeyID{key2(1)}}},
		} {
			if _, err := NewScorer(p, truth); err != ErrTruth {
				t.Errorf("%s: %v, want ErrTruth", name, err)
			}
		}
		sc, err := NewScorer(p, []EpisodeTruth{good})
		if err != nil {
			t.Fatal(err)
		}
		overload := NewSynth(siteA, 5).Rotating(Traffic{From: start, To: start, PerMinute: 1, L2: SynthKey(1), L1: SynthKey(2), Label: LabelOverload, Episode: "e1"}, 1)
		if err := sc.Observe(siteA, overload, []Span{span}); err != ErrTruth {
			t.Fatalf("record label disagreeing with the truth: %v, want ErrTruth", err)
		}
		untold := NewSynth(siteA, 6).Rotating(Traffic{From: start, To: start, PerMinute: 1, L2: SynthKey(1), L1: SynthKey(2), Label: LabelAttack, Episode: "e2"}, 1)
		if err := sc.Observe(siteA, untold, []Span{span}); err != ErrTruth {
			t.Fatalf("scored episode without truth: %v, want ErrTruth", err)
		}
		if err := sc.Observe(siteA, untold, nil); err != nil {
			t.Fatalf("a training segment needs no truth: %v", err)
		}
	})
}

func TestSketchLearningFeedback(t *testing.T) {
	p := Params{W: 5, R: 3, F: 1, K: 1, D: 4, C: 80, Baseline: BaselineParams{Alpha: 0.5, MinObs: 1, MinAge: 0, FloorPerMin: 1}}
	// Four hash values leave the sketch at most three distinct bindings
	// after removing one: every attack stays below D for the sketch, while
	// the exact residual sees each fresh client.
	sk := &SketchParams{M: 4, H: 8, Hash: func(b string) uint64 { return uint64(b[len(b)-1] % 4) }}
	start := weekStart + 14*60
	syn := NewSynth(testSite, 8)
	recs := syn.Pool(Traffic{From: start, To: start + 89, PerMinute: 2, L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 2)
	// Just above the cold floor from its first minute: an exact session
	// flags it at once and freezes; the sketch session learns it.
	recs = append(recs, syn.Rotating(Traffic{From: start + 20, To: start + 34, PerMinute: 20, L2: SynthKey(1), L1: SynthKey(3),
		Label: LabelAttack, Episode: "e-near"}, 1)...)
	recs = append(recs, syn.Rotating(Traffic{From: start + 60, To: start + 69, PerMinute: 60, L2: SynthKey(1), L1: SynthKey(3),
		Label: LabelAttack, Episode: "e-burst"}, 1)...)
	site := Site{Records: recs, Coverage: []Span{{From: start, To: start + 89}}}
	truth := []EpisodeTruth{
		{Episode: "e-near", Label: LabelAttack, Site: testSite, Keys: []KeyID{key1(3, 1)}},
		{Episode: "e-burst", Label: LabelAttack, Site: testSite, Keys: []KeyID{key1(3, 1)}},
	}

	exactRep, err := EvaluateSite(site, p, Options{Truth: truth})
	if err != nil {
		t.Fatal(err)
	}
	sketchRep, err := EvaluateSite(site, p, Options{Truth: truth, Sketch: sk})
	if err != nil {
		t.Fatal(err)
	}
	for _, ep := range exactRep.Episodes {
		if !ep.Detected {
			t.Fatalf("exact session missed %s", ep.Episode)
		}
	}
	for _, ep := range sketchRep.Episodes {
		if ep.Detected {
			t.Fatalf("sketch session detected %s through colliding hashes", ep.Episode)
		}
	}
	acc := sketchRep.Sketch
	if acc.Exceeded != 0 || acc.MaxDistinctError == 0 {
		t.Fatalf("accuracy %+v, want sound bounds with distinct error", acc)
	}

	// Recount lost decisions from two independent sessions, and find the
	// minutes the sketch session's own exact check can no longer see
	// because its baseline learned the missed attack.
	exactTicks := feedTicks(t, mustSession(t, SessionConfig{Params: p}), normalSegment(site))
	sketchTicks := feedTicks(t, mustSession(t, SessionConfig{Params: p, Sketch: sk}), normalSegment(site))
	var lost, hidden, lostFindings int64
	for i, tk := range exactTicks {
		for _, ev := range tk.Events {
			if activeFor(sketchTicks[i], ev.Key) == nil {
				lostFindings++
			}
		}
		for _, e := range tk.Evaluations {
			if !e.Anomalous {
				continue
			}
			s := evalOf(sketchTicks[i], e.Key)
			if s == nil || !s.Anomalous {
				lost++
				if s != nil && !s.ExactAnomalous {
					hidden++
				}
			}
		}
	}
	if acc.LostDecisions != lost || hidden == 0 || acc.LostFindings != lostFindings || lostFindings < 2 {
		t.Fatalf("lost decisions %d (recounted %d, %d hidden from the sketch session's own exact check), lost findings %d (recounted %d)",
			acc.LostDecisions, lost, hidden, acc.LostFindings, lostFindings)
	}
}

// walkKeys calls fn for every object member name in a JSON document.
func walkKeys(v any, fn func(string)) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			fn(k)
			walkKeys(child, fn)
		}
	case []any:
		for _, child := range x {
			walkKeys(child, fn)
		}
	}
}

func TestAcceptancePerSiteKey(t *testing.T) {
	p := coldParams()
	start := weekStart + 20*60
	span := Span{From: start, To: start + 1439}
	// Site A: an earlier attack e0 leaves the L2 and site keys active while
	// a new attack e1 starts on a sibling L1 key. Healthy traffic on another
	// L2 key runs throughout.
	syn := NewSynth(siteA, 11)
	a := syn.Pool(Traffic{From: span.From, To: span.To, PerMinute: 2, L2: SynthKey(9), L1: SynthKey(8), Label: LabelHealthy}, 3)
	a = append(a, syn.Rotating(Traffic{From: start + 30, To: start + 60, PerMinute: 80, L2: SynthKey(1), L1: SynthKey(2), Label: LabelAttack, Episode: "e0"}, 1)...)
	a = append(a, syn.Rotating(Traffic{From: start + 50, To: start + 70, PerMinute: 80, L2: SynthKey(1), L1: SynthKey(3), Label: LabelAttack, Episode: "e1"}, 1)...)
	// Site B: an unrelated healthy campaign at the same time.
	b := NewSynth(siteB, 12).Rotating(Traffic{From: start + 30, To: start + 60, PerMinute: 80, L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 1)
	truth := []EpisodeTruth{
		{Episode: "e0", Label: LabelAttack, Site: siteA, Keys: []KeyID{key1(2, 1), key2(1)}},
		{Episode: "e1", Label: LabelAttack, Site: siteA, Keys: []KeyID{key1(3, 1), key2(1)}},
	}
	sc, _ := scoreSites(t, SessionConfig{Params: p}, truth, map[string][]Record{siteA: a, siteB: b}, span)

	type found struct {
		key    KeyID
		minute int64
	}
	got := map[string][]found{}
	for _, e := range sc.Events {
		got[e.Site] = append(got[e.Site], found{e.Key, e.Minute - start})
	}
	want := map[string][]found{
		siteA: {{siteKey, 30}, {key2(1), 30}, {key1(2, 1), 30}, {key1(3, 1), 50}},
		siteB: {{siteKey, 30}, {key2(1), 30}, {key1(2, 1), 30}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("High transitions %v, want %v", got, want)
	}
	e0, e1 := outcome(t, sc, siteA, "e0"), outcome(t, sc, siteA, "e1")
	if !e0.Detected || e0.DetectMinute != start+30 || e0.DelaySeconds != (start+31)*60-e0.Onset {
		t.Fatalf("e0 %+v, want detection at minute 30", e0)
	}
	if !e1.Detected || *e1.Key != key1(3, 1) || e1.DetectMinute != start+50 || e1.DelaySeconds != (start+51)*60-e1.Onset {
		t.Fatalf("e1 %+v, want detection on its own key at minute 50", e1)
	}
	// e1 began under findings already active on its parent and the site:
	// they are recorded, never credited, and its scope match is explicit.
	if !reflect.DeepEqual(e1.ActiveAtOnset, []KeyID{siteKey, key2(1)}) || e1.ScopeMatch == "" || e1.Scope == nil {
		t.Fatalf("e1 %+v, want the active parent and site recorded with its scope", e1)
	}
	// e0 is first credited on its L2 key while the scope names only its L1
	// key; e1's own L1 key is in the scope chosen when it transitions.
	if *e0.Key != key2(1) || e0.ScopeMatch != ScopeNarrower || !reflect.DeepEqual(e0.Scope.Keys, []KeyID{key1(2, 1)}) {
		t.Fatalf("e0 scope %s %+v at key %+v, want a narrower L1 scope", e0.ScopeMatch, *e0.Scope, *e0.Key)
	}
	if e1.ScopeMatch != ScopeExact || !reflect.DeepEqual(e1.Scope.Keys, []KeyID{key1(2, 1), key1(3, 1)}) {
		t.Fatalf("e1 scope %s %+v, want the L1 set naming its key", e1.ScopeMatch, *e1.Scope)
	}
	for _, e := range sc.Events {
		if e.Site == siteB && (e.Class != LabelHealthy || len(e.Credited) != 0) {
			t.Fatalf("site B event %+v, want an uncredited healthy transition", e)
		}
	}

	// Per site-day denominators, recounted from the records.
	days := map[string]map[string]int64{siteA: {}, siteB: {}}
	for site, recs := range map[string][]Record{siteA: a, siteB: b} {
		for _, r := range recs {
			days[site][r.Label]++
		}
	}
	if len(sc.SiteDays) != 4 {
		t.Fatalf("site days %+v, want two sites over two UTC days", sc.SiteDays)
	}
	totals := map[string]SiteDay{}
	for _, d := range sc.SiteDays {
		sum := totals[d.Site]
		sum.Minutes += d.Minutes
		sum.Events += d.Events
		sum.Credited += d.Credited
		if sum.Requests == nil {
			sum.Requests = map[string]int64{}
		}
		for l, n := range d.Requests {
			sum.Requests[l] += n
		}
		totals[d.Site] = sum
	}
	if a := totals[siteA]; a.Minutes != 1440 || a.Events != 4 || a.Credited != 3 || !maps.Equal(a.Requests, days[siteA]) {
		t.Fatalf("site A days %+v, want 1440 minutes, 4 events (3 credited) and %v", a, days[siteA])
	}
	if b := totals[siteB]; b.Minutes != 1440 || b.Events != 3 || b.Credited != 0 || !maps.Equal(b.Requests, days[siteB]) {
		t.Fatalf("site B days %+v, want 1440 minutes, 3 uncredited events and %v", b, days[siteB])
	}

	// The harness decides High findings only: no severity, action or
	// enforcement output exists to assert on.
	raw, err := json.Marshal(sc)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	walkKeys(doc, func(k string) {
		for _, banned := range []string{"critical", "action", "enforce", "policy", "block", "challenge"} {
			if strings.Contains(strings.ToLower(k), banned) {
				t.Fatalf("scoring output has a %q member", k)
			}
		}
	})
}

func TestScoringSkipsTraining(t *testing.T) {
	p := coldParams()
	start := weekStart + 6*60
	train, score := Span{From: start, To: start + 59}, Span{From: start + 60, To: start + 119}
	syn := NewSynth(siteA, 13)
	recs := syn.Pool(Traffic{From: train.From, To: score.To, PerMinute: 2, L2: SynthKey(9), L1: SynthKey(8), Label: LabelHealthy}, 3)
	// e-train transitions in training and stays active into scoring;
	// e-late starts in scoring.
	recs = append(recs, syn.Rotating(Traffic{From: start + 40, To: start + 75, PerMinute: 80, L2: SynthKey(1), L1: SynthKey(2), Label: LabelAttack, Episode: "e-train"}, 1)...)
	recs = append(recs, syn.Rotating(Traffic{From: start + 90, To: start + 100, PerMinute: 80, L2: SynthKey(5), L1: SynthKey(4), Label: LabelAttack, Episode: "e-late"}, 1)...)
	truth := []EpisodeTruth{
		{Episode: "e-train", Label: LabelAttack, Site: siteA, Keys: []KeyID{key1(2, 1)}},
		{Episode: "e-late", Label: LabelAttack, Site: siteA, Keys: []KeyID{key1(4, 5)}},
	}
	s := mustSession(t, SessionConfig{Params: p})
	sc, err := NewScorer(p, truth)
	if err != nil {
		t.Fatal(err)
	}
	for _, seg := range []ReplaySegment{segment(siteA, recs, nil, train), segment(siteA, recs, []Span{score}, score)} {
		if err := sc.Observe(siteA, RestrictToCoverage(recs, seg.Coverage), seg.Score); err != nil {
			t.Fatal(err)
		}
		for _, tk := range feedTicks(t, s, seg) {
			sc.Tick(tk)
		}
	}
	got := sc.Report()
	for _, e := range got.Events {
		if e.Minute < score.From {
			t.Fatalf("training transition %+v was scored", e)
		}
	}
	if len(got.Events) != 3 || got.Events[0].Minute != start+90 {
		t.Fatalf("events %+v, want e-late's three transitions only", got.Events)
	}
	var starts []KeyID
	for _, st := range got.ScoreStarts {
		starts = append(starts, st.Key)
		if st.Since >= score.From || st.Site != siteA {
			t.Fatalf("score start %+v, want a finding active since training", st)
		}
	}
	if !reflect.DeepEqual(starts, []KeyID{siteKey, key2(1), key1(2, 1)}) {
		t.Fatalf("findings active when scoring began: %v", starts)
	}
	if o := outcome(t, got, siteA, "e-train"); o.Status != OutcomeUnscored || o.Detected {
		t.Fatalf("e-train %+v, want not scored", o)
	}
	if o := outcome(t, got, siteA, "e-late"); o.Status != OutcomeDetected || o.DetectMinute != start+90 {
		t.Fatalf("e-late %+v, want detected at minute 90", o)
	}
	var minutes int64
	for _, d := range got.SiteDays {
		minutes += d.Minutes
	}
	if minutes != 60 {
		t.Fatalf("site days count %d minutes, want the 60 scored", minutes)
	}
}

// Boundary evidence describes entry into the minute, even if it clears at
// that minute's evaluation. An ineligible request can mark episode onset
// without keeping an unrelated old anomaly alive.
func TestScoringBoundaryKeepsClearingFindings(t *testing.T) {
	p := Params{W: 2, R: 3, F: 1, K: 1, D: 2, C: 80,
		Baseline: BaselineParams{Alpha: 0.5, MinObs: 1, MinAge: 1 << 40, FloorPerMin: 1}}
	start := weekStart
	recs := NewSynth(testSite, 1).Rotating(Traffic{From: start, To: start + 4, PerMinute: 20,
		L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 1)
	const episode = "e-00000000000000d1"
	sc, err := NewScorer(p, []EpisodeTruth{{Episode: episode, Site: testSite, Label: LabelAttack, Keys: []KeyID{l1(2)}}})
	if err != nil {
		t.Fatal(err)
	}
	s := mustSession(t, SessionConfig{Params: p})
	train := segment(testSite, recs, nil, Span{From: start, To: start + 5})
	if err = sc.Observe(testSite, recs, nil); err != nil {
		t.Fatal(err)
	}
	for _, tk := range feedTicks(t, s, train) {
		sc.Tick(tk)
	}
	span := Span{From: start + 6, To: start + 6}
	request := Record{T: span.From*60 + 30, Seq: 1, Site: testSite, Class: ClassOther,
		Status: 200, Label: LabelAttack, Episode: episode}
	if err = sc.Observe(testSite, []Record{request}, []Span{span}); err != nil {
		t.Fatal(err)
	}
	for _, tk := range feedTicks(t, s, segment(testSite, []Record{request}, []Span{span}, span)) {
		if len(tk.Active) != 0 || len(tk.Events) != 0 {
			t.Fatalf("quiet window did not clear: %+v", tk)
		}
		sc.Tick(tk)
	}
	report := sc.Report()
	if len(report.ScoreStarts) != 3 {
		t.Fatalf("clearing findings missing at scoring entry: %+v", report.ScoreStarts)
	}
	if len(report.Episodes) != 1 || len(report.Episodes[0].ActiveAtOnset) != 3 || report.Episodes[0].Detected {
		t.Fatalf("onset lost prior findings or got false credit: %+v", report.Episodes)
	}
}

func TestClassifyLargeCounts(t *testing.T) {
	const total = int64(1<<63 - 1)
	for _, class := range []string{LabelHealthy, LabelAttack, LabelOverload} {
		name := class
		if class != LabelHealthy {
			name += "/e-00000000000000d1"
		}
		got, _ := classify(total, map[string]int64{name: total})
		if got != class {
			t.Errorf("class = %q, want %q without integer overflow", got, class)
		}
	}
}
