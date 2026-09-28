package crawlreplay

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
)

func TestScorerRequiresCoveredOnset(t *testing.T) {
	p := coldParams()
	span := Span{From: weekStart, To: weekStart + 9}
	for _, covered := range []bool{false, true} {
		t.Run(map[bool]string{false: "gap", true: "covered"}[covered], func(t *testing.T) {
			records := NewSynth(siteA, 1).Pool(Traffic{From: span.From + 3, To: span.From + 3,
				PerMinute: 1, Label: LabelAttack, Episode: "e1"}, 1)
			sc, err := NewScorer(p, []EpisodeTruth{{Episode: "e1", Label: LabelAttack, Site: siteA, Keys: []KeyID{truthSiteKey}}})
			if err != nil {
				t.Fatal(err)
			}
			if err = sc.Observe(siteA, records, []Span{span}); err != nil {
				t.Fatal(err)
			}
			coverage := []Span{{From: span.From, To: span.From + 2}, {From: span.From + 4, To: span.To}}
			want := OutcomeUnscored
			if covered {
				coverage, want = []Span{span}, OutcomeMissed
			}
			seg := segment(siteA, records, []Span{span}, coverage...)
			for _, tk := range feedTicks(t, mustSession(t, SessionConfig{Params: p}), seg) {
				sc.Tick(tk)
			}
			got := outcome(t, sc.Report(), siteA, "e1")
			if got.Status != want || got.Onset != records[0].T {
				t.Fatalf("outcome %+v, want %s at the original onset", got, want)
			}
		})
	}
}

// Splitting before the first counted request must not pin onset evidence
// to an earlier infrastructure or static request from the same episode.
func TestScorerRefreshesCountedOnsetEvidence(t *testing.T) {
	p := coldParams()
	span := Span{From: weekStart, To: weekStart + 29}
	truth := []EpisodeTruth{{Episode: "e1", Label: LabelAttack, Site: siteA, Keys: []KeyID{key1(2, 1)}}}
	for _, tc := range []struct {
		name       string
		background Span
		wantActive []KeyID
		wantStatus string
	}{
		{"finding starts after ignored request", Span{From: weekStart + 10, To: span.To},
			[]KeyID{truthSiteKey, key2(1), key1(2, 1)}, OutcomeMissed},
		{"finding clears before counted request", Span{From: weekStart, To: weekStart + 5},
			nil, OutcomeDetected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, infra := range []bool{false, true} {
				for _, split := range []bool{false, true} {
					syn := NewSynth(siteA, 7)
					records := syn.Rotating(Traffic{From: tc.background.From, To: tc.background.To, PerMinute: 30,
						L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 1)
					attack := syn.Rotating(Traffic{From: weekStart + 20, To: span.To, PerMinute: 120,
						L2: SynthKey(1), L1: SynthKey(2), Label: LabelAttack, Episode: "e1"}, 1)
					onset := attack[0].T
					for _, r := range attack {
						onset = min(onset, r.T)
					}
					records = append(records, attack...)
					ignored := Record{T: (weekStart+6)*60 + 5, Seq: 900000, Site: siteA,
						Class: ClassOther, Status: 200, Label: LabelAttack, Episode: "e1"}
					if infra {
						ignored.Infra, ignored.Class = true, ClassExpensive
						ignored.L2, ignored.L1 = SynthKey(1), SynthKey(2)
					}
					records = append(records, ignored)
					sc, err := NewScorer(p, truth)
					if err != nil {
						t.Fatal(err)
					}
					s := mustSession(t, SessionConfig{Params: p})
					spans := []Span{span}
					if split {
						spans = []Span{{From: span.From, To: weekStart + 9}, {From: weekStart + 10, To: span.To}}
					}
					for _, coverage := range spans {
						seg := segment(siteA, records, []Span{coverage}, coverage)
						if err := sc.Observe(siteA, seg.Records, seg.Score); err != nil {
							t.Fatal(err)
						}
						for _, tk := range feedTicks(t, s, seg) {
							sc.Tick(tk)
						}
					}
					got := outcome(t, sc.Report(), siteA, "e1")
					if got.Onset != onset || got.Status != tc.wantStatus || !slices.Equal(got.ActiveAtOnset, tc.wantActive) {
						t.Errorf("infra=%t split=%t: outcome %+v, want onset %d, status %s, active %v",
							infra, split, got, onset, tc.wantStatus, tc.wantActive)
					}
				}
			}
		})
	}
}

func TestScorerKeepsMissedAnomalousMargins(t *testing.T) {
	p := coldParams()
	span := Span{From: weekStart, To: weekStart + 20}
	syn := NewSynth(siteA, 1)
	records := syn.Rotating(Traffic{From: span.From, To: span.To, PerMinute: 30,
		L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 1)
	records = append(records, syn.Rotating(Traffic{From: span.From + 10, To: span.To, PerMinute: 120,
		L2: SynthKey(1), L1: SynthKey(2), Label: LabelAttack, Episode: "e1"}, 1)...)
	sc, _ := scoreSites(t, SessionConfig{Params: p}, []EpisodeTruth{{Episode: "e1", Label: LabelAttack,
		Site: siteA, Keys: []KeyID{key1(2, 1)}}}, map[string][]Record{siteA: records}, span)
	got := outcome(t, sc, siteA, "e1")
	if got.Status != OutcomeMissed || got.Detected || got.Worst.A1 < 1 || got.Worst.A2 < 1 {
		t.Fatalf("outcome %+v, want a missed transition with anomalous window margins", got)
	}
}

func TestScorerOwnsTruth(t *testing.T) {
	p := coldParams()
	span := Span{From: weekStart, To: weekStart + 9}
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "keys", true: "entry"}[replace], func(t *testing.T) {
			truth := []EpisodeTruth{{Episode: "e1", Label: LabelAttack, Site: siteA, Keys: []KeyID{key1(2, 1)}}}
			sc, err := NewScorer(p, truth)
			if err != nil {
				t.Fatal(err)
			}
			if replace {
				truth[0] = EpisodeTruth{Episode: "e2", Label: LabelAttack, Site: siteB, Keys: []KeyID{key1(3, 1)}}
			} else {
				truth[0].Keys[0] = key1(3, 1)
			}
			records := NewSynth(siteA, 1).Rotating(Traffic{From: span.From, To: span.To, PerMinute: 30,
				L2: SynthKey(1), L1: SynthKey(2), Label: LabelAttack, Episode: "e1"}, 1)
			if err = sc.Observe(siteA, records, []Span{span}); err != nil {
				t.Fatal(err)
			}
			for _, tk := range feedTicks(t, mustSession(t, SessionConfig{Params: p}), segment(siteA, records, []Span{span}, span)) {
				sc.Tick(tk)
			}
			got := outcome(t, sc.Report(), siteA, "e1")
			if !got.Detected || got.Key == nil || *got.Key != key1(2, 1) {
				t.Fatalf("caller changed validated truth: %+v", got)
			}
		})
	}
}

func TestScorerRejectedObservationDoesNotChangeOnset(t *testing.T) {
	p := coldParams()
	span := Span{From: weekStart, To: weekStart + 9}
	sc, err := NewScorer(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	syn := NewSynth(siteA, 1)
	records := syn.Pool(Traffic{From: span.From, To: span.From, PerMinute: 1,
		Label: LabelAttack, Episode: "e1"}, 1)
	bad := records[0]
	bad.Label = LabelOverload
	if err = sc.Observe(siteA, append(records, bad), []Span{span}); err != ErrTruth {
		t.Fatalf("conflicting labels: %v, want ErrTruth", err)
	}
	corrected := syn.Pool(Traffic{From: span.From + 3, To: span.From + 3, PerMinute: 1,
		Label: LabelOverload, Episode: "e1"}, 1)
	if err = sc.Observe(siteA, corrected, []Span{span}); err != nil {
		t.Fatalf("rejected records poisoned labels: %v", err)
	}
	for _, tk := range feedTicks(t, mustSession(t, SessionConfig{Params: p}), segment(siteA, corrected, []Span{span}, span)) {
		sc.Tick(tk)
	}
	got := outcome(t, sc.Report(), siteA, "e1")
	if got.Onset != corrected[0].T || got.Label != LabelOverload || got.Status != OutcomeMissed {
		t.Fatalf("rejected records changed outcome: %+v", got)
	}
}

func TestScorerOwnsEvidence(t *testing.T) {
	p := coldParams()
	span := Span{From: weekStart, To: weekStart + 20}
	syn := NewSynth(siteA, 1)
	records := syn.Rotating(Traffic{From: span.From, To: span.To, PerMinute: 30,
		L2: SynthKey(1), L1: SynthKey(2), Label: LabelAttack, Episode: "e1"}, 1)
	records = append(records, syn.Rotating(Traffic{From: span.From + 10, To: span.To, PerMinute: 120,
		L2: SynthKey(1), L1: SynthKey(3), Label: LabelAttack, Episode: "e2"}, 1)...)
	truth := []EpisodeTruth{
		{Episode: "e1", Label: LabelAttack, Site: siteA, Keys: []KeyID{key1(2, 1)}},
		{Episode: "e2", Label: LabelAttack, Site: siteA, Keys: []KeyID{key1(3, 1)}},
	}
	for _, boundary := range []string{"ticks", "report", "later ticks"} {
		t.Run(boundary, func(t *testing.T) {
			sc, err := NewScorer(p, truth)
			if err != nil {
				t.Fatal(err)
			}
			if err = sc.Observe(siteA, records, []Span{span}); err != nil {
				t.Fatal(err)
			}
			ticks := feedTicks(t, mustSession(t, SessionConfig{Params: p}), segment(siteA, records, []Span{span}, span))
			for _, tk := range ticks[:len(ticks)-1] {
				sc.Tick(tk)
			}
			report := sc.Report()
			before, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			switch boundary {
			case "ticks":
				for _, tk := range ticks {
					for _, ev := range tk.Events {
						clear(ev.Labels)
						clear(ev.Scope.Keys)
					}
				}
			case "report":
				for _, ev := range report.Events {
					clear(ev.Labels)
					clear(ev.Scope.Keys)
					clear(ev.Credited)
				}
				for _, ep := range report.Episodes {
					if ep.Key == nil || ep.Scope == nil {
						t.Fatalf("expected detected episode: %+v", ep)
					}
					*ep.Key = KeyID{}
					clear(ep.Scope.Keys)
					clear(ep.ActiveAtOnset)
				}
				clear(report.SiteDays[0].Requests)
			case "later ticks":
				sc.Tick(ticks[len(ticks)-1])
			}
			if boundary != "later ticks" {
				report = sc.Report()
			}
			after, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatalf("%s mutated previously scored evidence", boundary)
			}
		})
	}
}

// An episode whose first request fell in an unreplayed minute but whose
// later requests were replayed and scored without a correct transition is a
// miss, not an unscored episode.
func TestScorerMissesEpisodeAfterUncoveredOnset(t *testing.T) {
	p := coldParams()
	span := Span{From: weekStart, To: weekStart + 9}
	records := NewSynth(siteA, 1).Pool(Traffic{From: span.From + 3, To: span.From + 8,
		PerMinute: 1, Label: LabelAttack, Episode: "e1"}, 1)
	sc, err := NewScorer(p, []EpisodeTruth{{Episode: "e1", Label: LabelAttack, Site: siteA, Keys: []KeyID{truthSiteKey}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = sc.Observe(siteA, records, []Span{span}); err != nil {
		t.Fatal(err)
	}
	seg := segment(siteA, records, []Span{span}, Span{From: span.From, To: span.From + 2}, Span{From: span.From + 4, To: span.To})
	for _, tk := range feedTicks(t, mustSession(t, SessionConfig{Params: p}), seg) {
		sc.Tick(tk)
	}
	got := outcome(t, sc.Report(), siteA, "e1")
	if got.Status != OutcomeMissed || got.Detected || got.Onset != records[0].T {
		t.Fatalf("outcome %+v, want missed at the original onset", got)
	}
}

func TestScorerKeepsMissAcrossOverlappingDeclarations(t *testing.T) {
	p := coldParams()
	span := Span{From: weekStart, To: weekStart + 9}
	records := NewSynth(siteA, 1).Pool(Traffic{From: span.From + 3, To: span.From + 3,
		PerMinute: 1, Label: LabelAttack, Episode: "e1"}, 1)
	sc, err := NewScorer(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := mustSession(t, SessionConfig{Params: p})
	for _, seg := range []ReplaySegment{
		segment(siteA, records, []Span{span}, Span{From: span.From, To: span.From + 4}),
		segment(siteA, nil, []Span{{From: span.From + 1, To: span.From + 2}}, Span{From: span.From + 5, To: span.To}),
	} {
		if err = sc.Observe(siteA, seg.Records, seg.Score); err != nil {
			t.Fatal(err)
		}
		for _, tk := range feedTicks(t, s, seg) {
			sc.Tick(tk)
		}
		if got := outcome(t, sc.Report(), siteA, "e1"); got.Status != OutcomeMissed || got.Onset != records[0].T {
			t.Fatalf("outcome %+v, want original scored miss", got)
		}
	}
}

// Onset and the replayed evidence come from requests the detector counts:
// infrastructure and static requests inside a labeled range never move the
// onset or make an unreplayable episode a miss.
func TestScorerCountsOnlyEligibleRequests(t *testing.T) {
	p := coldParams()
	span := Span{From: weekStart, To: weekStart + 29}
	truth := []EpisodeTruth{{Episode: "e1", Label: LabelAttack, Site: siteA, Keys: []KeyID{key1(2, 1)}}}
	score := func(t *testing.T, recs []Record) EpisodeResult {
		t.Helper()
		sc, err := NewScorer(p, truth)
		if err != nil {
			t.Fatal(err)
		}
		if err = sc.Observe(siteA, recs, []Span{span}); err != nil {
			t.Fatal(err)
		}
		for _, tk := range feedTicks(t, mustSession(t, SessionConfig{Params: p}), segment(siteA, recs, []Span{span}, span)) {
			sc.Tick(tk)
		}
		return outcome(t, sc.Report(), siteA, "e1")
	}
	syn := NewSynth(siteA, 3)
	attack := syn.Rotating(Traffic{From: span.From + 20, To: span.From + 25, PerMinute: 60, L2: SynthKey(1), L1: SynthKey(2),
		Label: LabelAttack, Episode: "e1"}, 1)
	probe := Record{T: (span.From+2)*60 + 5, Seq: 900000, Site: siteA, Binding: "b-00000000000000aa", Class: ClassExpensive,
		L2: SynthKey(1), L1: SynthKey(2), Status: 200, Infra: true, Label: LabelAttack, Episode: "e1"}
	static := probe
	static.Infra, static.Class, static.L2, static.L1, static.Seq = false, ClassOther, "", "", 900001

	t.Run("ineligible requests do not move the onset", func(t *testing.T) {
		first := attack[0].T
		for _, r := range attack {
			first = min(first, r.T)
		}
		got := score(t, append([]Record{probe, static}, attack...))
		if !got.Detected || got.Onset != first || got.DelaySeconds != (got.DetectMinute+1)*60-first {
			t.Fatalf("outcome %+v, want onset at the first counted request %d", got, first)
		}
	})
	t.Run("only ineligible requests are not scored", func(t *testing.T) {
		got := score(t, []Record{probe, static})
		if got.Status != OutcomeUnscored || got.Detected {
			t.Fatalf("outcome %+v, want not_scored", got)
		}
	})
}
