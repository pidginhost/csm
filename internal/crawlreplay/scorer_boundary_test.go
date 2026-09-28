package crawlreplay

import (
	"bytes"
	"encoding/json"
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
