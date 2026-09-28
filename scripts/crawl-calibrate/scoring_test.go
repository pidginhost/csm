package main

import (
	"testing"

	"github.com/pidginhost/csm/internal/crawlreplay"
)

func TestCalibrateKeepsMissAfterExcludedOnset(t *testing.T) {
	p := crawlreplay.Params{W: 5, R: 3, F: 1, K: 1, D: 4, C: 80,
		Baseline: crawlreplay.BaselineParams{Alpha: 0.5, MinObs: 1, FloorPerMin: 1}}
	records := crawlreplay.NewSynth(attackSite, 1).Pool(crawlreplay.Traffic{From: 100, To: 109,
		PerMinute: 1, Label: crawlreplay.LabelAttack, Episode: "e1"}, 1)
	r := newRunResult(gridRun{Params: p})
	coverage := []crawlreplay.Span{{From: 101, To: 109}}
	site := crawlreplay.Site{Records: crawlreplay.RestrictToCoverage(records, coverage), Coverage: coverage}
	if err := r.addSite(attackSite, site, episodeOrigins(records)); err != nil {
		t.Fatal(err)
	}
	if len(r.Episodes) != 1 {
		t.Fatalf("episodes = %+v, want one missed episode", r.Episodes)
	}
	ep := r.Episodes[0]
	if ep.Status != crawlreplay.OutcomeMissed || ep.Detected || ep.Onset != records[0].T {
		t.Fatalf("episode = %+v, want miss with the original onset", ep)
	}
}

func TestCalibrateAggregatesSketchFindings(t *testing.T) {
	p := crawlreplay.Params{W: 5, R: 3, F: 1, K: 1, D: 4, C: 80,
		Baseline: crawlreplay.BaselineParams{Alpha: 0.5, MinObs: 1, MinAge: 0, FloorPerMin: 1}}
	sk := &crawlreplay.SketchParams{M: 4, H: 8, Hash: func(b string) uint64 { return uint64(b[len(b)-1] % 4) }}
	span := crawlreplay.Span{From: 100, To: 119}
	r := newRunResult(gridRun{Params: p, Sketch: sk})
	for _, name := range []string{attackSite, quietSite} {
		records := crawlreplay.NewSynth(name, 1).Rotating(crawlreplay.Traffic{From: span.From, To: span.To,
			PerMinute: 30, L2: crawlreplay.SynthKey(1), L1: crawlreplay.SynthKey(2), Label: crawlreplay.LabelAttack, Episode: "e1"}, 1)
		site := crawlreplay.Site{Records: records, Coverage: []crawlreplay.Span{span}}
		if err := r.addSite(name, site, episodeOrigins(records)); err != nil {
			t.Fatal(err)
		}
	}
	// Each site's exact replay raises L1, L2 and site findings; all are
	// lost by the sketch because its hashes cannot meet the distinct floor.
	if r.Sketch.LostFindings != 6 || r.Sketch.ExtraDecisions != 0 {
		t.Fatalf("aggregate accuracy %+v, want six lost findings and no extra decisions", r.Sketch)
	}
}

func TestCalibrateAggregatesExtraSketchDecisions(t *testing.T) {
	p := crawlreplay.Params{W: 5, R: 3, F: 1, K: 1, D: 4, C: 80,
		Baseline: crawlreplay.BaselineParams{Alpha: 0.5, MinObs: 1, FloorPerMin: 1}}
	span := crawlreplay.Span{From: 120, To: 156}
	syn := crawlreplay.NewSynth(attackSite, 1)
	records := syn.Pool(crawlreplay.Traffic{From: span.From, To: span.From + 29,
		PerMinute: 10, Label: crawlreplay.LabelHealthy}, 2)
	burst := syn.Rotating(crawlreplay.Traffic{From: span.From + 30, To: span.From + 30,
		PerMinute: 200, Label: crawlreplay.LabelAttack, Episode: "e1"}, 1)
	hashes := map[string]uint64{}
	for _, rec := range records {
		if hashes[rec.Binding] == 0 {
			hashes[rec.Binding] = uint64(len(hashes) + 1)
		}
	}
	records = append(records, burst...)
	later := syn.Rotating(crawlreplay.Traffic{From: span.To, To: span.To,
		PerMinute: 60, Label: crawlreplay.LabelAttack, Episode: "e2"}, 1)
	for _, rec := range later {
		hashes[rec.Binding] = uint64(len(hashes) + 1)
	}
	records = append(records, later...)
	// The burst collides to zero, so only the exact baseline freezes.
	// Quiet minutes then lower the sketch baseline below the exact one;
	// the final traffic crosses only the sketch's learned threshold.
	sk := &crawlreplay.SketchParams{M: 512, H: 512, Hash: func(b string) uint64 { return hashes[b] }}
	r := newRunResult(gridRun{Params: p, Sketch: sk})
	if err := r.addSite(attackSite, crawlreplay.Site{Records: records, Coverage: []crawlreplay.Span{span}}, episodeOrigins(records)); err != nil {
		t.Fatal(err)
	}
	if r.Sketch.ExtraDecisions != 1 || r.Sketch.LostFindings != 1 {
		t.Fatalf("aggregate accuracy %+v, want one extra decision and one lost finding", r.Sketch)
	}
}
