package main

import (
	"testing"

	"github.com/pidginhost/csm/internal/crawlreplay"
)

// replayScored feeds sites through one scoring bundle of a calibration,
// as run does once a bundle has validated, and returns the report.
func replayScored(t *testing.T, g gridRun, truth []crawlreplay.EpisodeTruth, span crawlreplay.Span,
	sites []string, records map[string][]crawlreplay.Record, coverage map[string][]crawlreplay.Span) report {
	t.Helper()
	c, err := newCalibration(experiment{Window: 1, Runs: []gridRun{g}, Truth: truth})
	if err != nil {
		t.Fatal(err)
	}
	c.begin(experimentBundle{Coverage: "proof", Role: roleScoring, Score: []crawlreplay.Span{span},
		States: []experimentState{{From: span.From, To: span.To, State: crawlreplay.StateNormal}}})
	var bs []crawlreplay.BundleSite
	for _, name := range sites {
		bs = append(bs, crawlreplay.BundleSite{Site: name, Certified: []crawlreplay.Span{span}, Coverage: coverage[name]})
	}
	if err = c.bundleSites(bs); err != nil {
		t.Fatal(err)
	}
	for _, name := range sites {
		if err = c.replaySite(name, records[name]); err != nil {
			t.Fatal(err)
		}
	}
	return c.report(calibratorTool())
}

func siteTruth(episode string, sites ...string) []crawlreplay.EpisodeTruth {
	var out []crawlreplay.EpisodeTruth
	for _, site := range sites {
		out = append(out, crawlreplay.EpisodeTruth{Episode: episode, Label: crawlreplay.LabelAttack, Site: site,
			Keys: []crawlreplay.KeyID{{Level: 3}}})
	}
	return out
}

func TestCalibrateKeepsMissAfterExcludedOnset(t *testing.T) {
	p := crawlreplay.Params{W: 5, R: 3, F: 1, K: 1, D: 4, C: 80,
		Baseline: crawlreplay.BaselineParams{Alpha: 0.5, MinObs: 1, FloorPerMin: 1}}
	span := crawlreplay.Span{From: 100, To: 109}
	records := crawlreplay.NewSynth(attackSite, 1).Pool(crawlreplay.Traffic{From: 100, To: 109,
		PerMinute: 1, Label: crawlreplay.LabelAttack, Episode: "e1"}, 1)
	rep := replayScored(t, gridRun{Params: p}, siteTruth("e1", attackSite), span, []string{attackSite},
		map[string][]crawlreplay.Record{attackSite: records}, map[string][]crawlreplay.Span{attackSite: {{From: 101, To: 109}}})
	eps := rep.Runs[0].Scoring.Episodes
	if len(eps) != 1 {
		t.Fatalf("episodes = %+v, want one missed episode", eps)
	}
	ep := eps[0]
	if ep.Status != crawlreplay.OutcomeMissed || ep.Detected || ep.Onset != records[0].T {
		t.Fatalf("episode = %+v, want miss with the original onset", ep)
	}
}

func TestCalibrateAggregatesSketchFindings(t *testing.T) {
	p := crawlreplay.Params{W: 5, R: 3, F: 1, K: 1, D: 4, C: 80,
		Baseline: crawlreplay.BaselineParams{Alpha: 0.5, MinObs: 1, MinAge: 0, FloorPerMin: 1}}
	sk := &crawlreplay.SketchParams{M: 4, H: 8, Hash: func(b string) uint64 { return uint64(b[len(b)-1] % 4) }}
	span := crawlreplay.Span{From: 100, To: 119}
	records := map[string][]crawlreplay.Record{}
	coverage := map[string][]crawlreplay.Span{}
	for _, name := range []string{attackSite, quietSite} {
		records[name] = crawlreplay.NewSynth(name, 1).Rotating(crawlreplay.Traffic{From: span.From, To: span.To,
			PerMinute: 30, L2: crawlreplay.SynthKey(1), L1: crawlreplay.SynthKey(2), Label: crawlreplay.LabelAttack, Episode: "e1"}, 1)
		coverage[name] = []crawlreplay.Span{span}
	}
	rep := replayScored(t, gridRun{Params: p, Sketch: sk}, siteTruth("e1", attackSite, quietSite), span,
		[]string{attackSite, quietSite}, records, coverage)
	r := rep.Runs[0]
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
	truth := append(siteTruth("e1", attackSite), siteTruth("e2", attackSite)...)
	rep := replayScored(t, gridRun{Params: p, Sketch: sk}, truth, span, []string{attackSite},
		map[string][]crawlreplay.Record{attackSite: records}, map[string][]crawlreplay.Span{attackSite: {span}})
	r := rep.Runs[0]
	if r.Sketch.ExtraDecisions != 1 || r.Sketch.LostFindings != 1 {
		t.Fatalf("aggregate accuracy %+v, want one extra decision and one lost finding", r.Sketch)
	}
}
