package main

import (
	"reflect"
	"testing"

	"github.com/pidginhost/csm/internal/crawlreplay"
)

func TestCalibrateShapeSurvivesBundleBoundaries(t *testing.T) {
	const start = int64(29_900_040)
	for name, spans := range map[string][]crawlreplay.Span{
		"adjacent":      {{From: start, To: start + 2}, {From: start + 3, To: start + 7}},
		"silent bundle": {{From: start, To: start + 2}, {From: start + 3, To: start + 4}, {From: start + 5, To: start + 7}},
		"gap":           {{From: start, To: start + 2}, {From: start + 5, To: start + 7}},
	} {
		t.Run(name, func(t *testing.T) {
			x := experiment{FormatVersion: experimentVersion, IdentityVersion: 1, Window: 3,
				Runs: []gridRun{}, Fixtures: []crawlreplay.Fixture{}, Truth: []crawlreplay.EpisodeTruth{}}
			syn := crawlreplay.NewSynth(attackSite, 1)
			records := syn.Pool(crawlreplay.Traffic{From: start, To: start, PerMinute: 2,
				L2: synthKey(1), L1: synthKey(2), Label: crawlreplay.LabelHealthy}, 2)
			records = append(records, syn.Pool(crawlreplay.Traffic{From: start + 2, To: start + 2, PerMinute: 2,
				L2: synthKey(1), L1: synthKey(2), Label: crawlreplay.LabelHealthy}, 2)...)
			records = append(records, syn.Pool(crawlreplay.Traffic{From: start + 5, To: start + 5, PerMinute: 2,
				L2: synthKey(1), L1: synthKey(3), Label: crawlreplay.LabelHealthy}, 2)...)
			var last bundle
			for _, span := range spans {
				last = encodeBundle(t, t.TempDir(), span, []siteRecords{{attackSite, attackAccount,
					crawlreplay.RestrictToCoverage(records, []crawlreplay.Span{span})}}, bundleOptions{})
				x.Bundles = append(x.Bundles, last.entry(roleTraining))
			}
			if err := run(last.with(t, x), testEnv()); err != nil {
				t.Fatal(err)
			}
			want := &shapeAccumulator{lateness: map[int64]int64{}, keys: map[uint8][]float64{}, newKeys: map[uint8][]float64{}}
			want.add(crawlreplay.ShapeSite(crawlreplay.Site{Records: records, Coverage: spans}, x.Window))
			if got := readReport(t, last.out).Shape; !reflect.DeepEqual(got, want.report()) {
				t.Fatalf("split shape = %+v, want %+v", got, want.report())
			}
		})
	}
}

func TestCalibrateVolumeExcludesBetweenBundleGaps(t *testing.T) {
	const start = int64(29_900_040)
	x := experiment{FormatVersion: experimentVersion, IdentityVersion: 1, Window: 3,
		Runs: []gridRun{}, Fixtures: []crawlreplay.Fixture{}, Truth: []crawlreplay.EpisodeTruth{}}
	var last bundle
	for _, from := range []int64{start, start + 60} {
		span := crawlreplay.Span{From: from, To: from + 4}
		syn := crawlreplay.NewSynth(attackSite, 1)
		records := syn.Pool(crawlreplay.Traffic{From: from, To: from, PerMinute: 4, Label: crawlreplay.LabelHealthy}, 2)
		records = append(records, syn.Pool(crawlreplay.Traffic{From: from + 4, To: from + 4,
			PerMinute: 4, Label: crawlreplay.LabelHealthy}, 2)...)
		last = encodeBundle(t, t.TempDir(), span, []siteRecords{{attackSite, attackAccount, records}}, bundleOptions{})
		x.Bundles = append(x.Bundles, last.entry(roleTraining))
	}
	if err := run(last.with(t, x), testEnv()); err != nil {
		t.Fatal(err)
	}
	want := crawlreplay.HostVolume{
		LinesPerMinute:     crawlreplay.Quantiles{N: 10, P50: 0, P99: 4, Max: 4},
		BytesPerMinute:     crawlreplay.Quantiles{N: 10, P50: 0, P99: 400, Max: 400},
		SiteLinesPerMinute: crawlreplay.Quantiles{N: 4, P50: 4, P99: 4, Max: 4},
	}
	if got := readReport(t, last.out).Volume; got != want {
		t.Fatalf("volume = %+v, want %+v", got, want)
	}
}

func TestCalibrateSketchAccuracyUsesOnlyScoredTicks(t *testing.T) {
	p := crawlreplay.Params{W: 5, R: 3, F: 1, K: 1, D: 4, C: 80,
		Baseline: crawlreplay.BaselineParams{Alpha: 0.5, MinObs: 1, FloorPerMin: 1}}
	sk := &crawlreplay.SketchParams{M: 4, H: 8, Hash: func(string) uint64 { return 0 }}
	c, err := newCalibration(experiment{Window: 1, Runs: []gridRun{{Params: p, Sketch: sk}}, Truth: siteTruth("e1", attackSite)})
	if err != nil {
		t.Fatal(err)
	}
	r := c.runs[0]
	for i, span := range []crawlreplay.Span{{From: 100, To: 109}, {From: 110, To: 119}} {
		records := crawlreplay.NewSynth(attackSite, 1).Rotating(crawlreplay.Traffic{From: span.From, To: span.To,
			PerMinute: 30, L2: synthKey(1), L1: synthKey(2), Label: crawlreplay.LabelAttack, Episode: "e1"}, 1)
		seg := crawlreplay.ReplaySegment{Site: attackSite, Records: records, Coverage: []crawlreplay.Span{span}}
		if i == 1 {
			seg.Score = []crawlreplay.Span{{From: 117, To: 119}}
		}
		if err := r.feed(seg, records); err != nil {
			t.Fatal(err)
		}
		acc := r.pairing.Accuracy()
		if i == 0 && acc != (crawlreplay.SketchAccuracy{}) {
			t.Errorf("training contributed sketch accuracy: %+v", acc)
		}
		if i == 1 && (acc.LostFindings != 0 || acc.LostDecisions != 9 || acc.ExtraDecisions != 0 || acc.Exceeded != 0) {
			t.Errorf("scored accuracy = %+v, want nine lost decisions and no new lost findings", acc)
		}
	}
}
