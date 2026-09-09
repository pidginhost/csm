package selftest

import (
	"errors"
	"testing"
)

func TestScanErrorsFailEverySampleKind(t *testing.T) {
	for _, engine := range []Engine{Realtime, Yara} {
		results := Run(engine, func([]byte, string) ([]string, error) {
			return nil, errors.New("engine failed")
		})
		for _, result := range results {
			if result.Error != "engine failed" || result.Pass || result.Detected {
				t.Errorf("%s: result = %+v, want scan failure", engine, result)
			}
		}
		want := Summary{Errors: len(Samples())}
		if summary := Summarize(results); summary != want || !summary.Failed() {
			t.Fatalf("%s: summary = %+v, want %+v and failure", engine, summary, want)
		}
	}
}

func TestSummaryRejectsEmptyRun(t *testing.T) {
	if !Summarize(nil).Failed() {
		t.Fatal("an empty run reports success")
	}
}

func TestDecodeErrorsFailEverySampleKind(t *testing.T) {
	for _, sample := range []Sample{
		{Name: "detected", Malicious: true},
		{Name: "gap", Malicious: true, RealtimeGap: true, YaraGap: true},
		{Name: "benign"},
	} {
		for _, encoded := range []string{"invalid!", ""} {
			t.Run(sample.Name+"/"+encoded, func(t *testing.T) {
				sample.Encoded = encoded
				withSamples(t, []Sample{sample})
				for _, engine := range []Engine{Realtime, Yara} {
					results := Run(engine, func([]byte, string) ([]string, error) {
						t.Fatal("invalid sample reached scanner")
						return nil, nil
					})
					if len(results) != 1 || results[0].Error == "" || results[0].Pass {
						t.Fatalf("%s results = %+v, want one failed decode", engine, results)
					}
					if summary := Summarize(results); !summary.Failed() || summary.Clean != 0 || summary.KnownGaps != 0 {
						t.Fatalf("%s summary = %+v, decode errors must fail, not count as clean or known gaps", engine, summary)
					}
				}
			})
		}
	}
}

func TestRunRejectsEmptyBundle(t *testing.T) {
	withSamples(t, nil)
	for _, engine := range []Engine{Realtime, Yara} {
		results := Run(engine, func([]byte, string) ([]string, error) {
			t.Fatal("empty bundle reached scanner")
			return nil, nil
		})
		if !Summarize(results).Failed() {
			t.Fatalf("%s: empty bundle reports success", engine)
		}
	}
}

func TestRunRequiresWorkingDetection(t *testing.T) {
	for _, engine := range []Engine{Realtime, Yara} {
		results := Run(engine, func([]byte, string) ([]string, error) { return nil, nil })
		if summary := Summarize(results); !summary.Failed() || summary.Missed == 0 {
			t.Fatalf("%s: a scanner returning nothing passed: %+v", engine, summary)
		}
	}
}

func TestRunGatesBothDirectionsAndFalsePositives(t *testing.T) {
	for _, engine := range []Engine{Realtime, Yara} {
		for _, tc := range []struct {
			name     string
			sample   Sample
			detected bool
			want     Summary
		}{
			{"lost detection", Sample{Malicious: true}, false, Summary{Missed: 1}},
			{"closed gap", Sample{Malicious: true, RealtimeGap: true, YaraGap: true}, true, Summary{ClosedGaps: 1}},
			{"false positive", Sample{}, true, Summary{FalsePositives: 1}},
		} {
			t.Run(string(engine)+"/"+tc.name, func(t *testing.T) {
				tc.sample.Encoded = "c2FtcGxl"
				withSamples(t, []Sample{tc.sample})
				results := Run(engine, func([]byte, string) ([]string, error) {
					if tc.detected {
						return []string{"matched"}, nil
					}
					return nil, nil
				})
				if len(results) != 1 || results[0].Pass {
					t.Fatalf("results = %+v, want one failed verdict", results)
				}
				if summary := Summarize(results); summary != tc.want || !summary.Failed() {
					t.Fatalf("summary = %+v, want failure %+v", summary, tc.want)
				}
			})
		}
	}
}

func withSamples(t *testing.T, bundle []Sample) {
	t.Helper()
	original := samples
	samples = bundle
	t.Cleanup(func() { samples = original })
}
