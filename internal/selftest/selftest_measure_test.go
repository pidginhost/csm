package selftest

import (
	"testing"

	"github.com/pidginhost/csm/internal/signatures"
)

// This is the bundle's own gate over the real-time YAML rules. It fails when a
// verdict changes in either direction: a sample that stops being detected is a
// regression, and a recorded gap that starts firing is an improvement the
// bundle has to be told about, so no gap can quietly become permanent.
func TestRealtimeRulesMatchTheBundle(t *testing.T) {
	scanner := signatures.NewScanner("../../configs")
	if err := scanner.LoadError(); err != nil {
		t.Fatalf("loading shipped rules: %v", err)
	}
	if scanner.RuleCount() == 0 {
		t.Fatal("no rules loaded from configs/; the gate would pass vacuously")
	}

	results := Run(Realtime, func(content []byte, ext string) []string {
		var names []string
		for _, m := range scanner.ScanContent(content, ext) {
			names = append(names, m.RuleName)
		}
		return names
	})
	assertBundle(t, Realtime, results)
}

func assertBundle(t *testing.T, engine Engine, results []Result) {
	t.Helper()
	if len(results) != len(Samples()) {
		t.Fatalf("results = %d, want one per sample (%d)", len(results), len(Samples()))
	}
	for _, r := range results {
		switch {
		case r.Error != "":
			t.Errorf("%s: %s", r.Name, r.Error)
		case r.KnownGap && r.Detected:
			t.Errorf("%s: the %s rules now detect this; clear the recorded gap in the bundle", r.Name, engine)
		case r.Malicious && !r.KnownGap && !r.Detected:
			t.Errorf("%s: the %s rules no longer detect this sample (%s)", r.Name, engine, r.Description)
		case !r.Malicious && r.Detected:
			t.Errorf("%s: the %s rules fire on a benign control (%s): %v", r.Name, engine, r.Description, r.Rules)
		}
	}
}

// Benign controls are the half that decides whether a rule set is usable, so
// the bundle must never lose them.
func TestBundleHasBenignControls(t *testing.T) {
	var malicious, benign int
	for _, s := range Samples() {
		if s.Malicious {
			malicious++
			continue
		}
		benign++
	}
	if malicious == 0 || benign == 0 {
		t.Fatalf("bundle has %d adversarial and %d benign samples; both halves are required to judge a rule set", malicious, benign)
	}
}

// A benign sample cannot carry a gap: a gap records that malware was missed,
// and marking a control would turn a false positive into an expectation.
func TestBenignSamplesCarryNoGaps(t *testing.T) {
	for _, s := range Samples() {
		if !s.Malicious && (s.RealtimeGap || s.YaraGap) {
			t.Errorf("%s is a benign control but records a detection gap", s.Name)
		}
	}
}

func TestSummarizeSeparatesTheFailureKinds(t *testing.T) {
	got := Summarize([]Result{
		{Malicious: true, Detected: true},
		{Malicious: true, KnownGap: true},
		{Malicious: true, KnownGap: true, Detected: true},
		{Malicious: true},
		{Detected: true},
		{},
	})
	want := Summary{Detected: 1, KnownGaps: 1, ClosedGaps: 1, Missed: 1, FalsePositives: 1, Clean: 1}
	if got != want {
		t.Fatalf("summary = %+v, want %+v", got, want)
	}
	if !got.Failed() {
		t.Error("a run with a miss and a false positive reports success")
	}
	if (Summary{Detected: 2, KnownGaps: 1, Clean: 3}).Failed() {
		t.Error("a clean run with recorded gaps reports failure")
	}
}
