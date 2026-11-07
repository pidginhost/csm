package attackcorpus

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

const (
	fileA   = "public_html/a.php"
	fileB   = "public_html/b.php"
	gapText = "tier does not read this shape"
)

var (
	sumX = strings.Repeat("a", 64)
	sumY = strings.Repeat("b", 64)
)

// judgeSample is malicious: realtime expects a finding and a quarantine,
// tier records a gap, fullscan expects a finding and a cleaning.
func judgeSample() Sample {
	return Sample{
		Name: "judge_case", Category: string(Webshell), Kind: "malicious", Half: "public",
		Files: []File{{Path: fileA}, {Path: fileB}},
		Expect: map[Path]PathExpect{
			Realtime: {
				Findings:    []ExpectedFinding{{Check: "test_check", File: fileA, MinSeverity: "High"}},
				Remediation: map[string]Remediation{fileA: Quarantined},
			},
			Tier: {Gap: gapText},
			FullScan: {
				Findings:      []ExpectedFinding{{Check: "test_check", File: fileA, MinSeverity: "critical"}},
				Remediation:   map[string]Remediation{fileA: Cleaned},
				CleanedSHA256: map[string]string{fileA: sumX},
			},
		},
	}
}

func judgeControl() Sample {
	s := judgeSample()
	s.Name, s.Kind = "judge_control", "control"
	s.Expect = map[Path]PathExpect{Realtime: {}, Tier: {}, FullScan: {}}
	return s
}

func untouched() map[string]Remediation {
	return map[string]Remediation{fileA: Untouched, fileB: Untouched}
}

func realtimeOK() Outcome {
	return Outcome{
		Findings:    []Observed{{Check: "test_check", Severity: alert.High, File: fileA}},
		Remediation: map[string]Remediation{fileA: Quarantined, fileB: Untouched},
	}
}

func wantFailures(t *testing.T, r Result, want ...string) {
	t.Helper()
	if !reflect.DeepEqual(r.Failures, want) {
		t.Fatalf("failures = %q\nwant %q", r.Failures, want)
	}
	if r.Pass != (len(want) == 0) {
		t.Errorf("Pass = %v with failures %q", r.Pass, r.Failures)
	}
}

func TestJudgeMissed(t *testing.T) {
	o := realtimeOK()
	// Same check on another file and another check on the expected file:
	// neither is the expected finding.
	o.Findings = []Observed{
		{Check: "test_check", Severity: alert.Critical, File: fileB},
		{Check: "other_check", Severity: alert.Critical, File: fileA},
	}
	r := Judge(judgeSample(), Realtime, o)
	wantFailures(t, r, "missed: test_check on "+fileA)

	want := Result{
		Sample: "judge_case", Category: string(Webshell), Kind: "malicious", Half: "public", Path: Realtime,
		Failures: r.Failures, Findings: []Observed{o.Findings[1], o.Findings[0]}, Remediation: o.Remediation,
	}
	if !reflect.DeepEqual(r, want) {
		t.Errorf("result = %+v\nwant %+v", r, want)
	}
}

func TestJudgeSeverityBelowMinimum(t *testing.T) {
	o := realtimeOK()
	o.Findings[0].Severity = alert.Warning
	wantFailures(t, Judge(judgeSample(), Realtime, o), "severity: test_check on "+fileA+" is WARNING, want HIGH or above")

	// The strongest matching finding counts, and the manifest case does not.
	o.Findings = []Observed{
		{Check: "test_check", Severity: alert.Warning, File: fileA},
		{Check: "test_check", Severity: alert.Critical, File: fileA},
	}
	wantFailures(t, Judge(judgeSample(), Realtime, o))
}

func TestJudgeControlFinding(t *testing.T) {
	o := Outcome{
		Findings: []Observed{
			{Check: "test_check", Severity: alert.Warning, File: fileB},
			{Check: "dir_check", Severity: alert.Warning, File: "public_html"},
		},
		Remediation: untouched(),
	}
	wantFailures(t, Judge(judgeControl(), FullScan, o),
		"false positive: dir_check on public_html",
		"false positive: test_check on "+fileB)

	wantFailures(t, Judge(judgeControl(), FullScan, Outcome{Remediation: untouched()}))
}

func TestJudgeUnattributedFindingOnControlIsReported(t *testing.T) {
	o := Outcome{
		Findings: []Observed{
			{Check: "named_check", Severity: alert.High, Text: "Suspicious file: /tmp/x/acct/" + fileA + "\nmore"},
			{Check: "host_check", Severity: alert.High, Text: "nothing about the planted files"},
		},
		Remediation: untouched(),
	}
	wantFailures(t, Judge(judgeControl(), Realtime, o),
		"error: unattributed finding host_check on control",
		"false positive: named_check names "+fileA)

	// The same unattributed finding on a malicious sample is an extra finding.
	o.Remediation = realtimeOK().Remediation
	o.Findings = append(o.Findings, realtimeOK().Findings...)
	wantFailures(t, Judge(judgeSample(), Realtime, o))
}

func TestJudgeRemediationMismatch(t *testing.T) {
	o := realtimeOK()
	o.Remediation = map[string]Remediation{fileA: Untouched, fileB: Removed}
	wantFailures(t, Judge(judgeSample(), Realtime, o),
		"remediation: "+fileA+" is untouched, want quarantined",
		"remediation: "+fileB+" is removed, want untouched")

	wantFailures(t, Judge(judgeControl(), Realtime, Outcome{Remediation: map[string]Remediation{fileA: Untouched, fileB: Cleaned}}),
		"remediation: "+fileB+" is cleaned, want untouched")
}

func TestJudgeCleanedHashMismatch(t *testing.T) {
	o := Outcome{
		Findings:      []Observed{{Check: "test_check", Severity: alert.Critical, File: fileA}},
		Remediation:   map[string]Remediation{fileA: Cleaned, fileB: Untouched},
		CleanedSHA256: map[string]string{fileA: sumY},
	}
	wantFailures(t, Judge(judgeSample(), FullScan, o),
		"remediation: "+fileA+" cleaned to sha256 "+sumY+", want "+sumX)

	o.CleanedSHA256 = map[string]string{fileA: sumX}
	wantFailures(t, Judge(judgeSample(), FullScan, o))
}

func TestJudgeGapClosed(t *testing.T) {
	o := Outcome{
		Findings:    []Observed{{Check: "test_check", Severity: alert.Critical, File: fileA}},
		Remediation: untouched(),
	}
	r := Judge(judgeSample(), Tier, o)
	wantFailures(t, r, "gap closed: test_check on "+fileA)
	if r.Gap != gapText {
		t.Errorf("Gap = %q, want %q", r.Gap, gapText)
	}

	// An unattributed finding closes the gap when its text names a planted
	// file, as a detector that names the file only in its details would.
	o.Findings = []Observed{{Check: "host_check", Severity: alert.Critical, Text: "Suspicious file: /tmp/x/acct/" + fileA}}
	wantFailures(t, Judge(judgeSample(), Tier, o), "gap closed: host_check names "+fileA)

	// One that names no planted file does not.
	o.Findings = []Observed{{Check: "host_check", Severity: alert.Critical, Text: "nothing about the planted files"}}
	wantFailures(t, Judge(judgeSample(), Tier, o))
}

func TestJudgeError(t *testing.T) {
	o := realtimeOK()
	o.Err = errors.New("analyzer not loaded")
	wantFailures(t, Judge(judgeSample(), Realtime, o), "error: driver did not complete")

	// A failed run is not judged further: missing remediation is not reported.
	wantFailures(t, Judge(judgeSample(), Realtime, Outcome{Err: errors.New("decode")}), "error: driver did not complete")
}

func TestJudgeExtraFindingsPass(t *testing.T) {
	o := realtimeOK()
	o.Findings = append(o.Findings,
		Observed{Check: "other_check", Severity: alert.Warning, File: fileB},
		Observed{Check: "host_check", Severity: alert.Critical, Text: fileB})
	r := Judge(judgeSample(), Realtime, o)
	wantFailures(t, r)
	if want := []Observed{o.Findings[2], o.Findings[0], o.Findings[1]}; !reflect.DeepEqual(r.Findings, want) {
		t.Errorf("findings = %+v, want every observed finding kept", r.Findings)
	}
}

// Scanners report in no fixed order, so the report and the failures sort by
// file, check, severity and text.
func TestJudgeSortsFindings(t *testing.T) {
	sorted := []Observed{
		{Check: "host_check", Severity: alert.Warning, Text: fileB},
		{Check: "host_check", Severity: alert.Warning, Text: "unrelated"},
		{Check: "other_check", Severity: alert.Warning, File: fileA},
		{Check: "test_check", Severity: alert.Warning, File: fileA},
		{Check: "test_check", Severity: alert.High, File: fileA},
		{Check: "other_check", Severity: alert.Critical, File: fileB},
	}
	var controlFailures []string
	for i, order := range [][]int{{0, 1, 2, 3, 4, 5}, {5, 4, 3, 2, 1, 0}, {2, 5, 1, 4, 0, 3}} {
		o := Outcome{Remediation: realtimeOK().Remediation}
		for _, j := range order {
			o.Findings = append(o.Findings, sorted[j])
		}
		if r := Judge(judgeSample(), Realtime, o); !reflect.DeepEqual(r.Findings, sorted) {
			t.Errorf("order %v: findings = %+v\nwant %+v", order, r.Findings, sorted)
		}
		o.Remediation = untouched()
		r := Judge(judgeControl(), Realtime, o)
		if i == 0 {
			controlFailures = r.Failures
		} else if !reflect.DeepEqual(r.Failures, controlFailures) {
			t.Errorf("order %v: failures = %q\nwant %q", order, r.Failures, controlFailures)
		}
	}
	if len(controlFailures) != len(sorted) {
		t.Errorf("control failures = %q, want one per finding", controlFailures)
	}
}

func TestJudgeNotAdmittedIsNotDetected(t *testing.T) {
	extra := Observed{Check: "other_check", Severity: alert.Warning, File: fileB}
	o := Outcome{
		Findings:    []Observed{{Check: "test_check", Severity: alert.Critical, File: fileA}, extra},
		Remediation: untouched(),
		NotAdmitted: []string{fileA},
	}
	r := Judge(judgeSample(), Realtime, o)
	wantFailures(t, r,
		"missed: test_check on "+fileA,
		"remediation: "+fileA+" is untouched, want quarantined")
	if !reflect.DeepEqual(r.Findings, []Observed{extra}) || !reflect.DeepEqual(r.NotAdmitted, []string{fileA}) {
		t.Errorf("findings = %+v, not admitted = %v; want only the admitted file's finding", r.Findings, r.NotAdmitted)
	}

	// A not-admitted file's finding does not close a gap either.
	wantFailures(t, Judge(judgeSample(), Tier, Outcome{Findings: o.Findings[:1], Remediation: untouched(), NotAdmitted: []string{fileA}}))
}

func TestJudgeKeepsControlFindingsAfterAdmissionRejection(t *testing.T) {
	o := Outcome{
		Findings:    []Observed{{Check: "test_check", Severity: alert.High, File: fileA}},
		Remediation: untouched(),
		NotAdmitted: []string{fileA},
	}
	r := Judge(judgeControl(), Realtime, o)
	wantFailures(t, r, "false positive: test_check on "+fileA)
	if len(r.Findings) != 1 {
		t.Fatal("the control's observed finding was discarded")
	}
}

func TestJudgeRejectsUnattributedControlFindings(t *testing.T) {
	for _, text := range []string{"unattributed scan result", "suspicious crontab for acct"} {
		s := judgeControl()
		s.Files = []File{{Path: "@crontab"}}
		o := Outcome{
			Findings:    []Observed{{Check: "test_check", Severity: alert.High, Text: text}},
			Remediation: map[string]Remediation{"@crontab": Untouched},
		}
		wantFailures(t, Judge(s, Tier, o), "error: unattributed finding test_check on control")
	}
}
