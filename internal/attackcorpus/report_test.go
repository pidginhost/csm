package attackcorpus

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestSummarizeCounts(t *testing.T) {
	ws, dr := string(Webshell), string(Dropper)
	results := []Result{
		{Category: ws, Kind: "malicious", Pass: true},
		{Category: ws, Kind: "malicious", Pass: true, Gap: gapText},
		{Category: ws, Kind: "malicious", Gap: gapText, Failures: []string{"gap closed: a", "gap closed: b"}},
		{Category: ws, Kind: "malicious", Failures: []string{"missed: a", "missed: b", "severity: c", "remediation: d"}},
		{Category: ws, Kind: "control", Failures: []string{"false positive: a", "false positive: b"}},
		{Category: ws, Kind: "control", Pass: true},
		{Category: dr, Kind: "malicious", Failures: []string{"severity: a"}},
		{Category: dr, Kind: "malicious", Failures: []string{"remediation: a"}},
		{Category: dr, Kind: "malicious", Failures: []string{"error: a"}},
		{Category: dr, Kind: "control", Failures: []string{"remediation: a"}},
	}
	want := map[Category]Counts{
		Webshell: {Samples: 6, Detected: 1, Gaps: 1, Missed: 1, FalsePositives: 1, ClosedGaps: 1, RemediationMismatches: 1},
		Dropper:  {Samples: 4, Missed: 1, RemediationMismatches: 2, Errors: 1},
	}
	if got := Summarize(results); !reflect.DeepEqual(got, want) {
		t.Errorf("Summarize = %+v\nwant %+v", got, want)
	}
}

func TestReportDoesNotQuoteDriverErrors(t *testing.T) {
	const marker = "sample-content-from-parser-error"
	o := realtimeOK()
	o.Err = errors.New("parser rejected " + marker)
	r := Judge(judgeSample(), Realtime, o)
	if r.Pass || len(r.Failures) != 1 || !strings.HasPrefix(r.Failures[0], "error:") {
		t.Fatal("a driver error must produce an error verdict")
	}
	if strings.Contains(strings.Join(r.Failures, "\n"), marker) {
		t.Error("the verdict exposes driver error text")
	}
	dir := t.TempDir()
	if err := WriteReport(dir, Realtime, []Result{r}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "realtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), marker) {
		t.Error("the report exposes driver error text")
	}
}

func TestReportRejectsEmptyResults(t *testing.T) {
	dir := t.TempDir()
	if err := WriteReport(dir, Realtime, nil); err == nil {
		t.Fatal("an empty run produced a success report")
	}
	if _, err := os.Stat(filepath.Join(dir, "realtime.json")); !os.IsNotExist(err) {
		t.Fatal("an empty run wrote a report")
	}
}

func TestWriteReportHasNoContent(t *testing.T) {
	const sampleMarker = "planted-content-marker-7f3a"
	const textMarker = "finding-text-marker-91c2"
	encoded := base64.StdEncoding.EncodeToString([]byte(sampleMarker + "\n"))

	s := loaded(t, controlWith(File{Path: fileA, B64: "m.b64"}), map[string]string{"m.b64": encoded})
	root := t.TempDir()
	planted, err := s.Plant(root, filepath.Join(root, "cron"), "acct")
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- the file was planted under t.TempDir() just above.
	content, err := os.ReadFile(planted[fileA])
	if err != nil || string(content) != sampleMarker+"\n" {
		t.Fatalf("planted content = %q, %v", content, err)
	}

	// The finding's text names the planted file, so Judge reads it and fails
	// the control; neither the text nor the content may reach the report.
	o := Outcome{
		Findings: []Observed{
			{Check: "named_check", Severity: alert.High, Text: textMarker + " " + planted[fileA] + "\n" + sampleMarker},
			{Check: "host_check", Severity: alert.Warning, Text: "unrelated"},
			{Check: "other_check", Severity: alert.Critical, Text: "unrelated"},
		},
		Remediation: map[string]Remediation{fileA: Untouched},
	}
	r := Judge(s, Realtime, o)
	wantFailures(t, r, "error: unattributed finding host_check on control",
		"false positive: named_check names "+fileA,
		"error: unattributed finding other_check on control")

	dir := filepath.Join(t.TempDir(), "reports")
	if err = WriteReport(dir, Realtime, []Result{r}); err != nil {
		t.Fatalf("WriteReport: %v", err)
	}
	// #nosec G304 -- the report was written under t.TempDir() just above.
	data, err := os.ReadFile(filepath.Join(dir, "realtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{sampleMarker, textMarker, encoded} {
		if strings.Contains(string(data), leak) {
			t.Errorf("report contains %q:\n%s", leak, data)
		}
	}

	type finding struct{ Check, Severity, File string }
	var report struct {
		Path    Path
		Results []struct {
			Result
			// Severities are written by name, so they decode as strings.
			Findings []finding `json:"findings"`
		}
		Summary map[Category]Counts
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("report is not JSON with named severities: %v", err)
	}
	if report.Path != Realtime || len(report.Results) != 1 {
		t.Fatalf("report = %+v, want path realtime and one result", report)
	}
	got := report.Results[0]
	if want := []finding{{"host_check", "WARNING", ""}, {"named_check", "HIGH", ""}, {"other_check", "CRITICAL", ""}}; !reflect.DeepEqual(got.Findings, want) {
		t.Errorf("report findings = %+v, want %+v", got.Findings, want)
	}
	r.Findings = nil
	if !reflect.DeepEqual(got.Result, r) {
		t.Errorf("report result = %+v\nwant %+v", got.Result, r)
	}
	if want := (Counts{Samples: 1, FalsePositives: 1, Errors: 1}); report.Summary[Webshell] != want || len(report.Summary) != 1 {
		t.Errorf("summary = %+v, want webshell %+v", report.Summary, want)
	}
}
