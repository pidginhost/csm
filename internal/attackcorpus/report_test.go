package attackcorpus

import (
	"encoding/base64"
	"encoding/json"
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

func TestWriteReportHasNoContent(t *testing.T) {
	const sampleMarker = "planted-content-marker-7f3a"
	const textMarker = "finding-text-marker-91c2"
	encoded := base64.StdEncoding.EncodeToString([]byte(sampleMarker + "\n"))

	sampleDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sampleDir, "m.b64"), []byte(encoded), 0o600); err != nil {
		t.Fatal(err)
	}
	s := judgeControl()
	s.Dir = sampleDir
	s.Files = []File{{Path: fileA, B64: "m.b64"}}
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
		Findings:    []Observed{{Check: "named_check", Severity: alert.High, Text: textMarker + " " + planted[fileA] + "\n" + sampleMarker}},
		Remediation: map[string]Remediation{fileA: Untouched},
	}
	r := Judge(s, Realtime, o)
	wantFailures(t, r, "false positive: named_check names "+fileA)

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

	var report struct {
		Path    Path
		Results []Result
		Summary map[Category]Counts
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}
	r.Findings[0].Text = ""
	if report.Path != Realtime || len(report.Results) != 1 || !reflect.DeepEqual(report.Results[0], r) {
		t.Errorf("report = %+v\nwant path realtime and result %+v", report, r)
	}
	if want := (Counts{Samples: 1, FalsePositives: 1}); report.Summary[Webshell] != want || len(report.Summary) != 1 {
		t.Errorf("summary = %+v, want webshell %+v", report.Summary, want)
	}
}
