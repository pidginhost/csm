package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/selftest"
	"github.com/pidginhost/csm/internal/yara"
)

// The verdict word is what an operator reads, so each outcome has to be
// distinguishable at a glance: a miss and a recorded gap are not the same
// thing, and neither is a false positive.
func TestSelfTestVerdictNamesEachOutcome(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result selftest.Result
		want   string
	}{
		{"detected", selftest.Result{Malicious: true, Detected: true}, "detected"},
		{"missed", selftest.Result{Malicious: true}, "MISSED"},
		{"known gap", selftest.Result{Malicious: true, KnownGap: true}, "known gap"},
		{"gap closed", selftest.Result{Malicious: true, KnownGap: true, Detected: true}, "GAP CLOSED"},
		{"false positive", selftest.Result{Detected: true}, "FALSE POSITIVE"},
		{"clean", selftest.Result{}, "clean"},
		{"error", selftest.Result{Error: "bad base64"}, "ERROR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := selfTestVerdict(tc.result); got != tc.want {
				t.Fatalf("verdict = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWriteSelfTestReportsEverySampleAndTheCounts(t *testing.T) {
	runs := []engineRun{{
		Engine:    selftest.Realtime,
		RuleCount: 186,
		Summary:   selftest.Summary{Detected: 1, KnownGaps: 1, Clean: 1},
		Results: []selftest.Result{
			{Name: "webshell_request_eval", Malicious: true, Detected: true, Rules: []string{"webshell_generic"}, Description: "a shell"},
			{Name: "obfuscated_chr_builder", Malicious: true, KnownGap: true, Description: "chr-built code"},
			{Name: "benign_wordpress_plugin", Description: "a plugin"},
		},
	}}

	var buf bytes.Buffer
	if err := writeSelfTest(&buf, "/opt/csm/rules", runs, false); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"webshell_request_eval", "obfuscated_chr_builder", "benign_wordpress_plugin",
		"webshell_generic", "186", "/opt/csm/rules",
		"1 detected, 1 clean, 1 known gap(s), 0 missed, 0 false positive(s)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
}

func TestWriteSelfTestJSONCarriesEveryEngine(t *testing.T) {
	runs := []engineRun{
		{Engine: selftest.Realtime, RuleCount: 186},
		{Engine: selftest.Yara, RuleCount: 162},
	}
	var buf bytes.Buffer
	if err := writeSelfTest(&buf, "/opt/csm/rules", runs, true); err != nil {
		t.Fatalf("write: %v", err)
	}
	var payload struct {
		RulesDir string `json:"rules_dir"`
		Engines  []struct {
			Engine    string `json:"engine"`
			RuleCount int    `json:"rule_count"`
		} `json:"engines"`
	}
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if payload.RulesDir != "/opt/csm/rules" || len(payload.Engines) != 2 {
		t.Fatalf("payload = %+v, want both engines and the rules directory", payload)
	}
	if payload.Engines[0].Engine != "realtime" || payload.Engines[1].Engine != "yara" {
		t.Fatalf("engines = %+v, want realtime then yara", payload.Engines)
	}
}

// A build without YARA-X must not report every YARA sample as missed: that
// reads as a detection failure when the engine is simply absent.
func TestSelfTestRunsReportYaraAvailability(t *testing.T) {
	runs, err := selfTestRuns("../../configs")
	if err != nil {
		t.Fatalf("runs: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("got %d engines, want both measured or explicitly skipped", len(runs))
	}
	if runs[0].Engine != selftest.Realtime {
		t.Fatalf("first engine = %q, want realtime", runs[0].Engine)
	}
	if runs[1].Engine != selftest.Yara || (runs[1].Skipped == "") != yara.Available() {
		t.Fatalf("YARA availability = %v, run = %+v", yara.Available(), runs[1])
	}
	for _, run := range runs {
		if run.Skipped == "" && run.Summary.Failed() {
			t.Errorf("%s: shipped rules disagree with the bundle: %+v", run.Engine, run.Summary)
		}
		if run.Skipped != "" {
			if run.RuleCount != 0 || len(run.Results) != 0 {
				t.Fatalf("skipped engine claims measurements: %+v", run)
			}
			for _, asJSON := range []bool{false, true} {
				var buf bytes.Buffer
				if err := writeSelfTest(&buf, "../../configs", runs, asJSON); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(buf.String(), run.Skipped) {
					t.Fatalf("JSON=%v: absent engine is not explained: %s", asJSON, buf.String())
				}
			}
		}
	}
}

func TestSelfTestRunsRejectPartialRealtimeLoad(t *testing.T) {
	dir := selfTestRulesDir(t)
	if err := os.WriteFile(filepath.Join(dir, "broken.yml"), []byte("rules: ["), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := selfTestRuns(dir); err == nil {
		t.Fatal("partially loaded realtime rules report success")
	}
}

func TestSelfTestRunsRejectEmptyRealtimeRules(t *testing.T) {
	if _, err := selfTestRuns(t.TempDir()); err == nil {
		t.Fatal("zero realtime rules report success")
	}
}

func TestWriteSelfTestIncludesErrorsAndClosedGaps(t *testing.T) {
	runs := []engineRun{{
		Engine:  selftest.Realtime,
		Summary: selftest.Summary{ClosedGaps: 1},
		Results: []selftest.Result{{Name: "broken", Error: "sample could not be decoded"}},
	}}
	var buf bytes.Buffer
	if err := writeSelfTest(&buf, "/rules", runs, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"sample could not be decoded", "1 closed gap(s)"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("output omits %q: %s", want, buf.String())
		}
	}
}

func selfTestRulesDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	data, err := os.ReadFile("../../configs/malware.yml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "malware.yml"), data, 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}
