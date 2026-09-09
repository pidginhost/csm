package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/selftest"
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
func TestSelfTestRunsSkipYaraWhenItIsNotCompiledIn(t *testing.T) {
	runs, err := selfTestRuns("../../configs")
	if err != nil {
		t.Fatalf("runs: %v", err)
	}
	if len(runs) == 0 {
		t.Fatal("no engines measured")
	}
	if runs[0].Engine != selftest.Realtime {
		t.Fatalf("first engine = %q, want realtime", runs[0].Engine)
	}
	for _, run := range runs {
		if run.Summary.Failed() {
			t.Errorf("%s: shipped rules disagree with the bundle: %+v", run.Engine, run.Summary)
		}
	}
}
