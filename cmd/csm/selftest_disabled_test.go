package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/selftest"
	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/yara"
)

func TestSelfTestMeasuresFullyDisabledRuleset(t *testing.T) {
	disabled := signatures.NewScanner("../../configs").RuleNames()
	disabled = append(disabled, yaraRuleNamesIn("../../configs")...)
	runs, err := selfTestRuns("../../configs", disabled...)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 {
		t.Fatalf("got %d engines, want both measured or skipped", len(runs))
	}
	if runs[0].Engine != selftest.Realtime || runs[1].Engine != selftest.Yara {
		t.Fatal("expected realtime and YARA engines")
	}
	for _, run := range runs {
		if run.Engine == selftest.Yara && !yara.Available() {
			if run.Skipped == "" {
				t.Fatal("absent YARA engine must be reported as skipped")
			}
			continue
		}
		if run.Skipped != "" || len(run.Results) != len(selftest.Samples()) {
			t.Fatalf("%s did not measure every sample", run.Engine)
		}
		for _, result := range run.Results {
			if result.Detected || result.Error != "" || len(result.Rules) != 0 {
				t.Errorf("%s: expected a completed scan with no matches: %+v", run.Engine, result)
			}
		}
		if run.RuleCount != 0 || run.Summary.Detected != 0 || run.Summary.Missed == 0 || !run.Summary.Failed() {
			t.Errorf("%s did not measure disabled coverage: %+v", run.Engine, run)
		}
	}
}

func TestSelfTestRejectsUnreadableConfig(t *testing.T) {
	if path := os.Getenv("CSM_SELFTEST_CONFIG_PROBE"); path != "" {
		os.Args = []string{"csm", "selftest", "--config", path, "--config-dir", filepath.Join(filepath.Dir(path), "conf.d")}
		runSelfTest()
		return
	}
	for _, missing := range []bool{false, true} {
		dir := t.TempDir()
		path := filepath.Join(dir, "csm.yaml")
		if !missing {
			if err := os.WriteFile(path, []byte("signatures:\n  disabled_rules: ["), 0600); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestSelfTestRejectsUnreadableConfig$")
		cmd.Env = append(os.Environ(), "CSM_SELFTEST_CONFIG_PROBE="+path)
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "loading self-test config") {
			t.Fatalf("missing=%t: silently fell back from unreadable config: %v\n%s", missing, err, out)
		}
	}
}

func TestSelfTestMeasuresDisabledRuleCoverage(t *testing.T) {
	enabled, err := selfTestRuns("../../configs")
	if err != nil {
		t.Fatal(err)
	}
	// Disable every rule responsible for this one sample, across both engines.
	const sample = "webshell_request_eval"
	var disabled []string
	for _, run := range enabled {
		for _, result := range run.Results {
			if result.Name == sample {
				if !result.Detected || len(result.Rules) == 0 {
					t.Fatalf("%s did not detect the control sample", run.Engine)
				}
				disabled = append(disabled, result.Rules...)
			}
		}
	}
	if len(disabled) == 0 {
		t.Fatal("control sample missing")
	}
	runs, err := selfTestRuns("../../configs", disabled...)
	if err != nil {
		t.Fatal(err)
	}
	for i, run := range runs {
		if run.Skipped != "" {
			continue
		}
		if run.RuleCount >= enabled[i].RuleCount || !run.Summary.Failed() || run.Summary.Missed == 0 {
			t.Errorf("%s did not report reduced coverage: %+v", run.Engine, run.Summary)
		}
		var found bool
		for _, result := range run.Results {
			if result.Name == sample {
				found = true
				if result.Detected || len(result.Rules) != 0 || selfTestVerdict(result) != "MISSED" {
					t.Errorf("%s still claims coverage: %+v", run.Engine, result)
				}
			}
		}
		if !found || (run.Engine != selftest.Realtime && run.Engine != selftest.Yara) {
			t.Fatalf("missing sample or unexpected engine: %s", run.Engine)
		}
	}
}
