package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/selftest"
)

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
