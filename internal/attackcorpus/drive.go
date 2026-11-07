package attackcorpus

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// Config is the config under test: the shipped template as a fresh install
// loads it, with auto-response and file quarantine on, observe mode off and
// state in stateDir. Nothing else differs from the template.
func Config(stateDir string) (*config.Config, error) {
	_, file, _, _ := runtime.Caller(0)
	// #nosec G304 -- the shipped template at a fixed path in this source tree.
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "configs", "csm.yaml"))
	if err != nil {
		return nil, err
	}
	cfg, err := config.LoadBytes(data)
	if err != nil {
		return nil, err
	}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	cfg.Mode = config.ModeEnforce
	cfg.StatePath = stateDir
	return cfg, nil
}

// gate decides whether the corpus runs. It runs only with a report dir, and a
// pipeline that requires it fails instead of skipping when the dir is unset.
func gate(getenv func(string) string) (reportDir, skipReason string, err error) {
	if dir := getenv("CSM_ATTACK_CORPUS_REPORT_DIR"); dir != "" {
		return dir, "", nil
	}
	if getenv("CSM_ATTACK_CORPUS_REQUIRED") == "1" {
		return "", "", errors.New("CSM_ATTACK_CORPUS_REQUIRED=1 but CSM_ATTACK_CORPUS_REPORT_DIR is not set")
	}
	return "", "CSM_ATTACK_CORPUS_REPORT_DIR is not set", nil
}

// prepare makes every check that must stop a run before its first sample and
// returns the report dir and samples, or a reason to skip. The private half is
// checked first, so its errors surface even when the public half is unusable.
func prepare(p Path, getenv func(string) string) (reportDir, skip string, samples []Sample, err error) {
	if !slices.Contains(Paths, p) {
		return "", "", nil, fmt.Errorf("unknown path %q", p)
	}
	if reportDir, skip, err = gate(getenv); err != nil || skip != "" {
		return "", skip, nil, err
	}
	if dir := getenv("CSM_ATTACK_CORPUS_PRIVATE"); dir != "" {
		if samples, err = Load(dir, "private"); err != nil {
			return "", "", nil, fmt.Errorf("private corpus: %w", err)
		}
		// A checkout that came up empty must not pass as a private run.
		if len(samples) == 0 {
			return "", "", nil, fmt.Errorf("private corpus %s has no samples", dir)
		}
	}
	public, err := Load(PublicDir(), "public")
	if err != nil {
		return "", "", nil, fmt.Errorf("public corpus: %w", err)
	}
	if err = ValidateCoverage(public, true); err != nil {
		return "", "", nil, fmt.Errorf("public corpus: %w", err)
	}
	return reportDir, "", append(public, samples...), nil
}

// Drive replays every corpus sample through path p, one subtest per sample,
// and writes the report even when samples fail. run must not call t.Parallel:
// drivers swap package globals, and the report is written after the loop.
func Drive(t *testing.T, p Path, run func(t *testing.T, s Sample) Outcome) {
	t.Helper()
	reportDir, skip, samples, err := prepare(p, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	if skip != "" {
		t.Skip(skip)
	}
	results := replay(t, p, samples, run)
	if err := WriteReport(reportDir, p, results); err != nil {
		t.Errorf("report: %v", err)
	}
}

func replay(t *testing.T, p Path, samples []Sample, run func(t *testing.T, s Sample) Outcome) []Result {
	t.Helper()
	attempts := Offline(t)

	results := make([]Result, 0, len(samples))
	for _, s := range samples {
		ran := false
		t.Run(s.Half+"/"+s.Category+"/"+s.Name, func(t *testing.T) {
			ran = true
			// A driver that stops the subtest still leaves an error result.
			o := Outcome{Err: errors.New("driver stopped before returning an outcome")}
			before := attempts.Load()
			// Register first so driver cleanups finish before the verdict is recorded.
			t.Cleanup(func() {
				if o.Err == nil && (t.Failed() || t.Skipped()) {
					o.Err = errors.New("driver subtest did not pass")
				}
				o.NetworkAttempts += attempts.Load() - before
				r := Judge(s, p, o)
				for _, f := range r.Failures {
					t.Error(f)
				}
				results = append(results, r)
			})
			o = run(t, s)
			// Test logs become CI artifacts and error text can quote decoded
			// bytes. Public samples are already in the repository; private
			// ones keep only the error type.
			switch {
			case o.Err != nil && s.Half == "public":
				t.Logf("driver error: %v", o.Err)
			case o.Err != nil:
				t.Logf("driver error type: %T (details withheld)", o.Err)
			}
		})
		if !ran {
			r := Judge(s, p, Outcome{Err: errors.New("sample excluded by test filter")})
			results = append(results, r)
			t.Errorf("sample %s/%s/%s excluded by test filter", s.Half, s.Category, s.Name)
		}
	}
	return results
}
