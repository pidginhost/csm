package attackcorpus

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
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

// Drive replays every corpus sample through path p, one subtest per sample,
// and writes the report even when samples fail. run must not call t.Parallel:
// drivers swap package globals, and the report is written after the loop.
func Drive(t *testing.T, p Path, run func(t *testing.T, s Sample) Outcome) {
	t.Helper()
	reportDir, skip, err := gate(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	if skip != "" {
		t.Skip(skip)
	}
	attempts := Offline(t)

	samples, err := Load(PublicDir(), "public")
	if err != nil {
		t.Fatalf("public corpus: %v", err)
	}
	if err := ValidateCoverage(samples, true); err != nil {
		t.Fatalf("public corpus: %v", err)
	}
	if dir := os.Getenv("CSM_ATTACK_CORPUS_PRIVATE"); dir != "" {
		private, err := Load(dir, "private")
		if err != nil {
			t.Fatalf("private corpus: %v", err)
		}
		samples = append(samples, private...)
	}

	results := make([]Result, 0, len(samples))
	for _, s := range samples {
		t.Run(s.Half+"/"+s.Category+"/"+s.Name, func(t *testing.T) {
			// A driver that stops the subtest still leaves an error result.
			o := Outcome{Err: errors.New("driver stopped before returning an outcome")}
			before := attempts.Load()
			defer func() {
				o.NetworkAttempts = attempts.Load() - before
				r := Judge(s, p, o)
				for _, f := range r.Failures {
					t.Error(f)
				}
				results = append(results, r)
			}()
			o = run(t, s)
		})
	}
	if err := WriteReport(reportDir, p, results); err != nil {
		t.Errorf("report: %v", err)
	}
}
