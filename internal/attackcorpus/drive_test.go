package attackcorpus

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestDriveGate(t *testing.T) {
	cases := []struct {
		name     string
		env      map[string]string
		wantDir  string
		wantSkip bool
		wantErr  bool
	}{
		{name: "no report dir", env: map[string]string{}, wantSkip: true},
		{name: "required only when set to 1", env: map[string]string{"CSM_ATTACK_CORPUS_REQUIRED": "0"}, wantSkip: true},
		{name: "required without report dir", env: map[string]string{"CSM_ATTACK_CORPUS_REQUIRED": "1"}, wantErr: true},
		{name: "report dir", env: map[string]string{"CSM_ATTACK_CORPUS_REPORT_DIR": "/srv/reports"}, wantDir: "/srv/reports"},
		{name: "required with report dir", env: map[string]string{"CSM_ATTACK_CORPUS_REPORT_DIR": "/srv/reports", "CSM_ATTACK_CORPUS_REQUIRED": "1"}, wantDir: "/srv/reports"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, skip, err := gate(func(k string) string { return tc.env[k] })
			if dir != tc.wantDir || (skip != "") != tc.wantSkip || (err != nil) != tc.wantErr {
				t.Fatalf("gate = %q, %q, %v; want dir %q, skip %v, error %v", dir, skip, err, tc.wantDir, tc.wantSkip, tc.wantErr)
			}
			for _, msg := range []string{skip, errString(err)} {
				if msg != "" && !strings.Contains(msg, "CSM_ATTACK_CORPUS_REPORT_DIR") {
					t.Errorf("message %q does not name the variable to set", msg)
				}
			}
		})
	}
}

func TestReplayLifecycle(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "filtered", "partial", "skip", "fatal", "error", "cleanup", "returned"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("CSM_ATTACK_CORPUS_TEST_MODE", mode)
			t.Setenv("CSM_ATTACK_CORPUS_TEST_REPORT", dir)
			pattern := "^TestReplayHelper$"
			switch mode {
			case "filtered":
				pattern += "/does-not-match$"
			case "partial":
				pattern += "/public/webshell/judge_control$"
			}
			// #nosec G204 -- re-exec this test binary with a fixed helper test.
			cmd := exec.Command(exe, "-test.run="+pattern, "-test.timeout=30s")
			output, runErr := cmd.CombinedOutput()
			wantPass := mode == "success"
			if (runErr == nil) != wantPass {
				t.Errorf("helper success = %v, want %v; output: %s", runErr == nil, wantPass, output)
			}
			data, err := os.ReadFile(filepath.Join(dir, "realtime.json"))
			if err != nil {
				t.Fatal(err)
			}
			var report struct {
				Results []Result
				Summary map[Category]Counts
			}
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			wantResults := 1
			if mode == "partial" {
				wantResults = 2
			}
			if len(report.Results) != wantResults {
				t.Fatalf("report has %d results, want %d", len(report.Results), wantResults)
			}
			for _, r := range report.Results {
				wantResultPass := wantPass || (mode == "partial" && r.Sample == "judge_control")
				if r.Pass != wantResultPass || (len(r.Failures) == 0) != wantResultPass {
					t.Errorf("report verdict disagrees with the subtest: pass=%v, failures=%v", r.Pass, r.Failures)
				}
			}
			if !wantPass && report.Summary[Webshell].Errors != 1 {
				t.Error("the incomplete run was not counted as an error")
			}
			if mode == "returned" {
				if !strings.Contains(string(output), helperDriverError) {
					t.Errorf("the driver's error reason is missing from the test log: %s", output)
				}
				if strings.Contains(string(data), helperDriverError) {
					t.Error("the driver's error reason reached the report")
				}
			}
		})
	}
}

// helperDriverError stands in for a driver error that quotes sample bytes.
const helperDriverError = "parse error near sample bytes"

func TestReplayHelper(t *testing.T) {
	mode := os.Getenv("CSM_ATTACK_CORPUS_TEST_MODE")
	if mode == "" {
		return
	}
	samples := []Sample{judgeControl()}
	if mode == "partial" {
		other := judgeControl()
		other.Name = "other_control"
		samples = append(samples, other)
	}
	results := replay(t, Realtime, samples, func(t *testing.T, _ Sample) Outcome {
		switch mode {
		case "skip":
			t.Skip("engine unavailable")
		case "fatal":
			t.Fatal("driver setup failed")
		case "error":
			t.Error("driver setup failed")
		case "cleanup":
			t.Cleanup(func() { t.Error("driver cleanup failed") })
		case "returned":
			return Outcome{Err: errors.New(helperDriverError)}
		}
		return Outcome{Remediation: untouched()}
	})
	if err := WriteReport(os.Getenv("CSM_ATTACK_CORPUS_TEST_REPORT"), Realtime, results); err != nil {
		t.Fatal(err)
	}
}

func TestDriveRejectsUnknownPath(t *testing.T) {
	for _, env := range []map[string]string{{}, {"CSM_ATTACK_CORPUS_REPORT_DIR": t.TempDir()}} {
		_, skip, samples, err := prepare("yara", func(k string) string { return env[k] })
		if err == nil || !strings.Contains(err.Error(), `unknown path "yara"`) || skip != "" || samples != nil {
			t.Errorf("prepare(yara) with env %v = %q, %d samples, %v; want an unknown path error, not a skip", env, skip, len(samples), err)
		}
	}
	if _, skip, _, err := prepare(Realtime, func(string) string { return "" }); err != nil || skip == "" {
		t.Errorf("prepare(realtime) without a report dir = %q, %v; want a skip", skip, err)
	}
}

func TestDrivePrivateCorpus(t *testing.T) {
	reports := t.TempDir()
	run := func(private string) ([]Sample, error) {
		env := map[string]string{"CSM_ATTACK_CORPUS_REPORT_DIR": reports, "CSM_ATTACK_CORPUS_PRIVATE": private}
		_, _, samples, err := prepare(Realtime, func(k string) string { return env[k] })
		return samples, err
	}

	empty := t.TempDir()
	if _, err := run(empty); err == nil || !strings.Contains(err.Error(), empty) || !strings.Contains(err.Error(), "no samples") {
		t.Errorf("empty private corpus: %v; want an error naming %s", err, empty)
	}
	if _, err := run(filepath.Join(empty, "missing")); err == nil || !strings.Contains(err.Error(), "private corpus") {
		t.Errorf("missing private corpus: %v; want a private corpus error", err)
	}

	// A private corpus with a sample passes the private checks. Whether the
	// run then starts depends on the public corpus.
	root := t.TempDir()
	s := maliciousSample()
	writeSample(t, filepath.Join(root, s.Category, s.Name), s)
	samples, err := run(root)
	if err != nil && strings.Contains(err.Error(), "private") {
		t.Errorf("private corpus with one sample: %v", err)
	}
	if err == nil && !slices.ContainsFunc(samples, func(x Sample) bool { return x.Half == "private" && x.Name == s.Name }) {
		t.Errorf("samples %+v do not include the private sample", samples)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestConfigUnderTest(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	// #nosec G304 -- the shipped template at a fixed path in this repo.
	template, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "configs", "csm.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := config.LoadBytes(template)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	got, err := Config(stateDir)
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if !got.AutoResponse.Enabled || !got.AutoResponse.QuarantineFiles || got.ObserveMode() || got.StatePath != stateDir {
		t.Fatalf("auto_response.enabled=%v quarantine_files=%v observe=%v state_path=%q; want true, true, false, %q",
			got.AutoResponse.Enabled, got.AutoResponse.QuarantineFiles, got.ObserveMode(), got.StatePath, stateDir)
	}

	rest := *got
	rest.AutoResponse.Enabled = plain.AutoResponse.Enabled
	rest.AutoResponse.QuarantineFiles = plain.AutoResponse.QuarantineFiles
	rest.Mode = plain.Mode
	rest.StatePath = plain.StatePath
	if !reflect.DeepEqual(&rest, plain) {
		t.Error("Config changed more than auto-response, quarantine, mode and state path")
	}
}
