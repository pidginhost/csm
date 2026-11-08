package attackcorpus

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	for _, mode := range []string{"success", "filtered", "partial", "skip", "fatal", "error", "cleanup", "returned", "returned_private", "returned_shown"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("CSM_ATTACK_CORPUS_TEST_MODE", mode)
			t.Setenv("CSM_ATTACK_CORPUS_TEST_REPORT", dir)
			show := ""
			if mode == "returned_shown" {
				show = "1"
			}
			t.Setenv("CSM_ATTACK_CORPUS_SHOW_ERRORS", show)
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
			if mode == "returned" || mode == "returned_private" {
				if strings.Contains(string(output), helperDriverError) {
					t.Error("a sample's driver error text reached the test log")
				}
				if !strings.Contains(string(output), "driver error: *errors.errorString (details withheld; set CSM_ATTACK_CORPUS_SHOW_ERRORS=1 locally)") {
					t.Error("a sample's driver error type is missing from the test log")
				}
			}
			if mode == "returned_shown" && !strings.Contains(string(output), "driver error: "+helperDriverError) {
				t.Error("CSM_ATTACK_CORPUS_SHOW_ERRORS=1 did not put the driver error reason in the test log")
			}
			if strings.HasPrefix(mode, "returned") && strings.Contains(string(data), helperDriverError) {
				t.Error("the driver's error reason reached the report")
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
	if mode == "returned_private" {
		samples[0].Half = "private"
	}
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
		case "returned", "returned_private", "returned_shown":
			return Outcome{Err: errors.New(helperDriverError)}
		}
		return Outcome{Remediation: untouched()}
	})
	if err := WriteReport(os.Getenv("CSM_ATTACK_CORPUS_TEST_REPORT"), Realtime, results); err != nil {
		t.Fatal(err)
	}
}

func TestDriverErrorText(t *testing.T) {
	err := fmt.Errorf("scan: %w", errors.New(helperDriverError))
	const withheld = "*fmt.wrapError (details withheld; set CSM_ATTACK_CORPUS_SHOW_ERRORS=1 locally)"
	for value, want := range map[string]string{"": withheld, "true": withheld, "0": withheld, "1": err.Error()} {
		t.Setenv("CSM_ATTACK_CORPUS_SHOW_ERRORS", value)
		if got := DriverErrorText(err); got != want {
			t.Errorf("CSM_ATTACK_CORPUS_SHOW_ERRORS=%q: DriverErrorText = %q, want %q", value, got, want)
		}
	}
}

// The report counts both the requests Offline refused and the lookups a
// driver's own seams answered.
func TestReplayAddsDriverNetworkAttempts(t *testing.T) {
	results := replay(t, Realtime, []Sample{judgeControl()}, func(t *testing.T, _ Sample) Outcome {
		req, err := http.NewRequest(http.MethodGet, "http://192.0.2.1/", nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp, err := http.DefaultTransport.RoundTrip(req); err == nil {
			_ = resp.Body.Close()
			t.Error("a request left the offline transport")
		}
		return Outcome{Remediation: untouched(), NetworkAttempts: 2}
	})
	if len(results) != 1 || results[0].NetworkAttempts != 3 {
		t.Fatalf("results %+v, want one with 3 network attempts", results)
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

// A pipeline that requires the private half fails without it, also where the
// run would otherwise skip for want of a report dir.
func TestDrivePrivateRequiredWithoutDir(t *testing.T) {
	for _, reports := range []string{"", t.TempDir()} {
		env := map[string]string{"CSM_ATTACK_CORPUS_REPORT_DIR": reports, "CSM_ATTACK_CORPUS_PRIVATE_REQUIRED": "1"}
		getenv := func(k string) string { return env[k] }
		_, skip, samples, err := prepare(Realtime, getenv)
		if err == nil || !strings.Contains(err.Error(), "CSM_ATTACK_CORPUS_PRIVATE is not set") || skip != "" || samples != nil {
			t.Errorf("required without a private corpus, report dir %q: %q, %d samples, %v; want an error naming CSM_ATTACK_CORPUS_PRIVATE", reports, skip, len(samples), err)
		}
		if _, _, _, err = prepare("yara", getenv); err == nil || !strings.Contains(err.Error(), `unknown path "yara"`) {
			t.Errorf("prepare(yara) = %v; want the unknown path error first", err)
		}

		// Only "1" requires the private half.
		env["CSM_ATTACK_CORPUS_PRIVATE_REQUIRED"] = "0"
		_, skip, samples, err = prepare(Realtime, getenv)
		if err != nil || (skip != "") != (reports == "") {
			t.Errorf("CSM_ATTACK_CORPUS_PRIVATE_REQUIRED=0, report dir %q: %q, %v; want the public run or its skip", reports, skip, err)
		}
		if slices.ContainsFunc(samples, func(s Sample) bool { return s.Half != "public" }) {
			t.Errorf("samples %+v include a private sample", samples)
		}
	}
}

func TestDrivePrivateRequiredEmpty(t *testing.T) {
	empty := t.TempDir()
	for _, private := range []string{empty, filepath.Join(empty, "missing")} {
		env := map[string]string{
			"CSM_ATTACK_CORPUS_REPORT_DIR":       t.TempDir(),
			"CSM_ATTACK_CORPUS_PRIVATE":          private,
			"CSM_ATTACK_CORPUS_PRIVATE_REQUIRED": "1",
		}
		_, skip, samples, err := prepare(Realtime, func(k string) string { return env[k] })
		if err == nil || !strings.Contains(err.Error(), "private corpus") || skip != "" || samples != nil {
			t.Errorf("required private corpus %s: %q, %d samples, %v; want a private corpus error", private, skip, len(samples), err)
		}
	}
}

func TestDrivePrivateRequiredCannotSkip(t *testing.T) {
	root := t.TempDir()
	s := maliciousSample()
	writeSample(t, filepath.Join(root, s.Category, s.Name), s)
	for _, private := range []string{root, filepath.Join(root, "missing")} {
		env := map[string]string{
			"CSM_ATTACK_CORPUS_PRIVATE":          private,
			"CSM_ATTACK_CORPUS_PRIVATE_REQUIRED": "1",
		}
		_, skip, samples, err := prepare(Realtime, func(k string) string { return env[k] })
		if err == nil || !strings.Contains(err.Error(), "CSM_ATTACK_CORPUS_REPORT_DIR") || skip != "" || samples != nil {
			t.Fatalf("required private run without reports: skip %q, %d samples, error %v; want a report directory error", skip, len(samples), err)
		}
	}
}

// Reports and subtests identify a sample by name, so a private sample must
// not reuse a public name, even in another category.
func TestLoadRejectsCrossHalfNameCollision(t *testing.T) {
	public, err := Load(PublicDir(), "public")
	if err != nil || len(public) == 0 {
		t.Fatalf("public corpus: %d samples, %v", len(public), err)
	}
	s := maliciousSample()
	s.Name = public[0].Name
	root := t.TempDir()
	writeSample(t, filepath.Join(root, s.Category, s.Name), s)
	if _, err = Load(root, "private"); err != nil {
		t.Fatalf("the private sample does not load on its own: %v", err)
	}
	env := map[string]string{"CSM_ATTACK_CORPUS_REPORT_DIR": t.TempDir(), "CSM_ATTACK_CORPUS_PRIVATE": root}
	_, _, samples, err := prepare(Realtime, func(k string) string { return env[k] })
	if err == nil || !strings.Contains(err.Error(), s.Category+"/"+s.Name) || samples != nil {
		t.Errorf("private sample named like public %s/%s: %d samples, %v; want an error naming it", public[0].Category, s.Name, len(samples), err)
	}
}

func TestPrivateCommitRejectsMalformed(t *testing.T) {
	const pin = "0123456789abcdef0123456789abcdef01234567"
	dir := t.TempDir()
	read := func(content string) (string, error) {
		path := filepath.Join(dir, "private.commit")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return readCommit(path)
	}
	for _, content := range []string{pin, pin + "\n"} {
		if got, err := read(content); err != nil || got != pin {
			t.Errorf("readCommit(%q) = %q, %v; want %q", content, got, err, pin)
		}
	}
	for name, content := range map[string]string{
		"empty":          "",
		"newline only":   "\n",
		"crlf":           pin + "\r\n",
		"leading space":  " " + pin,
		"trailing space": pin + " \n",
		"two newlines":   pin + "\n\n",
		"second line":    pin + "\n" + pin + "\n",
		"uppercase":      strings.ToUpper(pin),
		"short sha":      pin[:12] + "\n",
		"too long":       pin + "8\n",
		"ref name":       "refs/heads/main\n",
		"not hex":        strings.Repeat("g", 40) + "\n",
	} {
		got, err := read(content)
		if err == nil || got != "" {
			t.Errorf("%s: readCommit = %q, %v; want an error", name, got, err)
			continue
		}
		if strings.Contains(strings.ToLower(err.Error()), pin[:16]) {
			t.Errorf("%s: error %q quotes the file", name, err)
		}
	}
	if _, err := readCommit(filepath.Join(dir, "absent")); err == nil {
		t.Error("a missing pin file was accepted")
	}
}

// The shipped pin must be a valid full hash. The value itself is not checked
// here: it moves with each reviewed private commit.
func TestPrivateCommitIsPinned(t *testing.T) {
	got, err := PrivateCommit()
	if err != nil {
		t.Fatalf("PrivateCommit() error: %v", err)
	}
	if len(got) != 40 || strings.Trim(got, "0123456789abcdef") != "" {
		t.Errorf("PrivateCommit() = %q; want 40 lowercase hex digits", got)
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
