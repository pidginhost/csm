package attackcorpus

import (
	"os"
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
