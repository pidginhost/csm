package attackcorpus

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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
