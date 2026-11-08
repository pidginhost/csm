//go:build linux && !yara

package checks

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The scan drivers need the yara tag. Without it a requested corpus run must
// fail instead of passing with nothing replayed.
func TestAttackCorpusTier(t *testing.T) { requireYARATag(t, "tier") }

func TestAttackCorpusFullScan(t *testing.T) { requireYARATag(t, "fullscan") }

func requireYARATag(t *testing.T, path string) {
	t.Helper()
	if os.Getenv("CSM_ATTACK_CORPUS_REPORT_DIR") == "" && os.Getenv("CSM_ATTACK_CORPUS_REQUIRED") != "1" {
		t.Skip("CSM_ATTACK_CORPUS_REPORT_DIR is not set")
	}
	t.Fatalf("%s attack corpus requires -tags yara", path)
}

func TestAttackCorpusScanDriversRequireYARATag(t *testing.T) {
	for _, d := range []struct{ test, path string }{
		{"TestAttackCorpusTier", "tier"},
		{"TestAttackCorpusFullScan", "fullscan"},
	} {
		for _, env := range []struct {
			reportDir, required string
			fails               bool
		}{
			{"", "", false},
			{t.TempDir(), "", true},
			{"", "1", true},
		} {
			t.Setenv("CSM_ATTACK_CORPUS_REPORT_DIR", env.reportDir)
			t.Setenv("CSM_ATTACK_CORPUS_REQUIRED", env.required)
			// #nosec G204 -- re-exec this test binary with a fixed test name.
			out, err := exec.Command(os.Args[0], "-test.run=^"+d.test+"$", "-test.v").CombinedOutput()
			want := "--- SKIP: " + d.test
			if env.fails {
				want = d.path + " attack corpus requires -tags yara"
			}
			if (err != nil) != env.fails || !strings.Contains(string(out), want) {
				t.Errorf("%s with report dir %q, required %q: error %v, want %q in:\n%s", d.test, env.reportDir, env.required, err, want, out)
			}
		}
	}
}
