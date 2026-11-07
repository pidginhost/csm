//go:build linux && !yara

package daemon

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Keep the gate present in untagged builds: a requested run must not pass
// merely because the YARA-backed test was excluded from the binary.
func TestAttackCorpusRealtime(t *testing.T) {
	if os.Getenv("CSM_ATTACK_CORPUS_REPORT_DIR") == "" && os.Getenv("CSM_ATTACK_CORPUS_REQUIRED") != "1" {
		t.Skip("CSM_ATTACK_CORPUS_REPORT_DIR is not set")
	}
	t.Fatal("realtime attack corpus requires -tags yara")
}

func TestAttackCorpusRealtimeRequiresYARA(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"optional", "required", "report"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("CSM_ATTACK_CORPUS_REQUIRED", "")
			t.Setenv("CSM_ATTACK_CORPUS_REPORT_DIR", "")
			if mode == "required" {
				t.Setenv("CSM_ATTACK_CORPUS_REQUIRED", "1")
			}
			if mode == "report" {
				t.Setenv("CSM_ATTACK_CORPUS_REPORT_DIR", t.TempDir())
			}
			// #nosec G204 -- re-exec this test binary with a fixed test name.
			cmd := exec.Command(exe, "-test.run=^TestAttackCorpusRealtime$", "-test.v", "-test.timeout=30s")
			output, err := cmd.CombinedOutput()
			if mode == "optional" {
				if err != nil || !strings.Contains(string(output), "--- SKIP: TestAttackCorpusRealtime") {
					t.Fatalf("optional corpus did not skip: %v; %s", err, output)
				}
			} else if err == nil || !strings.Contains(string(output), "requires -tags yara") {
				t.Fatalf("requested corpus did not reject the missing engine: %v; %s", err, output)
			}
		})
	}
}
