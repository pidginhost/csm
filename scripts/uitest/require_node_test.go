package uitest

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Run the real test in a child process so Fatal and Skip remain observable
// without failing or skipping the test that checks the requirement.
func TestMissingNodeRequirement(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		required string
		wantFail bool
	}{
		{name: "optional"},
		{name: "disabled", required: "0"},
		{name: "required", required: "1", wantFail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// An empty search directory makes this independent of installed
			// runtimes, including the production builder which has no node.
			t.Setenv("PATH", t.TempDir())
			t.Setenv("CSM_REQUIRE_NODE", tc.required)
			cmd := exec.CommandContext(t.Context(), executable,
				"-test.run=^TestBrowserSourcesPassTheirNodeTests$", "-test.v", "-test.timeout=30s")
			out, err := cmd.CombinedOutput()
			if tc.wantFail {
				if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
					t.Fatalf("required node: want test failure, got %v\n%s", err, out)
				}
				if !strings.Contains(string(out), "CSM_REQUIRE_NODE=1 but node is unavailable") ||
					!strings.Contains(string(out), "--- FAIL: TestBrowserSourcesPassTheirNodeTests") {
					t.Fatalf("missing required-node failure:\n%s", out)
				}
				return
			}
			if err != nil || !strings.Contains(string(out), "--- SKIP: TestBrowserSourcesPassTheirNodeTests") {
				t.Fatalf("optional node: want successful skip, got %v\n%s", err, out)
			}
		})
	}
}
