package uitest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The dashboard's JavaScript has no build step and no runner of its own, so
// its unit tests run through Go. A machine without node skips them; the CI test
// job installs node and sets CSM_REQUIRE_NODE=1, so a missing runtime there is
// a failure rather than a quiet skip. The server side of the same behaviour is
// covered by the handler tests in internal/webui.
func TestBrowserSourcesPassTheirNodeTests(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CSM_REQUIRE_NODE") == "1" {
			t.Fatalf("CSM_REQUIRE_NODE=1 but node is unavailable: %v", err)
		}
		t.Skip("node is not installed; set CSM_REQUIRE_NODE=1 to require it")
	}
	matches, err := filepath.Glob(filepath.Join("..", "..", "ui", "*_test.js"))
	if err != nil {
		t.Fatalf("glob browser tests: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no browser tests found; this runner has nothing to protect")
	}
	args := append([]string{"--test"}, matches...)
	cmd := exec.Command(node, args...) // #nosec G204 -- fixed flags over a repo-local glob
	// Intl follows the host locale; pin the one the expectations are written in.
	cmd.Env = append(os.Environ(), "LC_ALL=en_US.UTF-8", "LANG=en_US.UTF-8")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node --test failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "fail 0") {
		t.Fatalf("node --test reported failures:\n%s", out)
	}
}
