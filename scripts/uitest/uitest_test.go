package uitest

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The dashboard's JavaScript has no build step and no runner of its own, so
// its unit tests run through Go. A machine without node cannot check them, and
// CI's Go images carry none, so this is developer-local coverage; the server
// side of the same behaviour is covered by the handler tests in internal/webui.
func TestBrowserSourcesPassTheirNodeTests(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed; the browser tests cannot run here")
	}
	matches, err := filepath.Glob(filepath.Join("..", "..", "ui", "*_test.js"))
	if err != nil {
		t.Fatalf("glob browser tests: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no browser tests found; this runner has nothing to protect")
	}
	args := append([]string{"--test"}, matches...)
	out, err := exec.Command(node, args...).CombinedOutput() // #nosec G204 -- fixed flags over a repo-local glob
	if err != nil {
		t.Fatalf("node --test failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "fail 0") {
		t.Fatalf("node --test reported failures:\n%s", out)
	}
}
