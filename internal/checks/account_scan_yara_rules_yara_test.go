//go:build yara

package checks

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/yara"
)

// The full account scan runs the shipped rule set over the account's
// document roots: a dormant shell in an addon-domain directory is reported,
// a clean file beside it is not.
func TestFullAccountScanMatchesShippedYARARules(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	scanner, err := yara.NewScanner(filepath.Join(filepath.Dir(thisFile), "..", "..", "configs"))
	if err != nil {
		t.Fatal(err)
	}
	yara.SetActive(scanner)
	t.Cleanup(func() { yara.SetActive(nil) })

	root := filepath.Join(t.TempDir(), "home")
	withAccountHomeRoots(t, root)
	shell := writeYARADeepFile(t, root, "alice/addon.example/assets/cache.dat", "<?php system($_POST['cmd']);")
	writeYARADeepFile(t, root, "alice/addon.example/assets/site.css", "body { margin: 0; }")
	cfg := &config.Config{StatePath: t.TempDir()}

	findings := RunAccountScanWithOptions(context.Background(), cfg, nil, "alice", FullScanOptions(cfg, false))

	got := yaraMatchPaths(findings)
	if len(got) == 0 {
		t.Fatalf("no YARA match for %s; findings %+v", shell, findings)
	}
	for _, path := range got {
		if path != shell {
			t.Fatalf("YARA matched %s, want only %s", path, shell)
		}
	}
}
