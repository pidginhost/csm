package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/yara"
)

// cleanScanBackend is a loaded scanner whose rules match nothing, so a
// re-check reaches the demotion gates instead of stopping at "scanner
// unavailable".
type cleanScanBackend struct{}

func (cleanScanBackend) ScanFile(string, int) []yara.Match { return nil }
func (cleanScanBackend) ScanBytes([]byte) []yara.Match     { return nil }
func (cleanScanBackend) ScanBytesChecked([]byte) ([]yara.Match, error) {
	return nil, nil
}
func (cleanScanBackend) Reload() error  { return nil }
func (cleanScanBackend) RuleCount() int { return 5 }

func withCleanYARAScanner(t *testing.T) {
	t.Helper()
	old := contentYARAScanner
	contentYARAScanner = func() yara.Backend { return cleanScanBackend{} }
	t.Cleanup(func() { contentYARAScanner = old })
}

// Every other consumer of the quarantine allow-list resolves it through
// effectiveFixRoots, which turns the nil production value into the platform's
// account roots. Content re-verification read the raw var instead, so on a real
// host -- where nothing assigns it -- the allow-list was empty and every content
// finding failed the root check before its file was ever opened.
//
// The tests below pin the production shape: the override stays nil, exactly as
// it is on a running daemon. An override set to t.TempDir() hides the defect,
// which is why it survived from 2026-06-21 to 2026-09-04 with a green suite
// while cluster6 carried 92 content findings that could not be re-checked at
// all.

func TestReverifyContentFindingUsesAccountRootsWhenNoOverride(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	withCleanYARAScanner(t)

	// A cleaned file two levels below the account root, the shape a real
	// finding has: /<root>/<account>/public_html/index.php.
	dir := filepath.Join(root, "acct", "public_html")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	cleaned := filepath.Join(dir, "index.php")
	if err := os.WriteFile(cleaned, []byte("<?php\n// Silence is golden.\n"), 0644); err != nil {
		t.Fatal(err)
	}

	res := reverifyContentFinding(VerifyInput{
		Check: "yara_match_scheduled", Path: cleaned, ContentSHA256: "detection-time-hash",
	})
	if !res.Checked {
		t.Fatalf("a file under an account root must be re-checkable: %+v", res)
	}
	if res.Resolved {
		t.Fatalf("a modified file must never auto-clear: %+v", res)
	}
	if !res.Demote {
		t.Fatalf("a cleaned file should stop competing with live findings: %+v", res)
	}
}

func TestReverifyContentFindingReachesTempTreesWhenNoOverride(t *testing.T) {
	// Droppers land in the temp trees, which are reachable for quarantine and
	// so must be reachable for the re-check that follows one.
	root := t.TempDir()
	tempTree := t.TempDir()
	withAccountHomeRoots(t, root)
	withQuarantineExtraRoots(t, tempTree)
	withCleanYARAScanner(t)

	dropped := filepath.Join(tempTree, "dropper.php")
	if err := os.WriteFile(dropped, []byte("<?php\n// Silence is golden.\n"), 0644); err != nil {
		t.Fatal(err)
	}

	res := reverifyContentFinding(VerifyInput{
		Check: "yara_match_scheduled", Path: dropped, ContentSHA256: "detection-time-hash",
	})
	if !res.Checked {
		t.Fatalf("a file in a temp tree must be re-checkable: %+v", res)
	}
	if !res.Demote {
		t.Fatalf("a cleaned dropper should stop competing with live findings: %+v", res)
	}
}

func TestVerifyWriteBitUsesAccountRootsWhenNoOverride(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)

	dir := filepath.Join(root, "acct", "public_html")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	fixed := filepath.Join(dir, "wp-config.php")
	if err := os.WriteFile(fixed, []byte("<?php\n"), 0644); err != nil {
		t.Fatal(err)
	}

	res := verifyWriteBit(fixed, 0002, "world-writable")
	if !res.Checked {
		t.Fatalf("a file under an account root must be re-checkable: %+v", res)
	}
	if !res.Resolved {
		t.Fatalf("a file no longer world-writable should resolve: %+v", res)
	}
}

func TestVerifyHtaccessCleanUsesAccountRootsWhenNoOverride(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)

	dir := filepath.Join(root, "acct", "public_html")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	cleaned := filepath.Join(dir, ".htaccess")
	if err := os.WriteFile(cleaned, []byte("Options -Indexes\n"), 0644); err != nil {
		t.Fatal(err)
	}

	res := verifyHtaccessClean(cleaned)
	if !res.Checked {
		t.Fatalf("a .htaccess under an account root must be re-checkable: %+v", res)
	}
	if !res.Resolved {
		t.Fatalf("a cleaned .htaccess should resolve: %+v", res)
	}
}

func TestReverifyContentFindingRejectsPathOutsideEveryRoot(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	withCleanYARAScanner(t)

	outside := filepath.Join(t.TempDir(), "elsewhere", "index.php")
	if err := os.MkdirAll(filepath.Dir(outside), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("<?php\n// Silence is golden.\n"), 0644); err != nil {
		t.Fatal(err)
	}

	res := reverifyContentFinding(VerifyInput{
		Check: "yara_match_scheduled", Path: outside, ContentSHA256: "detection-time-hash",
	})
	if res.Checked || res.Demote || res.Resolved {
		t.Fatalf("a path outside every root must stay unchecked: %+v", res)
	}
	if !strings.Contains(res.Detail, "outside the allowed remediation roots") {
		t.Fatalf("detail should name the root check, got %q", res.Detail)
	}
}
