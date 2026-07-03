package signatures

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// One corrupt rule file must not disable every other rule file. Before the
// fix, Reload returned on the first yaml parse error, so a single operator
// typo in one file silently dropped ALL signature detection.
func TestReloadOneBadFileDoesNotAbortOthers(t *testing.T) {
	dir := t.TempDir()
	good := `
version: 3
rules:
  - name: good_rule
    description: "ok"
    severity: high
    category: webshell
    file_types: [".php"]
    patterns: ["eval("]
`
	// Names chosen so the bad file sorts BEFORE the good one; the old code
	// aborted on the first bad file and never reached the good one.
	if err := os.WriteFile(filepath.Join(dir, "00-bad.yml"), []byte("version: [\nrules:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "10-good.yml"), []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Scanner{rulesDir: dir}
	err := s.Reload()
	if err == nil {
		t.Fatal("expected Reload to report the corrupt file as an error")
	}
	if !strings.Contains(err.Error(), "00-bad.yml") {
		t.Errorf("error should name the bad file, got: %v", err)
	}
	if s.RuleCount() != 1 {
		t.Fatalf("good rule must still load despite the bad neighbour, got %d rules", s.RuleCount())
	}
	// The good rule must actually be usable, not just counted.
	if hits := s.ScanContent([]byte("<?php eval($_POST[x]); ?>"), ".php"); len(hits) != 1 {
		t.Errorf("loaded rule did not match; got %d hits", len(hits))
	}
}

// A load error is retained on the scanner so a caller (cmd/csm main) can log
// it loudly at startup instead of the corrupt-file failure being swallowed by
// NewScanner's best-effort `_ = s.Reload()`.
func TestNewScannerRetainsLoadError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.yml"), []byte("version: [\nrules:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(dir)
	if s.LoadError() == nil {
		t.Fatal("NewScanner must retain the load error from a corrupt rules dir")
	}
	if !strings.Contains(s.LoadError().Error(), "broken.yml") {
		t.Errorf("LoadError should name the corrupt file, got: %v", s.LoadError())
	}
}

// A clean load clears any previous load error.
func TestReloadClearsLoadErrorOnSuccess(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "rules.yml")
	if err := os.WriteFile(bad, []byte("version: [\nrules:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(dir)
	if s.LoadError() == nil {
		t.Fatal("precondition: expected a load error from the corrupt file")
	}

	good := `
version: 1
rules:
  - name: ok
    severity: high
    category: webshell
    file_types: [".php"]
    patterns: ["eval("]
`
	if err := os.WriteFile(bad, []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload of fixed file: %v", err)
	}
	if s.LoadError() != nil {
		t.Errorf("LoadError should be cleared after a clean reload, got: %v", s.LoadError())
	}
}
