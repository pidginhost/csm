package modsec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The refresh skips a rebuild when the tree fingerprint equals the one the
// last registry was built from, so the two must be computed over the same
// files and the same bytes. If they can ever differ for an unchanged tree,
// the cache never hits and every refresh reparses the whole vendor pack.

func oversizedRuleFile(t *testing.T, dir string) {
	t.Helper()
	// One logical line past the parser's ceiling: the file reads fine and its
	// content never changes, but parsing it always fails.
	body := `SecRule ARGS "@rx ` + strings.Repeat("A", 9<<20) + `" "id:99,deny"`
	if err := os.WriteFile(filepath.Join(dir, "oversized.conf"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBuildRegistryFingerprintMatchesTheTreeFingerprint(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, filepath.Join(dir, "vendor.conf"), `SecRule ARGS "@rx x" "id:1,pass"`)
	writeRule(t, filepath.Join(dir, "nested", "extra.conf"), `SecRule ARGS "@rx y" "id:2,deny"`)

	reg, err := BuildRegistry([]string{dir})
	if err != nil {
		t.Fatalf("BuildRegistry: %v", err)
	}
	tree, present := RuleTreeFingerprint([]string{dir})
	if !present {
		t.Fatal("rule tree reported absent")
	}
	if reg.Fingerprint() != tree {
		t.Fatalf("registry fingerprint %q does not match the tree fingerprint %q", reg.Fingerprint(), tree)
	}
}

func TestBuildRegistryKeepsItsFingerprintWhenAFileCannotBeParsed(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, filepath.Join(dir, "vendor.conf"), `SecRule ARGS "@rx x" "id:1,pass"`)
	oversizedRuleFile(t, dir)

	reg, err := BuildRegistry([]string{dir})
	if err == nil {
		t.Fatal("an unparseable rule file must still be reported")
	}
	if action, ok := reg.Action(1); !ok || action != "pass" {
		t.Fatalf("rules from the readable files were lost: action=%q ok=%v", action, ok)
	}
	tree, _ := RuleTreeFingerprint([]string{dir})
	if reg.Fingerprint() == "" {
		t.Fatal("a file that cannot be parsed left the build uncacheable; its bytes were read and will not change")
	}
	if reg.Fingerprint() != tree {
		t.Fatalf("registry fingerprint %q does not match the tree fingerprint %q", reg.Fingerprint(), tree)
	}
}

func TestBuildRegistryHasNoFingerprintWhenAFileCannotBeRead(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, filepath.Join(dir, "vendor.conf"), `SecRule ARGS "@rx x" "id:1,pass"`)
	if err := os.Symlink(filepath.Join(dir, "absent"), filepath.Join(dir, "broken.conf")); err != nil {
		t.Fatal(err)
	}

	reg, err := BuildRegistry([]string{dir})
	if err == nil {
		t.Fatal("an unreadable rule file must be reported")
	}
	if reg.Fingerprint() != "" {
		t.Fatal("a build that could not read every rule file must not be cacheable")
	}
}
