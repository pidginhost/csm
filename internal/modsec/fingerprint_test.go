package modsec

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Rebuilding the registry parses every vendor rule file. The rule tree changes
// rarely (a vendor pack update, cPanel's assemble job), so the refresh needs a
// cheap way to tell that nothing moved since the last build.

func writeRule(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRuleTreeFingerprintIsStableWhileTheTreeIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, filepath.Join(dir, "vendor.conf"), `SecRule ARGS "@rx x" "id:1,deny"`)

	first, present := RuleTreeFingerprint([]string{dir})
	if !present {
		t.Fatal("fingerprint reported no rule tree for an existing directory")
	}
	second, _ := RuleTreeFingerprint([]string{dir})
	if first != second {
		t.Fatalf("fingerprint changed without the tree changing: %q then %q", first, second)
	}
}

func TestRuleTreeFingerprintChangesWhenARuleFileIsRewritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vendor.conf")
	writeRule(t, path, `SecRule ARGS "@rx x" "id:1,deny"`)
	before, _ := RuleTreeFingerprint([]string{dir})

	// cPanel's modsec_assemble rewrites files in place; the directory mtime
	// alone does not move when that happens.
	writeRule(t, path, `SecRule ARGS "@rx x" "id:1,pass"`)
	if err := os.Chtimes(path, time.Now().Add(time.Second), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	after, _ := RuleTreeFingerprint([]string{dir})
	if after == before {
		t.Fatal("rewritten rule file did not change the fingerprint")
	}
}

func TestRuleTreeFingerprintChangesWhenARuleFileAppears(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, filepath.Join(dir, "vendor.conf"), `SecRule ARGS "@rx x" "id:1,deny"`)
	before, _ := RuleTreeFingerprint([]string{dir})

	writeRule(t, filepath.Join(dir, "nested", "extra.conf"), `SecRule ARGS "@rx y" "id:2,deny"`)

	after, _ := RuleTreeFingerprint([]string{dir})
	if after == before {
		t.Fatal("a rule file added in a subdirectory did not change the fingerprint")
	}
}

func TestRuleTreeFingerprintIgnoresNonRuleFiles(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, filepath.Join(dir, "vendor.conf"), `SecRule ARGS "@rx x" "id:1,deny"`)
	before, _ := RuleTreeFingerprint([]string{dir})

	writeRule(t, filepath.Join(dir, "notes.txt"), "not a rule file")

	after, _ := RuleTreeFingerprint([]string{dir})
	if after != before {
		t.Fatal("a file the registry never parses changed the fingerprint")
	}
}

func TestRuleTreeFingerprintReportsAnAbsentTree(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone")

	if _, present := RuleTreeFingerprint([]string{missing}); present {
		t.Fatal("fingerprint reported a rule tree that does not exist")
	}
}
