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

func TestRuleTreeFingerprintTracksContentsWithPreservedMetadata(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "rewrite", true: "replace"}[replace], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "vendor.conf")
			writeRule(t, path, `SecRule ARGS "@rx x" "id:1,pass"`)
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			before, _ := RuleTreeFingerprint([]string{dir})
			target := path
			if replace {
				target = filepath.Join(dir, "replacement")
			}
			writeRule(t, target, `SecRule ARGS "@rx x" "id:1,deny"`)
			if err := os.Chtimes(target, info.ModTime(), info.ModTime()); err != nil {
				t.Fatal(err)
			}
			if replace {
				if err := os.Rename(target, path); err != nil {
					t.Fatal(err)
				}
			}
			after, _ := RuleTreeFingerprint([]string{dir})
			if before == after {
				t.Fatal("changed rule contents retained the cached fingerprint")
			}
		})
	}
}

func TestRuleTreeFingerprintTracksSymlinkTargets(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "rules.txt")
	writeRule(t, target, `SecRule ARGS "@rx x" "id:1,pass"`)
	if err := os.Symlink(target, filepath.Join(dir, "vendor.CONF")); err != nil {
		t.Fatal(err)
	}
	before, _ := RuleTreeFingerprint([]string{dir})
	writeRule(t, target, `SecRule ARGS "@rx x" "id:1,deny"`)
	after, _ := RuleTreeFingerprint([]string{dir})
	reg, err := BuildRegistry([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if action, _ := reg.Action(1); action != "deny" {
		t.Fatalf("registry did not read the symlink target: %q", action)
	}
	if before == after {
		t.Fatal("fingerprint missed a changed file that BuildRegistry reads")
	}
}

func TestRuleTreeFingerprintDoesNotCacheUnreadableFiles(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, filepath.Join(dir, "good.conf"), `SecRule ARGS "@rx x" "id:1,pass"`)
	if err := os.Symlink(filepath.Join(dir, "missing"), filepath.Join(dir, "broken.conf")); err != nil {
		t.Fatal(err)
	}
	if fingerprint, present := RuleTreeFingerprint([]string{dir}); fingerprint != "" || !present {
		t.Fatalf("unreadable tree: fingerprint=%q present=%v, want empty and true", fingerprint, present)
	}
}
