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

func TestBuildRegistryFingerprintMatchesTheTreeFingerprint(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, filepath.Join(dir, "empty.conf"), "")
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

func TestBuildRegistryFingerprintMatchesForAnEmptyFile(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, filepath.Join(dir, "empty.conf"), "")
	reg, err := BuildRegistry([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	tree, present := RuleTreeFingerprint([]string{dir})
	if !present || tree == "" || reg.Fingerprint() != tree || reg.Len() != 0 {
		t.Fatalf("empty file: registry=%q tree=%q present=%v rules=%d", reg.Fingerprint(), tree, present, reg.Len())
	}
}

func TestBuildRegistryKeepsItsFingerprintWhenAFileCannotBeParsed(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"physical_line", strings.Repeat("A", maxModsecLineBytes+1)},
		{"continued_line", strings.Repeat(strings.Repeat("A", 1024)+"\\\n", maxModsecLineBytes/1024+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeRule(t, filepath.Join(dir, "vendor.conf"), `SecRule ARGS "@rx x" "id:1,pass"`)
			path := filepath.Join(dir, "oversized.conf")
			writeRule(t, path, tc.body+"\ntail A\n")

			reg, err := BuildRegistry([]string{dir})
			if err == nil {
				t.Fatal("an unparseable rule file must still be reported")
			}
			if action, ok := reg.Action(1); !ok || action != "pass" {
				t.Fatalf("rules from the readable files were lost: action=%q ok=%v", action, ok)
			}
			tree, _ := RuleTreeFingerprint([]string{dir})
			if reg.Fingerprint() == "" || reg.Fingerprint() != tree {
				t.Fatalf("registry fingerprint %q does not match the complete tree fingerprint %q", reg.Fingerprint(), tree)
			}

			// Bytes beyond either parser ceiling must still affect the cache.
			writeRule(t, path, tc.body+"\ntail B\n")
			changed, _ := RuleTreeFingerprint([]string{dir})
			if changed == tree {
				t.Fatal("changed unparsed tail retained the fingerprint")
			}
			reg, err = BuildRegistry([]string{dir})
			if err == nil || reg.Fingerprint() != changed {
				t.Fatalf("changed tail: fingerprint=%q want=%q err=%v", reg.Fingerprint(), changed, err)
			}
		})
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
