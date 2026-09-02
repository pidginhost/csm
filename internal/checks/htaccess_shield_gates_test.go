package checks

import (
	"os"
	"path/filepath"
	"testing"
)

// The shield detector's suppression gates were attacker-controlled: any
// alphanumeric anywhere in the FilesMatch pattern counted as "targeted", so
// `^(a|.*)\.php$` (which still matches every .php) was skipped, and three
// dummy .php files next to the .htaccess satisfied the sibling gate. A
// pattern is targeted only when every alternative names something, and the
// sibling gate does not apply inside upload-style trees, where droppers land.
func TestFilesMatchShieldPatternTargetedRequiresEveryAlternativeToName(t *testing.T) {
	targeted := []string{`wpc\.php$`, `ps_facetedsearch-.+\.php$`, `(webp-on-demand\.php|webp-realizer\.php)$`, `^(ajax|api)\.php$`}
	for _, p := range targeted {
		if !filesMatchPatternIsTargeted(p) {
			t.Errorf("%q should count as targeted", p)
		}
	}
	wildcard := []string{`\.php$`, `.*\.php$`, `[^/]+\.php$`, `^(a|.*)\.php$`, `^(wpc\.php|.*)$`, `(x|[^/]+)\.php$`}
	for _, p := range wildcard {
		if filesMatchPatternIsTargeted(p) {
			t.Errorf("%q matches arbitrary names and must not count as targeted", p)
		}
	}
}

func TestFilesMatchShieldSiblingGateIgnoredInUploadTrees(t *testing.T) {
	shield := []byte("<FilesMatch \"\\.php$\">\nAllow from all\n</FilesMatch>\n")
	mk := func(rel string) string {
		dir := filepath.Join(t.TempDir(), rel)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"a.php", "b.php", "c.php"} {
			if err := os.WriteFile(filepath.Join(dir, n), []byte("<?php\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		path := filepath.Join(dir, ".htaccess")
		if err := os.WriteFile(path, shield, 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	if got := detectFilesMatchShield(shield, mk(filepath.Join("public_html", "wp-content", "uploads", "2026", "09"))); len(got) == 0 {
		t.Fatal("three dummy PHP files under uploads silenced the shield finding")
	}
	if got := detectFilesMatchShield(shield, mk(filepath.Join("public_html", "wp-content", "plugins", "kcfinder"))); len(got) != 0 {
		t.Fatalf("plugin directory with sibling dispatchers still flagged: %+v", got)
	}
}
