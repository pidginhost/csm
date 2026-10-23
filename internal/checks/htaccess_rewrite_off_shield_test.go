package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The template turns rewriting off for its directory, which drops the rewrite
// protections a parent .htaccess applies there, and carries an access grant
// whose file list was left empty. No author writes a grant for a name that
// cannot exist, so the empty grant marks the file as the template's.
const rewriteOffShieldTemplate = "<IfModule mod_rewrite.c>\n" +
	"    RewriteEngine Off\n" +
	"</IfModule>\n" +
	"<FilesMatch \"^()$\">\n" +
	"Order allow,deny\n" +
	"Allow from all\n" +
	"</FilesMatch>\n"

func TestDetectorRewriteOffShieldFlagsEmptyGrantTemplate(t *testing.T) {
	path := writeHtaccess(t, t.TempDir(), "site/assets", rewriteOffShieldTemplate)
	findings, _ := AuditHtaccessFile(path)
	// One finding for the rewrite switch and one for the grant block.
	if got := countByCheck(findings, "htaccess_rewrite_off_shield"); got != 2 {
		t.Errorf("rewrite_off_shield findings = %d, want 2", got)
	}
}

func TestDetectorRewriteOffShieldEmptyNameSpellings(t *testing.T) {
	for name, open := range map[string]string{
		"bare anchors":        `<FilesMatch "^$">`,
		"empty alternation":   `<FilesMatch "^(|)$">`,
		"non-capturing group": `<FilesMatch '^(?:)$'>`,
		"unquoted":            `<FilesMatch ^()$>`,
	} {
		t.Run(name, func(t *testing.T) {
			body := "RewriteEngine off\n" + open + "\n    Require all granted\n</FilesMatch>\n"
			path := writeHtaccess(t, t.TempDir(), "site", body)
			findings, _ := AuditHtaccessFile(path)
			if got := countByCheck(findings, "htaccess_rewrite_off_shield"); got != 2 {
				t.Errorf("rewrite_off_shield findings = %d, want 2", got)
			}
		})
	}
}

// Plugins ship asset folders that switch rewriting off and grant access to
// named static file types. Each half of the template alone is also not
// enough: rewriting off is a common setting, and an empty grant with rewriting
// still on changes nothing.
func TestDetectorRewriteOffShieldIgnoresLegitimateAndPartialFiles(t *testing.T) {
	for name, body := range map[string]string{
		"asset folder grant": "RewriteEngine Off\n" +
			"<FilesMatch \"\\.(css|js|png|jpe?g|gif|svg|woff2?)$\">\n" +
			"    Order allow,deny\n    Allow from all\n</FilesMatch>\n",
		"rewriting off alone": "<IfModule mod_rewrite.c>\nRewriteEngine Off\n</IfModule>\n",
		"empty grant with rewriting on": "RewriteEngine On\n" +
			"<FilesMatch \"^()$\">\nAllow from all\n</FilesMatch>\n",
		"commented rewrite switch": "# RewriteEngine Off\n" +
			"<FilesMatch \"^()$\">\nAllow from all\n</FilesMatch>\n",
		"empty block that denies": "RewriteEngine Off\n" +
			"<FilesMatch \"^()$\">\nRequire all denied\n</FilesMatch>\n",
		"unanchored pattern": "RewriteEngine Off\n" +
			"<FilesMatch \"()\">\nAllow from all\n</FilesMatch>\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := writeHtaccess(t, t.TempDir(), "site", body)
			findings, _ := AuditHtaccessFile(path)
			if got := countByCheck(findings, "htaccess_rewrite_off_shield"); got != 0 {
				t.Errorf("rewrite_off_shield findings = %d, want 0", got)
			}
		})
	}
}

func TestCleanHtaccessFileRemovesRewriteOffShield(t *testing.T) {
	prevRoots := fixHtaccessAllowedRoots
	prevBackup := htaccessBackupDirRoot
	t.Cleanup(func() {
		fixHtaccessAllowedRoots = prevRoots
		htaccessBackupDirRoot = prevBackup
	})
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fixHtaccessAllowedRoots = []string{dir}
	htaccessBackupDirRoot = filepath.Join(t.TempDir(), "pre_clean")

	path := writeHtaccess(t, dir, "site/assets", "# kept\n"+rewriteOffShieldTemplate)
	res := CleanHtaccessFile(path)
	if !res.Success {
		t.Fatalf("clean failed: %+v", res)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cleaned := string(data)
	for _, gone := range []string{"RewriteEngine", "FilesMatch", "Allow from all"} {
		if strings.Contains(cleaned, gone) {
			t.Errorf("cleaned file still contains %q:\n%s", gone, cleaned)
		}
	}
	if !strings.Contains(cleaned, "# kept") {
		t.Errorf("cleaner removed unrelated content:\n%s", cleaned)
	}
	if findings, _ := AuditHtaccessFile(path); countByCheck(findings, "htaccess_rewrite_off_shield") != 0 {
		t.Error("finding still raised after cleaning")
	}
}
