package checks

import (
	"fmt"
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

	prefix := "# kept\n\nOptions -Indexes\n\n"
	suffix := "\n# untouched\nDirectoryIndex index.html\n"
	path := writeHtaccess(t, dir, "site/assets", prefix+rewriteOffShieldTemplate+suffix)
	res := CleanHtaccessFile(path)
	if !res.Success {
		t.Fatalf("clean failed: %+v", res)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != prefix+suffix {
		t.Fatalf("cleaned bytes = %q, want %q", data, prefix+suffix)
	}
	if findings, _ := AuditHtaccessFile(path); countByCheck(findings, "htaccess_rewrite_off_shield") != 0 {
		t.Error("finding still raised after cleaning")
	}
}

func TestRewriteOffShieldDirectiveSyntax(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want int
	}{
		"grant with additional hosts":   {"RewriteEngine Off\n<FilesMatch \"^()$\">\nAllow from 192.0.2.1 all\n</FilesMatch>\n", 2},
		"tabbed grant":                  {"RewriteEngine Off\n<FilesMatch \"^()$\">\nAllow\tfrom\tall\n</FilesMatch>\n", 2},
		"continued grant":               {"RewriteEngine Off\n<FilesMatch \\\n\"^()$\">\nRequire all \\\ngranted\n</FilesMatch>\n", 2},
		"quoted grant":                  {"RewriteEngine Off\n<FilesMatch \"^()$\">\nRequire \"all\" \"granted\"\n</FilesMatch>\n", 2},
		"commented grant":               {"RewriteEngine Off\n<FilesMatch \"^()$\">\n# Allow from all\nRequire all denied\n</FilesMatch>\n", 0},
		"grant inside another argument": {"RewriteEngine Off\n<FilesMatch \"^()$\">\nErrorDocument 403 \"Require all granted\"\n</FilesMatch>\n", 0},
		"continued comment":             {"RewriteEngine Off\n# example \\\n<FilesMatch \"^()$\">\nAllow from all\n</FilesMatch>\n", 0},
		"unanchored alternative":        {"RewriteEngine Off\n<FilesMatch \"^()|()$\">\nAllow from all\n</FilesMatch>\n", 0},
		"literal colon filename":        {"RewriteEngine Off\n<FilesMatch \"^(:)$\">\nAllow from all\n</FilesMatch>\n", 0},
	} {
		t.Run(name, func(t *testing.T) {
			if got := len(detectRewriteOffShield([]byte(tc.body), ".htaccess")); got != tc.want {
				t.Fatalf("got %d matches, want %d", got, tc.want)
			}
		})
	}
}

func TestRewriteOffShieldPreservesUnrelatedBytes(t *testing.T) {
	for _, ending := range []string{"\n", "\r\n"} {
		t.Run(fmt.Sprintf("ending_%q", ending), func(t *testing.T) {
			prefix := "# before\n\nOptions -Indexes\n\n"
			suffix := "\n# after\n<FilesMatch \"\\.(css|js)$\">\nRequire all granted\n</FilesMatch>"
			content := []byte(strings.ReplaceAll(prefix+rewriteOffShieldTemplate+suffix, "\n", ending))
			matches := detectRewriteOffShield(content, ".htaccess")
			if len(matches) != 2 {
				t.Fatalf("got %d matches, want two offending blocks", len(matches))
			}
			got := applyRangeRemoval(content, mergeRanges(matchRanges(matches)))
			want := strings.ReplaceAll(prefix+suffix, "\n", ending)
			if string(got) != want {
				t.Fatalf("cleaned bytes = %q, want %q", got, want)
			}
		})
	}
}

func TestRewriteOffShieldPreservesSharedWrapper(t *testing.T) {
	prefix := "<IfModule mod_rewrite.c>\n# keep this comment\nOptions -Indexes\n"
	suffix := "\n</IfModule>\n\n"
	grant := "<FilesMatch \"^()$\">\nRequire all granted\n</FilesMatch>\n"
	content := []byte(prefix + "RewriteEngine Off\n" + suffix + grant)
	matches := detectRewriteOffShield(content, ".htaccess")
	if len(matches) != 2 {
		t.Fatalf("got %d matches, want 2", len(matches))
	}
	got := applyRangeRemoval(content, mergeRanges(matchRanges(matches)))
	if string(got) != prefix+suffix {
		t.Fatalf("cleaned bytes = %q, want %q", got, prefix+suffix)
	}
}
