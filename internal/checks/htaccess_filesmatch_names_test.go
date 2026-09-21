package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

const logoHandlerHtaccess = "<FilesMatch \"logo\">\nSetHandler application/x-httpd-ea-php81\n</FilesMatch>\n"

// A FilesMatch pattern with no extension marker ("logo", "^(config|data)$")
// selects files by name, so a PHP handler inside it executes files that no
// extension list covers. The overlay must treat such a file as PHP so it is
// content-scanned, and the .htaccess check must report the remap.
func TestPHPPathExecutesUnderNameOnlyFilesMatchHandler(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".htaccess"), []byte(logoHandlerHtaccess), 0o644); err != nil {
		t.Fatal(err)
	}
	if !phpPathExecutes(filepath.Join(dir, "logo"), "logo") {
		t.Fatal("file selected by a name-only FilesMatch with a PHP handler not treated as executable")
	}

	restricted := "<FilesMatch \"\\.php$\">\nSetHandler application/x-httpd-ea-php81\n</FilesMatch>\n"
	if err := os.WriteFile(filepath.Join(dir, ".htaccess"), []byte(restricted), 0o644); err != nil {
		t.Fatal(err)
	}
	if phpPathExecutes(filepath.Join(dir, "logo"), "logo") {
		t.Fatal("extension-restricted handler context wrongly made a plain file executable")
	}
}

func TestCheckHtaccessFileReportsNameOnlyFilesMatchHandler(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{"name-only pattern", logoHandlerHtaccess, 1},
		{"mixed pattern with a bare name", "<FilesMatch \"\\.php$|^logo$\">\nSetHandler application/x-httpd-ea-php81\n</FilesMatch>\n", 1},
		{"nested mixed pattern", "<FilesMatch \"^(?:\\.php|logo)$\">\nSetHandler application/x-httpd-ea-php81\n</FilesMatch>\n", 1},
		{"extension-restricted", "<FilesMatch \"\\.php$\">\nSetHandler application/x-httpd-ea-php81\n</FilesMatch>\n", 0},
		{"nested extension group", "<FilesMatch \"^(?:foo|bar)\\.(?:php|phtml)$\">\nSetHandler application/x-httpd-ea-php81\n</FilesMatch>\n", 0},
		{"escaped pipe and class", "<FilesMatch \"^(?:foo\\|bar|[a|b]+)\\.php$\">\nSetHandler application/x-httpd-ea-php81\n</FilesMatch>\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp := filepath.Join(t.TempDir(), ".htaccess")
			if err := os.WriteFile(tmp, []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			withMockOS(t, &mockOS{open: func(string) (*os.File, error) { return os.Open(tmp) }})
			var findings []alert.Finding
			checkHtaccessFile(context.Background(), tmp, nil, nil, &findings)
			got := 0
			for _, f := range findings {
				if f.Check == "htaccess_injection" {
					got++
				}
			}
			if got != tc.want {
				t.Fatalf("handler remap findings = %d, want %d: %+v", got, tc.want, findings)
			}
		})
	}
}

func TestTopLevelAlternativesIgnoresNestedEscapedAndClassPipes(t *testing.T) {
	pattern := `(?:foo|bar)\.php|logo\|pipe|[a|b]\.phtml`
	got := topLevelAlternatives(pattern)
	if len(got) != 3 {
		t.Fatalf("topLevelAlternatives(%q) = %v, want 3 branches", pattern, got)
	}
}

func TestFilesMatchSelectsByNameNestedAlternatives(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		want    bool
	}{
		{`^(?:\.php|logo)$`, true},
		{`^(?:\.php|(?:\.phtml|logo))$`, true},
		{`^(?:foo|bar)\.(?:php|phtml)$`, false},
		{`^logo(?:\.php)?$`, true},
		{`^(?:foo\|bar|[a|b]+)\.php$`, false},
		{`^[.]phtml$`, true},
		{`\.php{999999999999999999999}`, true},
		{`\.php{1,bad}`, true},
		{`\.php{2,1}`, true},
	} {
		if got := filesMatchSelectsByName(tc.pattern); got != tc.want {
			t.Errorf("filesMatchSelectsByName(%q) = %v, want %v", tc.pattern, got, tc.want)
		}
	}
}
