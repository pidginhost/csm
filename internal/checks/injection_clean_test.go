package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withQuarantineDirT redirects quarantineDir for any test (linux or
// macOS). Distinct from withQuarantineDir (linux test file) to avoid
// duplicate symbol errors.
func withQuarantineDirT(t *testing.T, dir string) {
	t.Helper()
	old := quarantineDir
	quarantineDir = dir
	t.Cleanup(func() { quarantineDir = old })
}

func writeTempPHP(t *testing.T, content string) string {
	t.Helper()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "victim.php")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCleanInfectedFileMissingFileReturnsError(t *testing.T) {
	withQuarantineDirT(t, t.TempDir())
	res := CleanInfectedFile("/nonexistent/path/file.php")
	if res.Cleaned || !strings.Contains(res.Error, "cannot read file") {
		t.Errorf("expected read error, got %+v", res)
	}
}

func TestCleanInfectedFileNoInjectionsReturnsError(t *testing.T) {
	withQuarantineDirT(t, t.TempDir())
	path := writeTempPHP(t, "<?php\n// clean code\necho 'hello world';\n")

	res := CleanInfectedFile(path)
	if res.Cleaned {
		t.Errorf("clean file should not report Cleaned=true, got %+v", res)
	}
	if !strings.Contains(res.Error, "no known injection patterns") {
		t.Errorf("expected 'no known injection patterns' error, got %+v", res)
	}
	// Backup should have been written even though clean failed.
	if res.BackupPath == "" {
		t.Error("backup path should be populated even when no patterns found")
	}
	if _, err := os.Stat(res.BackupPath); err != nil {
		t.Errorf("backup file should exist: %v", err)
	}
}

func TestCleanInfectedFileRemovesIncludeInjection(t *testing.T) {
	withQuarantineDirT(t, t.TempDir())
	content := "<?php\n@include(\"/tmp/payload.txt\");\necho 'app';\n"
	path := writeTempPHP(t, content)

	res := CleanInfectedFile(path)
	if !res.Cleaned {
		t.Fatalf("expected cleaned, got %+v", res)
	}
	if len(res.Removals) == 0 {
		t.Error("expected at least one removal")
	}
	cleaned, _ := os.ReadFile(path)
	if strings.Contains(string(cleaned), "@include") {
		t.Errorf("@include should be stripped:\n%s", cleaned)
	}
	if !strings.Contains(string(cleaned), "echo 'app'") {
		t.Errorf("legitimate code should be preserved:\n%s", cleaned)
	}
}

func TestCleanInfectedFileRemovesAppendInjectionAfterCloseTag(t *testing.T) {
	withQuarantineDirT(t, t.TempDir())
	// Legitimate file ending with ?>, then a second <?php block appended.
	// removeAppendInjection scans content after the LAST ?> — so we must NOT
	// have a second ?> after the malicious payload.
	content := "<?php\necho 'legit content here';\n?>\n<?php @system($_GET['c']);\n"
	path := writeTempPHP(t, content)

	res := CleanInfectedFile(path)
	if !res.Cleaned {
		t.Fatalf("expected cleaned, got %+v", res)
	}
	cleaned, _ := os.ReadFile(path)
	cs := string(cleaned)
	if strings.Contains(cs, "@system") {
		t.Errorf("appended @system should be stripped:\n%s", cs)
	}
	if !strings.Contains(cs, "legit content here") {
		t.Errorf("legitimate code should be preserved:\n%s", cs)
	}
}

func TestCleanInfectedFileRemovesChrChain(t *testing.T) {
	withQuarantineDirT(t, t.TempDir())
	// chr() chain on standalone line — at least 5 chr() calls concatenated.
	chrLine := strings.Repeat("chr(115).", 6) + "chr(116);"
	// Pad with junk so the line passes the >80-char gate via removeMultiLayerBase64
	// path (chrChain regex itself has no length gate but the function does).
	content := "<?php\n" +
		"// legit header comment that should survive cleaning operations safely\n" +
		"$x = " + chrLine + " // long padding to ensure >80 char detection threshold met\n" +
		"echo 'app body';\n"
	path := writeTempPHP(t, content)

	res := CleanInfectedFile(path)
	if !res.Cleaned {
		t.Fatalf("expected cleaned, got %+v", res)
	}
	cleaned, _ := os.ReadFile(path)
	cs := string(cleaned)
	if strings.Contains(cs, "chr(115).chr(115)") {
		t.Errorf("chr() chain should be stripped:\n%s", cs)
	}
	if !strings.Contains(cs, "echo 'app body'") {
		t.Errorf("legitimate code preserved:\n%s", cs)
	}
}

func TestCleanInfectedFileBackupHasMetaSidecar(t *testing.T) {
	qdir := t.TempDir()
	withQuarantineDirT(t, qdir)
	path := writeTempPHP(t, "<?php\n@include(\"/tmp/x\");\n")

	res := CleanInfectedFile(path)
	if !res.Cleaned {
		t.Fatalf("expected cleaned, got %+v", res)
	}
	if _, err := os.Stat(res.BackupPath + ".meta"); err != nil {
		t.Errorf(".meta sidecar should exist next to backup: %v", err)
	}
}

func TestShouldCleanInsteadOfQuarantine(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/home/u/public_html/wp-includes/post.php", true},
		{"/home/u/public_html/wp-admin/options.php", true},
		{"/home/u/public_html/wp-content/plugins/foo/foo.php", true},
		{"/home/u/public_html/wp-content/themes/twenty/index.php", true},
		// Webshell name in a plugin dir → still quarantine (don't preserve).
		{"/home/u/public_html/wp-content/plugins/foo/c99.php", false},
		// Standalone files outside WP → quarantine.
		{"/home/u/public_html/dropper.php", false},
		{"/tmp/evil.php", false},
	}
	for _, c := range cases {
		if got := ShouldCleanInsteadOfQuarantine(c.path); got != c.want {
			t.Errorf("ShouldCleanInsteadOfQuarantine(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestFormatCleanResult(t *testing.T) {
	cases := []struct {
		name    string
		in      CleanResult
		mustHas []string
	}{
		{
			name:    "error",
			in:      CleanResult{Path: "/x/y.php", Error: "boom"},
			mustHas: []string{"FAILED", "/x/y.php", "boom"},
		},
		{
			name:    "noop",
			in:      CleanResult{Path: "/x/y.php"},
			mustHas: []string{"No changes made", "/x/y.php"},
		},
		{
			name: "cleaned",
			in: CleanResult{
				Path: "/x/y.php", Cleaned: true,
				BackupPath: "/q/y.php",
				Removals:   []string{"removed @include injection: @include(\"/tmp/x\")"},
			},
			mustHas: []string{"CLEANED", "/x/y.php", "Backup:", "/q/y.php", "removed @include"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := FormatCleanResult(c.in)
			for _, s := range c.mustHas {
				if !strings.Contains(got, s) {
					t.Errorf("output missing %q:\n%s", s, got)
				}
			}
		})
	}
}

func TestShannonEntropyBoundaries(t *testing.T) {
	if got := shannonEntropy(""); got != 0 {
		t.Errorf("empty string entropy should be 0, got %v", got)
	}
	if got := shannonEntropy("aaaa"); got != 0 {
		t.Errorf("uniform string entropy should be 0, got %v", got)
	}
	// Random-ish content should have entropy > 2.
	if got := shannonEntropy("abcdefghijklmnop"); got < 2 {
		t.Errorf("varied string entropy should be > 2, got %v", got)
	}
}

func TestContainsLongEncodedString(t *testing.T) {
	if containsLongEncodedString("short", 100) {
		t.Error("short string should not match minLength=100")
	}
	long := strings.Repeat("Ab12+/", 30)
	if !containsLongEncodedString(long, 100) {
		t.Errorf("180-char base64-like string should match minLength=100")
	}
}
