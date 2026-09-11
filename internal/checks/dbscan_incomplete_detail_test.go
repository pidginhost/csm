package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The incomplete finding used to carry one static sentence naming all three
// possible causes -- "a document-root record, wp-config.php file, or database
// query could not be read safely" -- without saying which install failed or
// which of the three it was. On a live host it fired on every cycle for
// weeks, so nobody could act on it: the one thing an operator needs is which
// install to go and look at.
//
// Preservation is deliberately left alone. These findings carry no FilePath,
// so the path-attributed gap mechanism cannot match them and switching to it
// would purge real findings instead of retaining them.
func TestDatabaseScanIncompleteNamesInstallAndCause(t *testing.T) {
	dir := t.TempDir()

	oversized := filepath.Join(dir, "oversized-wp-config.php")
	if err := os.WriteFile(oversized, []byte("<?php\ndefine('DB_NAME', 'a');\n"+strings.Repeat("# pad\n", maxCMSConfigBytes/6+2)), 0o600); err != nil {
		t.Fatal(err)
	}
	noCreds := filepath.Join(dir, "nocreds-wp-config.php")
	if err := os.WriteFile(noCreds, []byte("<?php\n$table_prefix = 'wp_';\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unsafePrefix := filepath.Join(dir, "unsafe-prefix-wp-config.php")
	if err := os.WriteFile(unsafePrefix, []byte("<?php\ndefine('DB_NAME', 'fixture');\ndefine('DB_USER', 'fixture');\n$table_prefix = 'unsafe-';\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	installs := []string{
		"/home/alice/public_html/wp-config.php",
		"/home/bob/public_html/wp-config.php",
		"/home/carol/public_html/wp-config.php",
	}
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/home/*/public_html/wp-config.php" {
				return installs, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "alice") {
				return os.Open(oversized)
			}
			if strings.Contains(name, "carol") {
				return os.Open(unsafePrefix)
			}
			return os.Open(noCreds)
		},
		lstat: func(name string) (os.FileInfo, error) { return mockPathInfo(name, installs) },
	})

	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	findings := CheckDatabaseContent(ctx, nil, nil)
	if !incomplete.contains("db_content") {
		t.Fatal("unreadable installs did not mark the database scan incomplete")
	}

	if len(findings) != 1 {
		t.Fatalf("want exactly one incomplete finding: %+v", findings)
	}
	details := databaseCoverageSummary(t, findings).Details
	want := "3 of 3 discovered installs could not be fully inspected.\n" +
		"missing_credentials=1 (example: /home/bob/public_html/wp-config.php)\n" +
		"unreadable_config=1 (example: /home/alice/public_html/wp-config.php)\n" +
		"unresolved_table_prefix=1 (example: /home/carol/public_html/wp-config.php)\n" +
		"Findings from the previous complete scan are retained."
	if details != want {
		t.Errorf("details = %q, want %q", details, want)
	}
}
