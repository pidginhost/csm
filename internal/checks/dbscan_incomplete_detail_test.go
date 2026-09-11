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

	installs := []string{
		"/home/alice/public_html/wp-config.php",
		"/home/bob/public_html/wp-config.php",
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
			return os.Open(noCreds)
		},
		lstat: func(name string) (os.FileInfo, error) { return mockPathInfo(name, installs) },
	})

	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	findings := CheckDatabaseContent(ctx, nil, nil)
	if !incomplete.contains("db_content") {
		t.Fatal("unreadable installs did not mark the database scan incomplete")
	}

	var gap *string
	for i := range findings {
		if findings[i].Check == "db_content_scan_incomplete" {
			gap = &findings[i].Details
		}
	}
	if gap == nil {
		t.Fatalf("no db_content_scan_incomplete finding: %+v", findings)
	}
	details := *gap

	// How many of how many, so the scale is visible without guessing.
	if !strings.Contains(details, "2 of 2") {
		t.Errorf("details do not say how many installs of how many failed: %q", details)
	}
	// Which cause, counted, rather than a list of every possible cause.
	for _, want := range []string{"unreadable_config=1", "missing_credentials=1"} {
		if !strings.Contains(details, want) {
			t.Errorf("details do not count the cause %q: %q", want, details)
		}
	}
	// Which install to go and look at.
	if !strings.Contains(details, "/home/alice/public_html/wp-config.php") {
		t.Errorf("details name no example install for the unreadable config: %q", details)
	}
	// The retention promise must survive.
	if !strings.Contains(details, "retained") {
		t.Errorf("details dropped the retention note: %q", details)
	}
}
