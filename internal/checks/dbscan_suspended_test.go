package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A suspended account's database users are locked by cPanel, so every query
// against its installs fails with an access error. Those failures were counted
// as missing database coverage, which kept a warning open on every scan that
// no operator action could clear, and kept the check from ever completing.
func TestDatabaseScanSkipsSuspendedAccounts(t *testing.T) {
	dir := t.TempDir()
	unreadable := filepath.Join(dir, "suspended-wp-config.php")
	if err := os.WriteFile(unreadable, []byte("<?php\n$table_prefix = 'wp_';\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/home/*/public_html/wp-config.php" {
				return []string{"/home/parked/public_html/wp-config.php"}, nil
			}
			return nil, nil
		},
		open: func(string) (*os.File, error) { return os.Open(unreadable) },
		stat: func(name string) (os.FileInfo, error) {
			if name == "/var/cpanel/suspended/parked" {
				return fakeFileInfo{name: "parked"}, nil
			}
			return nil, os.ErrNotExist
		},
		readDir: func(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist },
	})

	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	findings := CheckDatabaseContent(ctx, nil, nil)

	// The fixture's mocked filesystem makes document-root discovery itself
	// incomplete, which is reported on its own and is not what this pins. What
	// matters is that the suspended install is never counted as an install the
	// scan failed to inspect.
	for _, f := range findings {
		if f.Check != "db_content_scan_incomplete" {
			continue
		}
		if strings.Contains(f.Details, "could not be fully inspected") &&
			!strings.HasPrefix(f.Details, "0 of 0") {
			t.Fatalf("a suspended account was counted as an uninspected install: %s", f.Details)
		}
		if strings.Contains(f.Details, "parked") {
			t.Fatalf("a suspended account was named as a coverage gap: %s", f.Details)
		}
	}
	_ = incomplete
}
