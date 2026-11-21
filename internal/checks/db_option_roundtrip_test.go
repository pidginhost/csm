package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/mysqlclient"
)

// TestReadOptionValue_UnescapesBatchOutput proves readOptionValue returns the
// true byte-original of a wp_option, not the mysql batch-mode escaped text.
// Without unescaping, a real newline would come back as the two-byte literal
// "\n"; writing that back to the DB (and to the csm_backup rollback copy)
// corrupts the value and breaks PHP-serialized length prefixes.
func TestReadOptionValue_UnescapesBatchOutput(t *testing.T) {
	// s:11 counts the real newline byte between "line1" and "line2".
	original := "  a:1:{s:3:\"css\";s:11:\"line1\nline2\";}  "
	// What `mysql -N -B` / mysqlclient hand back for that value: the newline
	// rendered as a literal backslash-n (two bytes).
	batchEscaped := `  a:1:{s:3:"css";s:11:"line1\nline2";}  `

	mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, _ mysqlclient.Creds, query string, _ ...any) ([]string, error) {
		if !strings.Contains(query, "SELECT option_value") {
			t.Fatalf("unexpected query: %q", query)
		}
		return []string{batchEscaped}, nil
	})
	t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })

	got := readOptionValue(wpDBCreds{dbName: "db1", dbUser: "u", dbHost: "localhost"}, "wp_", "td_live_css_local_storage")
	if got != original {
		t.Fatalf("readOptionValue did not round-trip\n got:  %q\n want: %q", got, original)
	}
	if strings.Contains(got, `\n`) {
		t.Errorf("value still carries a literal backslash-n escape: %q", got)
	}
	if !strings.HasPrefix(got, "  ") || !strings.HasSuffix(got, "  ") {
		t.Errorf("value lost leading/trailing spaces: %q", got)
	}
}

// TestBackupAndCleanOption_BackupStoresTrueOriginal proves the csm_backup copy
// persists the true original bytes (real newline preserved) rather than the
// batch-escaped text, so a rollback restores a valid value.
func TestBackupAndCleanOption_BackupStoresTrueOriginal(t *testing.T) {
	maliciousURL := "https://evil.top/x.js"
	// True original: a real newline on either side of an injected attacker
	// script (evil.top is an abused TLD -> attacker indicator).
	original := "start\n<script src=\"" + maliciousURL + "\"></script>\nend"

	var inserted, updated bool
	withOptionExec(t, func(stmt string, args []any) (int64, error) {
		switch {
		case strings.HasPrefix(stmt, "INSERT"):
			inserted = true
			if len(args) != 2 || args[1] != original {
				t.Fatal("backup did not receive the exact original")
			}
		case strings.HasPrefix(stmt, "UPDATE"):
			updated = true
			if !inserted || !strings.Contains(stmt, "BINARY option_value=?") || len(args) != 3 ||
				args[0] != "start\n\nend" || args[1] != "opt" || args[2] != original {
				t.Fatal("update did not compare and replace the exact option bytes")
			}
		default:
			t.Fatalf("unexpected statement %q", stmt)
		}
		return 1, nil
	})
	creds := wpDBCreds{dbName: "db1", dbUser: "u", dbHost: "localhost"}
	if !backupAndCleanOption(creds, "wp_", "opt", original, maliciousURL) || !updated {
		t.Fatal("expected backup and update")
	}
}

func withOptionExec(t *testing.T, fn func(string, []any) (int64, error)) {
	t.Helper()
	old := execOptionWrite
	t.Cleanup(func() { execOptionWrite = old })
	execOptionWrite = func(_ context.Context, _ mysqlclient.Creds, stmt string, args ...any) (int64, error) {
		return fn(stmt, args)
	}
}

func TestCleanOptionConcurrentUpdate(t *testing.T) {
	withOptionExec(t, func(stmt string, _ []any) (int64, error) {
		if strings.HasPrefix(stmt, "INSERT") {
			return 1, nil
		}
		return 0, nil
	})
	name, err := writeCleanOption(wpDBCreds{}, "wp_", "widget_text", "before", "after")
	if name == "" || err == nil {
		t.Fatal("a concurrent edit must report failure and identify the retained backup")
	}
}
