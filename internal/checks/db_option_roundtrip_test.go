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
	original := "a:1:{s:3:\"css\";s:11:\"line1\nline2\";}"
	// What `mysql -N -B` / mysqlclient hand back for that value: the newline
	// rendered as a literal backslash-n (two bytes).
	batchEscaped := `a:1:{s:3:"css";s:11:"line1\nline2";}`

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
}

// TestBackupAndCleanOption_BackupStoresTrueOriginal proves the csm_backup copy
// persists the true original bytes (real newline preserved) rather than the
// batch-escaped text, so a rollback restores a valid value.
func TestBackupAndCleanOption_BackupStoresTrueOriginal(t *testing.T) {
	maliciousURL := "https://evil.top/x.js"
	// True original: a real newline on either side of an injected attacker
	// script (evil.top is an abused TLD -> attacker indicator).
	original := "start\n<script src=\"" + maliciousURL + "\"></script>\nend"

	var queries []string
	mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, _ mysqlclient.Creds, query string, _ ...any) ([]string, error) {
		queries = append(queries, query)
		return nil, nil
	})
	t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })

	creds := wpDBCreds{dbName: "db1", dbUser: "u", dbHost: "localhost"}
	if !backupAndCleanOption(creds, "wp_", "opt", original, maliciousURL) {
		t.Fatal("expected clean to succeed and write a backup")
	}

	var insert, update string
	for _, q := range queries {
		switch {
		case strings.HasPrefix(strings.TrimSpace(q), "INSERT"):
			insert = q
		case strings.HasPrefix(strings.TrimSpace(q), "UPDATE"):
			update = q
		}
	}
	if insert == "" || update == "" {
		t.Fatalf("expected both INSERT (backup) and UPDATE (clean) queries; got %v", queries)
	}
	// The backup stores the SQL-escaped true original: a real newline appears
	// as the single-escape "\n" here, and NOT the double "\\n" that a
	// batch-escaped-then-re-escaped value would produce.
	if !strings.Contains(insert, escapeSQLString(original)) {
		t.Errorf("backup did not store the true original bytes\n insert: %q\n want substring: %q", insert, escapeSQLString(original))
	}
	if strings.Contains(insert, `start\\nstart`) || strings.Contains(insert, `\\n<script`) {
		t.Errorf("backup value is double-escaped (corrupted): %q", insert)
	}
}
