package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- DBCleanOption ---

func TestDBCleanOption_InvalidOptionName(t *testing.T) {
	result := DBCleanOption("testaccount", "'; DROP TABLE --", false)
	if result.Success {
		t.Error("expected failure for SQL injection option name")
	}
	if !strings.Contains(result.Message, "Invalid option name") {
		t.Errorf("unexpected message: %s", result.Message)
	}
}

func TestDBCleanOption_NoDatabase(t *testing.T) {
	// Non-existent account — no wp-config.php found.
	result := DBCleanOption("nonexistent_account_xyz_999", "test_option", false)
	if result.Success {
		t.Error("expected failure for non-existent account")
	}
	if !strings.Contains(result.Message, "No WordPress database") {
		t.Errorf("unexpected message: %s", result.Message)
	}
}

func TestDBCleanOption_PreviewMode(t *testing.T) {
	// Preview should always succeed without modifying anything.
	// On a test system without the account, this should fail gracefully.
	result := DBCleanOption("nonexistent_account_xyz_999", "test_option", true)
	// Should fail because account doesn't exist, not because of preview.
	if result.Success {
		t.Error("expected failure for non-existent account even in preview")
	}
}

// --- DBRevokeUser ---

func TestDBRevokeUser_NoDatabase(t *testing.T) {
	result := DBRevokeUser("nonexistent_account_xyz_999", 1, false, false)
	if result.Success {
		t.Error("expected failure for non-existent account")
	}
}

func TestDBRevokeUser_InvalidUserID(t *testing.T) {
	// User ID must be positive.
	result := DBRevokeUser("nonexistent_account_xyz_999", 0, false, false)
	if result.Success {
		t.Error("expected failure for user ID 0")
	}
}

func TestDBRevokeUser_Preview(t *testing.T) {
	result := DBRevokeUser("nonexistent_account_xyz_999", 1, true, true)
	if result.Success {
		t.Error("expected failure for non-existent account even in preview")
	}
}

// --- DBDeleteSpam ---

func TestDBDeleteSpam_NoDatabase(t *testing.T) {
	result := DBDeleteSpam("nonexistent_account_xyz_999", false)
	if result.Success {
		t.Error("expected failure for non-existent account")
	}
}

func TestDBDeleteSpam_Preview(t *testing.T) {
	result := DBDeleteSpam("nonexistent_account_xyz_999", true)
	if result.Success {
		t.Error("expected failure for non-existent account even in preview")
	}
}

// --- FormatDBCleanResult ---

func TestFormatDBCleanResult_Success(t *testing.T) {
	r := DBCleanResult{
		Account:  "testuser",
		Database: "testuser_wp",
		Action:   "clean-option",
		Success:  true,
		Message:  "Cleaned malicious script",
		Details:  []string{"Malicious URL: https://evil.com/x.js", "Backup saved as: csm_backup_test_123"},
	}
	output := FormatDBCleanResult(r)
	if !strings.Contains(output, "[OK]") {
		t.Error("expected [OK] in output")
	}
	if !strings.Contains(output, "clean-option") {
		t.Error("expected action in output")
	}
	if !strings.Contains(output, "testuser_wp") {
		t.Error("expected database in output")
	}
	if !strings.Contains(output, "evil.com") {
		t.Error("expected detail in output")
	}
}

func TestFormatDBCleanResult_Failure(t *testing.T) {
	r := DBCleanResult{
		Account: "testuser",
		Action:  "delete-spam",
		Success: false,
		Message: "No WordPress database found",
	}
	output := FormatDBCleanResult(r)
	if !strings.Contains(output, "[FAILED]") {
		t.Error("expected [FAILED] in output")
	}
}

func TestFormatDBCleanResult_EmptyDetails(t *testing.T) {
	r := DBCleanResult{
		Action:  "revoke-user",
		Success: true,
		Message: "Done",
	}
	output := FormatDBCleanResult(r)
	if !strings.Contains(output, "[OK]") {
		t.Error("expected [OK] in output")
	}
	// Should not contain "Database:" since it's empty.
	if strings.Contains(output, "Database:") {
		t.Error("should not show empty database")
	}
}

// --- findCredsForAccount ---

func TestFindCredsForAccount_NonExistent(t *testing.T) {
	creds, prefix := findCredsForAccount("nonexistent_account_xyz_999")
	if creds.dbName != "" {
		t.Errorf("expected empty dbName, got %q", creds.dbName)
	}
	if prefix != "" {
		t.Errorf("expected empty prefix, got %q", prefix)
	}
}

// --- Integration: option name validation through the full chain ---

func TestDBCleanOption_SQLInjectionVariants(t *testing.T) {
	injections := []string{
		"' OR 1=1 --",
		"'; DELETE FROM wp_options; --",
		"test\x00option",
		"test\noption",
		"test\roption",
		string(make([]byte, 200)), // too long
	}
	for _, name := range injections {
		result := DBCleanOption("testaccount", name, false)
		if result.Success {
			t.Errorf("SQL injection should fail: %q", name)
		}
	}
}

// --- resolveTablePrefix ---

func TestResolveTablePrefix_Cases(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"", "wp_", true},
		{"wp_", "wp_", true},
		{"my_prefix_", "my_prefix_", true},
		{"site42_", "site42_", true},
		{"wp_; DROP TABLE wp_users; --", "", false},
		{"wp_'; SELECT", "", false},
		{"wp_`; DROP", "", false},
		{"a b", "", false},
		{"a-b", "", false},
		{"a.b", "", false},
		{"a/b", "", false},
		{"--", "", false},
		{"' OR '1'='1", "", false},
	}
	for _, c := range cases {
		got, ok := resolveTablePrefix(wpDBCreds{tablePrefix: c.in})
		if got != c.want || ok != c.wantOK {
			t.Errorf("resolveTablePrefix(%q) = (%q, %v), want (%q, %v)",
				c.in, got, ok, c.want, c.wantOK)
		}
	}
}

// findCredsForAccount must refuse a wp-config whose $table_prefix is
// attacker-controlled. DBCleanOption, DBRevokeUser, and DBDeleteSpam
// concatenate the parsed prefix into root MySQL statements.
func TestFindCredsForAccount_RejectsMaliciousPrefix(t *testing.T) {
	body := `<?php
define( 'DB_NAME', 'attacker_wp' );
define( 'DB_USER', 'wpuser' );
define( 'DB_PASSWORD', 'x' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_; DROP TABLE wp_users; --';
`
	opened := false
	m := &mockOS{
		glob: func(string) ([]string, error) { return nil, nil },
		open: func(path string) (*os.File, error) {
			if path != "/home/attacker/public_html/wp-config.php" {
				return nil, os.ErrNotExist
			}
			opened = true
			f, err := os.CreateTemp(t.TempDir(), "wpconfig")
			if err != nil {
				return nil, err
			}
			if _, err := f.WriteString(body); err != nil {
				_ = f.Close()
				return nil, err
			}
			if _, err := f.Seek(0, 0); err != nil {
				_ = f.Close()
				return nil, err
			}
			return f, nil
		},
	}
	withMockOS(t, m)
	creds, prefix := findCredsForAccount("attacker")
	if !opened {
		t.Fatal("findCredsForAccount did not read the account's primary wp-config")
	}
	if creds.dbName != "" || prefix != "" {
		t.Fatalf("findCredsForAccount must reject malicious prefix; got dbName=%q prefix=%q",
			creds.dbName, prefix)
	}
}

// Same root cause via the auto-response credential helper.
func TestFindCredsForDB_RejectsMaliciousPrefix(t *testing.T) {
	dir := t.TempDir()
	wpConfig := filepath.Join(dir, "wp-config.php")
	body := []byte(`<?php
define( 'DB_NAME', 'attacker_wp' );
define( 'DB_USER', 'wpuser' );
define( 'DB_PASSWORD', 'x' );
define( 'DB_HOST', 'localhost' );
$table_prefix = "wp_'; DROP TABLE wp_users; --";
`)
	if err := os.WriteFile(wpConfig, body, 0o600); err != nil {
		t.Fatal(err)
	}
	m := &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.HasSuffix(pattern, "/public_html/wp-config.php") {
				return []string{wpConfig}, nil
			}
			return nil, nil
		},
		open: os.Open,
	}
	withMockOS(t, m)
	creds := findCredsForDB("attacker_wp")
	if creds.dbName != "" {
		t.Fatalf("findCredsForDB must reject malicious prefix; got dbName=%q", creds.dbName)
	}
}

func TestDatabaseScanners_RejectMaliciousPrefixBeforeQuery(t *testing.T) {
	wpConfig := `<?php
define( 'DB_NAME', 'attacker_wp' );
define( 'DB_USER', 'wpuser' );
define( 'DB_PASSWORD', 'x' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_; DROP TABLE wp_users; --';
`
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			switch pattern {
			case "/home/*/public_html/wp-config.php",
				"/home/attacker/*/wp-config.php",
				"/home/attacker/public_html/wp-config.php":
				return []string{"/home/attacker/public_html/wp-config.php"}, nil
			default:
				return nil, nil
			}
		},
		open: func(name string) (*os.File, error) {
			if !strings.HasSuffix(name, "wp-config.php") {
				return nil, os.ErrNotExist
			}
			f, err := os.CreateTemp(t.TempDir(), "wpconfig")
			if err != nil {
				return nil, err
			}
			if _, err := f.WriteString(wpConfig); err != nil {
				_ = f.Close()
				return nil, err
			}
			if _, err := f.Seek(0, 0); err != nil {
				_ = f.Close()
				return nil, err
			}
			return f, nil
		},
	})

	mysqlCalls := 0
	withMockCmd(t, &mockCmd{
		runWithEnv: func(string, []string, ...string) ([]byte, error) {
			mysqlCalls++
			return nil, nil
		},
	})

	findings := CheckDatabaseContent(context.Background(), nil, nil)
	if len(findings) != 0 {
		t.Fatalf("CheckDatabaseContent returned findings for rejected prefix: %v", findings)
	}
	if got := CleanDatabaseSpam("attacker"); len(got) != 0 {
		t.Fatalf("CleanDatabaseSpam returned findings for rejected prefix: %v", got)
	}
	if mysqlCalls != 0 {
		t.Fatalf("malicious table prefix reached MySQL query path %d times", mysqlCalls)
	}
}
