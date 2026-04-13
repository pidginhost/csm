package checks

import (
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
