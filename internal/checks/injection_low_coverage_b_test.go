package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// wpConfigFixture creates a mock that resolves a WP config for an account.
// Returns the mockOS to use with withMockOS.
func wpConfigFixture(t *testing.T, account, wpConfigContent string) *mockOS {
	t.Helper()
	return &mockOS{
		glob: func(pattern string) ([]string, error) {
			primary := fmt.Sprintf("/home/%s/public_html/wp-config.php", account)
			if pattern == primary {
				return []string{primary}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				f, err := os.CreateTemp(t.TempDir(), "wpconfig")
				if err != nil {
					return nil, err
				}
				_, _ = f.WriteString(wpConfigContent)
				_, _ = f.Seek(0, 0)
				return f, nil
			}
			return nil, os.ErrNotExist
		},
	}
}

// ---------------------------------------------------------------------------
// db_clean.go — DBCleanOption with mocked WP config + MySQL
// readOptionValue uses runMySQLQuery -> runCmdWithEnv (mockCmd.runWithEnv)
// ---------------------------------------------------------------------------

func TestDBCleanOption_FoundButNoMaliciousURL(t *testing.T) {
	wpCfg := `<?php
define( 'DB_NAME', 'testdb' );
define( 'DB_USER', 'testuser' );
define( 'DB_PASSWORD', 'testpass' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
`
	withMockOS(t, wpConfigFixture(t, "acmeuser", wpCfg))

	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			if name == "mysql" {
				for _, a := range args {
					if strings.Contains(a, "SELECT option_value") {
						return []byte("just some safe html content\n"), nil
					}
				}
			}
			return nil, nil
		},
	})

	result := DBCleanOption("acmeuser", "blogdescription", false)
	if result.Success {
		t.Error("should not succeed when no malicious URL found")
	}
	if !strings.Contains(result.Message, "No malicious external script") {
		t.Errorf("unexpected message: %s", result.Message)
	}
}

func TestDBCleanOption_EmptyOptionValue(t *testing.T) {
	wpCfg := `<?php
define( 'DB_NAME', 'emptydb' );
define( 'DB_USER', 'u' );
define( 'DB_PASSWORD', 'p' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
`
	withMockOS(t, wpConfigFixture(t, "emptyuser", wpCfg))

	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			return []byte(""), nil
		},
	})

	result := DBCleanOption("emptyuser", "test_option", false)
	if result.Success {
		t.Error("should not succeed when option is empty")
	}
	if !strings.Contains(result.Message, "not found or empty") {
		t.Errorf("unexpected message: %s", result.Message)
	}
}

func TestDBCleanOption_ContentUnchangedAfterCleaning(t *testing.T) {
	wpCfg := `<?php
define( 'DB_NAME', 'unchanged_db' );
define( 'DB_USER', 'u' );
define( 'DB_PASSWORD', 'p' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
`
	// Content has a script src from a non-safe domain BUT no closing </script>,
	// so removeMaliciousScripts won't strip it.
	contentValue := `<script src="https://evil.top/x.js" async>`

	withMockOS(t, wpConfigFixture(t, "unch", wpCfg))

	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			if name == "mysql" {
				for _, a := range args {
					if strings.Contains(a, "SELECT option_value") {
						return []byte(contentValue + "\n"), nil
					}
				}
			}
			return nil, nil
		},
	})

	result := DBCleanOption("unch", "some_option", false)
	if result.Success {
		t.Error("should report unchanged content")
	}
	if !strings.Contains(result.Message, "Content unchanged") {
		t.Errorf("unexpected message: %s", result.Message)
	}
}

func TestDBCleanOption_PreviewWithMalicious(t *testing.T) {
	wpCfg := `<?php
define( 'DB_NAME', 'prevdb' );
define( 'DB_USER', 'u' );
define( 'DB_PASSWORD', 'p' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
`
	maliciousContent := `<script src="https://evil.top/x.js"></script>`

	withMockOS(t, wpConfigFixture(t, "prevuser", wpCfg))

	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			if name == "mysql" {
				for _, a := range args {
					if strings.Contains(a, "SELECT option_value") {
						return []byte(maliciousContent + "\n"), nil
					}
				}
			}
			return nil, nil
		},
	})

	result := DBCleanOption("prevuser", "widget_text", true)
	if !result.Success {
		t.Errorf("preview should succeed, got: %s", result.Message)
	}
	if !strings.Contains(result.Message, "PREVIEW") {
		t.Errorf("expected PREVIEW in message, got: %s", result.Message)
	}
}

func TestDBCleanOption_FullCleanWithBackup(t *testing.T) {
	wpCfg := `<?php
define( 'DB_NAME', 'cleandb' );
define( 'DB_USER', 'u' );
define( 'DB_PASSWORD', 'p' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
`
	maliciousContent := `stuff <script src="https://evil.top/x.js"></script> more`

	withMockOS(t, wpConfigFixture(t, "cleanuser", wpCfg))

	var sawInsert, sawUpdate bool
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			if name == "mysql" {
				for _, a := range args {
					if strings.Contains(a, "SELECT option_value") {
						return []byte(maliciousContent + "\n"), nil
					}
					if strings.Contains(a, "INSERT INTO") {
						sawInsert = true
					}
					if strings.Contains(a, "UPDATE") && strings.Contains(a, "option_value") {
						sawUpdate = true
					}
				}
			}
			return nil, nil
		},
	})

	result := DBCleanOption("cleanuser", "widget_text", false)
	if !result.Success {
		t.Errorf("full clean should succeed, got: %s", result.Message)
	}
	if !strings.Contains(result.Message, "Cleaned malicious script") {
		t.Errorf("unexpected message: %s", result.Message)
	}
	if !sawInsert {
		t.Error("expected INSERT for backup")
	}
	if !sawUpdate {
		t.Error("expected UPDATE for cleaned value")
	}
	if len(result.BackupNames) == 0 {
		t.Error("expected backup name in result")
	}
}

// ---------------------------------------------------------------------------
// db_clean.go — DBRevokeUser (uses runMySQLQueryRoot -> cmdExec.Run)
// ---------------------------------------------------------------------------

func TestDBRevokeUser_UserExistsPreview(t *testing.T) {
	wpCfg := `<?php
define( 'DB_NAME', 'revokedb' );
define( 'DB_USER', 'u' );
define( 'DB_PASSWORD', 'p' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
`
	withMockOS(t, wpConfigFixture(t, "revuser", wpCfg))

	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "mysql" {
				for _, a := range args {
					if strings.Contains(a, "SELECT user_login") {
						return []byte("admin\tadmin@example.com\n"), nil
					}
					if strings.Contains(a, "session_tokens") {
						return []byte(`a:1:{s:10:"expiration";i:99999;}` + "\n"), nil
					}
				}
			}
			return nil, nil
		},
	})

	result := DBRevokeUser("revuser", 1, true, true)
	if !result.Success {
		t.Errorf("preview should succeed, got: %s", result.Message)
	}
	if !strings.Contains(result.Message, "PREVIEW") {
		t.Errorf("expected PREVIEW, got: %s", result.Message)
	}
	if !strings.Contains(result.Message, "demote to subscriber") {
		t.Errorf("expected demote mention, got: %s", result.Message)
	}
}

func TestDBRevokeUser_UserNotFound(t *testing.T) {
	wpCfg := `<?php
define( 'DB_NAME', 'revokedb2' );
define( 'DB_USER', 'u' );
define( 'DB_PASSWORD', 'p' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
`
	withMockOS(t, wpConfigFixture(t, "revuser2", wpCfg))

	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return []byte(""), nil
		},
	})

	result := DBRevokeUser("revuser2", 999, false, false)
	if result.Success {
		t.Error("should fail when user not found")
	}
	if !strings.Contains(result.Message, "User ID 999 not found") {
		t.Errorf("unexpected message: %s", result.Message)
	}
}

func TestDBRevokeUser_RevokeAndDemote(t *testing.T) {
	wpCfg := `<?php
define( 'DB_NAME', 'demotedb' );
define( 'DB_USER', 'u' );
define( 'DB_PASSWORD', 'p' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
`
	withMockOS(t, wpConfigFixture(t, "demuser", wpCfg))

	var queries []string
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "mysql" {
				for _, a := range args {
					if strings.Contains(a, "SELECT user_login") {
						return []byte("hacker\thacker@evil.com\n"), nil
					}
					if strings.Contains(a, "SELECT LEFT(meta_value") {
						return []byte(`a:1:{s:10:"expiration";i:9999;}` + "\n"), nil
					}
					if strings.Contains(a, "UPDATE") && strings.Contains(a, "session_tokens") {
						queries = append(queries, a)
						return nil, nil
					}
					if strings.Contains(a, "SELECT meta_key") && strings.Contains(a, "capabilities") {
						return []byte("wp_capabilities\n"), nil
					}
					if strings.Contains(a, "UPDATE") && strings.Contains(a, "subscriber") {
						queries = append(queries, a)
						return nil, nil
					}
				}
			}
			return nil, nil
		},
	})

	result := DBRevokeUser("demuser", 5, true, false)
	if !result.Success {
		t.Errorf("should succeed, got: %s", result.Message)
	}
	if !strings.Contains(result.Message, "Revoked sessions") {
		t.Errorf("expected 'Revoked sessions', got: %s", result.Message)
	}

	foundDemote := false
	for _, d := range result.Details {
		if strings.Contains(d, "Demoted to subscriber") {
			foundDemote = true
		}
	}
	if !foundDemote {
		t.Errorf("expected demotion detail, details: %v", result.Details)
	}
}

func TestDBRevokeUser_RevokeNoDemote(t *testing.T) {
	wpCfg := `<?php
define( 'DB_NAME', 'nodemotedb' );
define( 'DB_USER', 'u' );
define( 'DB_PASSWORD', 'p' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
`
	withMockOS(t, wpConfigFixture(t, "nodemuser", wpCfg))

	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "mysql" {
				for _, a := range args {
					if strings.Contains(a, "SELECT user_login") {
						return []byte("bob\tbob@test.com\n"), nil
					}
					if strings.Contains(a, "session_tokens") {
						return []byte("\n"), nil
					}
				}
			}
			return nil, nil
		},
	})

	result := DBRevokeUser("nodemuser", 2, false, false)
	if !result.Success {
		t.Errorf("should succeed, got: %s", result.Message)
	}
	for _, d := range result.Details {
		if strings.Contains(d, "Demoted") {
			t.Error("should not demote when demote=false")
		}
	}
}

func TestDBRevokeUser_UserEmailOnlyLogin(t *testing.T) {
	wpCfg := `<?php
define( 'DB_NAME', 'emaildb' );
define( 'DB_USER', 'u' );
define( 'DB_PASSWORD', 'p' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
`
	withMockOS(t, wpConfigFixture(t, "emailusr", wpCfg))

	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "mysql" {
				for _, a := range args {
					if strings.Contains(a, "SELECT user_login") {
						// No tab separator -- only login, no email.
						return []byte("loginonly\n"), nil
					}
					if strings.Contains(a, "session_tokens") {
						return []byte("\n"), nil
					}
				}
			}
			return nil, nil
		},
	})

	result := DBRevokeUser("emailusr", 3, false, false)
	if !result.Success {
		t.Errorf("should succeed, got: %s", result.Message)
	}
}

// ---------------------------------------------------------------------------
// db_clean.go — DBDeleteSpam
// ---------------------------------------------------------------------------

func TestDBDeleteSpam_NoSpamFound(t *testing.T) {
	wpCfg := `<?php
define( 'DB_NAME', 'spamdb' );
define( 'DB_USER', 'u' );
define( 'DB_PASSWORD', 'p' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
`
	withMockOS(t, wpConfigFixture(t, "spamuser", wpCfg))

	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "mysql" {
				for _, a := range args {
					if strings.Contains(a, "COUNT(*)") {
						return []byte("0\n"), nil
					}
				}
			}
			return nil, nil
		},
	})

	result := DBDeleteSpam("spamuser", false)
	if !result.Success {
		t.Errorf("no spam should be a success, got: %s", result.Message)
	}
	if !strings.Contains(result.Message, "No spam posts") {
		t.Errorf("unexpected message: %s", result.Message)
	}
}

func TestDBDeleteSpam_PreviewWithSpam(t *testing.T) {
	wpCfg := `<?php
define( 'DB_NAME', 'spamdb2' );
define( 'DB_USER', 'u' );
define( 'DB_PASSWORD', 'p' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
`
	withMockOS(t, wpConfigFixture(t, "spu", wpCfg))

	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "mysql" {
				for _, a := range args {
					if strings.Contains(a, "COUNT(*)") && strings.Contains(a, "casino") {
						return []byte("15\n"), nil
					}
					if strings.Contains(a, "COUNT(*)") && strings.Contains(a, "viagra") {
						return []byte("5\n"), nil
					}
					if strings.Contains(a, "COUNT(*)") {
						return []byte("0\n"), nil
					}
				}
			}
			return nil, nil
		},
	})

	result := DBDeleteSpam("spu", true)
	if !result.Success {
		t.Errorf("preview should succeed, got: %s", result.Message)
	}
	if !strings.Contains(result.Message, "PREVIEW") {
		t.Errorf("expected PREVIEW, got: %s", result.Message)
	}
}

func TestDBDeleteSpam_DeleteWithBatching(t *testing.T) {
	wpCfg := `<?php
define( 'DB_NAME', 'spamdeldb' );
define( 'DB_USER', 'u' );
define( 'DB_PASSWORD', 'p' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
`
	withMockOS(t, wpConfigFixture(t, "deluser", wpCfg))

	var deleteQueries []string
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "mysql" {
				for _, a := range args {
					if strings.Contains(a, "COUNT(*)") && strings.Contains(a, "cialis") {
						return []byte("3\n"), nil
					}
					if strings.Contains(a, "COUNT(*)") {
						return []byte("0\n"), nil
					}
					if strings.Contains(a, "SELECT ID") && strings.Contains(a, "cialis") {
						return []byte("101\n102\n103\n"), nil
					}
					if strings.Contains(a, "DELETE") {
						deleteQueries = append(deleteQueries, a)
						return nil, nil
					}
				}
			}
			return nil, nil
		},
	})

	result := DBDeleteSpam("deluser", false)
	if !result.Success {
		t.Errorf("delete should succeed, got: %s", result.Message)
	}
	if !strings.Contains(result.Message, "Deleted") {
		t.Errorf("expected 'Deleted' in message, got: %s", result.Message)
	}
	if len(deleteQueries) < 3 {
		t.Errorf("expected >= 3 DELETE queries (postmeta, revisions, posts), got %d", len(deleteQueries))
	}
}

func TestDBDeleteSpam_NonNumericIDs(t *testing.T) {
	wpCfg := `<?php
define( 'DB_NAME', 'nonnumdb' );
define( 'DB_USER', 'u' );
define( 'DB_PASSWORD', 'p' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
`
	withMockOS(t, wpConfigFixture(t, "nnuser", wpCfg))

	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "mysql" {
				for _, a := range args {
					if strings.Contains(a, "COUNT(*)") && strings.Contains(a, "casino") {
						return []byte("2\n"), nil
					}
					if strings.Contains(a, "COUNT(*)") {
						return []byte("0\n"), nil
					}
					if strings.Contains(a, "SELECT ID") {
						return []byte("NOTANUMBER\nALSOBAD\n"), nil
					}
				}
			}
			return nil, nil
		},
	})

	result := DBDeleteSpam("nnuser", false)
	if !result.Success {
		t.Errorf("should succeed even with 0 deletions, got: %s", result.Message)
	}
}

// ---------------------------------------------------------------------------
// db_clean.go — runMySQLQueryRoot
// ---------------------------------------------------------------------------

func TestRunMySQLQueryRoot_CmdError(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return nil, fmt.Errorf("connection refused")
		},
	})
	lines := runMySQLQueryRoot("testdb", "SELECT 1")
	if lines != nil {
		t.Errorf("expected nil on error, got %v", lines)
	}
}

func TestRunMySQLQueryRoot_NilOutput(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return nil, nil
		},
	})
	lines := runMySQLQueryRoot("testdb", "SELECT 1")
	if lines != nil {
		t.Errorf("expected nil for nil output, got %v", lines)
	}
}

func TestRunMySQLQueryRoot_MultiLine(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return []byte("row1\nrow2\n\nrow3\n"), nil
		},
	})
	lines := runMySQLQueryRoot("testdb", "SELECT col FROM tbl")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != "row1" || lines[1] != "row2" || lines[2] != "row3" {
		t.Errorf("unexpected lines: %v", lines)
	}
}

func TestRunMySQLQueryRoot_PassesCorrectArgs(t *testing.T) {
	var gotName string
	var gotArgs []string
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			gotName = name
			gotArgs = args
			return []byte("ok\n"), nil
		},
	})
	runMySQLQueryRoot("mydb", "SELECT 1")
	if gotName != "mysql" {
		t.Errorf("expected mysql command, got %q", gotName)
	}
	if len(gotArgs) < 5 {
		t.Fatalf("expected >= 5 args, got %v", gotArgs)
	}
	if gotArgs[0] != "-N" || gotArgs[1] != "-B" {
		t.Errorf("expected -N -B flags, got %v", gotArgs[:2])
	}
	if gotArgs[2] != "mydb" {
		t.Errorf("expected dbName=mydb, got %q", gotArgs[2])
	}
}

// ---------------------------------------------------------------------------
// db_clean.go — findCredsForAccount with addon domains
// ---------------------------------------------------------------------------

func TestFindCredsForAccount_AddonDomain(t *testing.T) {
	wpCfg := `<?php
define( 'DB_NAME', 'addondb' );
define( 'DB_USER', 'addonuser' );
define( 'DB_PASSWORD', 'p' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'mywp_';
`
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "public_html/wp-config.php") {
				return nil, nil // Primary doesn't have WP.
			}
			if strings.Contains(pattern, "/home/addonacct/*/wp-config.php") {
				return []string{"/home/addonacct/addon.com/wp-config.php"}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				f, err := os.CreateTemp(t.TempDir(), "wpconfig")
				if err != nil {
					return nil, err
				}
				_, _ = f.WriteString(wpCfg)
				_, _ = f.Seek(0, 0)
				return f, nil
			}
			return nil, os.ErrNotExist
		},
	})

	creds, prefix := findCredsForAccount("addonacct")
	if creds.dbName != "addondb" {
		t.Errorf("dbName = %q, want addondb", creds.dbName)
	}
	if prefix != "mywp_" {
		t.Errorf("prefix = %q, want mywp_", prefix)
	}
	if creds.dbUser != "" {
		t.Errorf("dbUser should be empty for root auth, got %q", creds.dbUser)
	}
}

func TestFindCredsForAccount_DefaultPrefix(t *testing.T) {
	wpCfg := `<?php
define( 'DB_NAME', 'defprefixdb' );
define( 'DB_USER', 'u' );
define( 'DB_PASSWORD', 'p' );
define( 'DB_HOST', 'localhost' );
`
	withMockOS(t, wpConfigFixture(t, "defuser", wpCfg))

	creds, prefix := findCredsForAccount("defuser")
	if creds.dbName != "defprefixdb" {
		t.Errorf("dbName = %q, want defprefixdb", creds.dbName)
	}
	if prefix != "wp_" {
		t.Errorf("prefix = %q, want wp_ (default)", prefix)
	}
}

// ---------------------------------------------------------------------------
// db_autoresponse.go — handleMaliciousOption
// ---------------------------------------------------------------------------

func TestHandleMaliciousOption_SkipsCSMBackupOption(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.CleanDatabase = true

	f := alert.Finding{
		Check:   "db_options_injection",
		Details: "Database: testdb\nOption: csm_backup_siteurl_1234567890",
	}
	actions := handleMaliciousOption(cfg, f)
	if len(actions) != 0 {
		t.Errorf("should skip csm_backup_ options, got %d actions", len(actions))
	}
}

func TestHandleMaliciousOption_EmptyDBName(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.CleanDatabase = true

	f := alert.Finding{
		Check:   "db_options_injection",
		Details: "Option: siteurl",
	}
	actions := handleMaliciousOption(cfg, f)
	if len(actions) != 0 {
		t.Errorf("should return nil for empty DB, got %d actions", len(actions))
	}
}

func TestHandleMaliciousOption_InvalidOptionInDetails(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.CleanDatabase = true

	f := alert.Finding{
		Check:   "db_options_injection",
		Details: "Database: testdb\nOption: '; DROP TABLE;",
	}
	actions := handleMaliciousOption(cfg, f)
	if len(actions) != 0 {
		t.Errorf("should skip invalid option name, got %d actions", len(actions))
	}
}

func TestHandleMaliciousOption_NoCredsForDB(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.CleanDatabase = true

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
	})

	f := alert.Finding{
		Check:   "db_options_injection",
		Details: "Database: nonexistent_db\nOption: siteurl",
	}
	actions := handleMaliciousOption(cfg, f)
	if len(actions) != 0 {
		t.Errorf("should return nil for missing creds, got %d actions", len(actions))
	}
}

func TestHandleMaliciousOption_NoMaliciousURL(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.CleanDatabase = true

	wpCfg := `<?php
define( 'DB_NAME', 'cleandb' );
define( 'DB_USER', 'u' );
define( 'DB_PASSWORD', 'p' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
`
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "public_html/wp-config.php") {
				return []string{"/home/user1/public_html/wp-config.php"}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				f, err := os.CreateTemp(t.TempDir(), "wpconfig")
				if err != nil {
					return nil, err
				}
				_, _ = f.WriteString(wpCfg)
				_, _ = f.Seek(0, 0)
				return f, nil
			}
			return nil, os.ErrNotExist
		},
	})

	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			if name == "mysql" {
				for _, a := range args {
					if strings.Contains(a, "SELECT option_value") {
						return []byte("safe content no scripts\n"), nil
					}
				}
			}
			return nil, nil
		},
	})

	f := alert.Finding{
		Check:   "db_options_injection",
		Details: "Database: cleandb\nOption: blogname",
	}
	actions := handleMaliciousOption(cfg, f)
	if len(actions) != 0 {
		t.Errorf("should return nil when no malicious URL, got %d actions", len(actions))
	}
}

// ---------------------------------------------------------------------------
// db_autoresponse.go — handleSiteurlHijack
// ---------------------------------------------------------------------------

func TestHandleSiteurlHijack_EmptyDB(t *testing.T) {
	cfg := &config.Config{}
	f := alert.Finding{
		Check:   "db_siteurl_hijack",
		Details: "Something without DB line",
	}
	actions := handleSiteurlHijack(cfg, f)
	if len(actions) != 0 {
		t.Errorf("should return nil for empty DB, got %d actions", len(actions))
	}
}

func TestHandleSiteurlHijack_NoCreds(t *testing.T) {
	cfg := &config.Config{}
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
	})
	f := alert.Finding{
		Check:   "db_siteurl_hijack",
		Details: "Database: nosuchdb\nSiteURL changed to phishing",
	}
	actions := handleSiteurlHijack(cfg, f)
	if len(actions) != 0 {
		t.Errorf("should return nil when no creds found, got %d actions", len(actions))
	}
}

// ---------------------------------------------------------------------------
// db_autoresponse.go — extractSuspiciousSessionIPs
// ---------------------------------------------------------------------------

func TestExtractSuspiciousSessionIPs_FiltersPrivateAndInfra(t *testing.T) {
	sessionData := `"ip";s:13:"192.168.1.100"` + "\t" +
		`"ip";s:9:"127.0.0.1"` + "\t" +
		`"ip";s:11:"10.0.0.1"` + "\t" +
		`"ip";s:14:"203.0.113.50"` + "\t" +
		`"ip";s:14:"198.51.100.42"`

	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			if name == "mysql" {
				for _, a := range args {
					if strings.Contains(a, "session_tokens") {
						return []byte(sessionData + "\n"), nil
					}
				}
			}
			return nil, nil
		},
	})

	creds := wpDBCreds{dbName: "sessdb", dbUser: "u", dbPass: "p", dbHost: "localhost", tablePrefix: "wp_"}
	infraIPs := []string{"198.51.100.42"}
	ips := extractSuspiciousSessionIPs(creds, "wp_", infraIPs)

	if len(ips) != 1 {
		t.Fatalf("expected 1 suspicious IP, got %d: %v", len(ips), ips)
	}
	if ips[0] != "203.0.113.50" {
		t.Errorf("expected 203.0.113.50, got %s", ips[0])
	}
}

func TestExtractSuspiciousSessionIPs_EmptyResults(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			return []byte(""), nil
		},
	})
	creds := wpDBCreds{dbName: "db", dbUser: "u", dbPass: "p", dbHost: "localhost"}
	ips := extractSuspiciousSessionIPs(creds, "wp_", nil)
	if len(ips) != 0 {
		t.Errorf("expected 0, got %v", ips)
	}
}

func TestExtractSuspiciousSessionIPs_DeduplicatesIPs(t *testing.T) {
	sessionData := `"ip";s:14:"203.0.113.50"` + "\n" + `"ip";s:14:"203.0.113.50"`

	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			return []byte(sessionData + "\n"), nil
		},
	})
	creds := wpDBCreds{dbName: "db", dbUser: "u", dbPass: "p", dbHost: "localhost"}
	ips := extractSuspiciousSessionIPs(creds, "wp_", nil)
	if len(ips) != 1 {
		t.Errorf("should deduplicate, got %d: %v", len(ips), ips)
	}
}

// ---------------------------------------------------------------------------
// db_autoresponse.go — revokeCompromisedSessions
// ---------------------------------------------------------------------------

func TestRevokeCompromisedSessions_OnlySuspicious(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			if name == "mysql" {
				for _, a := range args {
					if strings.Contains(a, "SELECT user_id") {
						return []byte("1\t" + `"ip";s:14:"203.0.113.50"` + "\n" +
							"2\t" + `"ip";s:13:"192.168.1.100"` + "\n"), nil
					}
				}
			}
			return nil, nil
		},
	})
	creds := wpDBCreds{dbName: "revdb", dbUser: "u", dbPass: "p", dbHost: "localhost"}
	revoked := revokeCompromisedSessions(creds, "wp_", nil)
	if revoked != 1 {
		t.Errorf("expected 1 revoked, got %d", revoked)
	}
}

func TestRevokeCompromisedSessions_NoSuspicious(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			return []byte("1\t" + `"ip";s:13:"192.168.1.100"` + "\n"), nil
		},
	})
	creds := wpDBCreds{dbName: "revdb2", dbUser: "u", dbPass: "p", dbHost: "localhost"}
	revoked := revokeCompromisedSessions(creds, "wp_", nil)
	if revoked != 0 {
		t.Errorf("expected 0, got %d", revoked)
	}
}

func TestRevokeCompromisedSessions_MalformedLine(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			return []byte("notabbed\n"), nil
		},
	})
	creds := wpDBCreds{dbName: "revdb3", dbUser: "u", dbPass: "p", dbHost: "localhost"}
	revoked := revokeCompromisedSessions(creds, "wp_", nil)
	if revoked != 0 {
		t.Errorf("expected 0, got %d", revoked)
	}
}

// ---------------------------------------------------------------------------
// db_autoresponse.go — backupAndCleanOption
// ---------------------------------------------------------------------------

func TestBackupAndCleanOption_NoChange(t *testing.T) {
	creds := wpDBCreds{dbName: "db1", dbUser: "u", dbPass: "p", dbHost: "localhost"}
	cleaned := backupAndCleanOption(creds, "wp_", "opt", "safe content", "")
	if cleaned {
		t.Error("should return false when content is unchanged")
	}
}

func TestBackupAndCleanOption_SuccessfulClean(t *testing.T) {
	var insertSeen, updateSeen bool
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			if name == "mysql" {
				for _, a := range args {
					if strings.Contains(a, "INSERT INTO") {
						insertSeen = true
					}
					if strings.Contains(a, "UPDATE") && strings.Contains(a, "option_value") {
						updateSeen = true
					}
				}
			}
			return nil, nil
		},
	})
	creds := wpDBCreds{dbName: "db2", dbUser: "u", dbPass: "p", dbHost: "localhost"}
	original := `stuff <script src="https://evil.top/x.js"></script> more`
	cleaned := backupAndCleanOption(creds, "wp_", "widget_text", original, "https://evil.top/x.js")
	if !cleaned {
		t.Error("should return true")
	}
	if !insertSeen {
		t.Error("expected INSERT for backup")
	}
	if !updateSeen {
		t.Error("expected UPDATE for cleaned value")
	}
}

// ---------------------------------------------------------------------------
// db_autoresponse.go — findCredsForDB
// ---------------------------------------------------------------------------

func TestFindCredsForDB_FoundInAddon(t *testing.T) {
	wpCfg := `<?php
define( 'DB_NAME', 'target_db' );
define( 'DB_USER', 'u' );
define( 'DB_PASSWORD', 'p' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
`
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "public_html/wp-config.php") {
				return nil, nil
			}
			if strings.Contains(pattern, "/home/*/*/wp-config.php") {
				return []string{"/home/user1/addon.com/wp-config.php"}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				f, err := os.CreateTemp(t.TempDir(), "wpconfig")
				if err != nil {
					return nil, err
				}
				_, _ = f.WriteString(wpCfg)
				_, _ = f.Seek(0, 0)
				return f, nil
			}
			return nil, os.ErrNotExist
		},
	})

	creds := findCredsForDB("target_db")
	if creds.dbName != "target_db" {
		t.Errorf("dbName = %q, want target_db", creds.dbName)
	}
}

func TestFindCredsForDB_NotFound(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
	})
	creds := findCredsForDB("no_such_db")
	if creds.dbName != "" {
		t.Errorf("expected empty creds, got dbName=%q", creds.dbName)
	}
}

// ---------------------------------------------------------------------------
// db_autoresponse.go — readOptionValue
// ---------------------------------------------------------------------------

func TestReadOptionValue_InvalidName(t *testing.T) {
	creds := wpDBCreds{dbName: "db", dbUser: "u", dbPass: "p", dbHost: "localhost"}
	val := readOptionValue(creds, "wp_", "'; DROP TABLE --")
	if val != "" {
		t.Errorf("expected empty for invalid name, got %q", val)
	}
}

func TestReadOptionValue_EmptyResult(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			return []byte(""), nil
		},
	})
	creds := wpDBCreds{dbName: "db", dbUser: "u", dbPass: "p", dbHost: "localhost"}
	val := readOptionValue(creds, "wp_", "blogname")
	if val != "" {
		t.Errorf("expected empty, got %q", val)
	}
}

// ---------------------------------------------------------------------------
// remediate.go — sanitizeFixPath
// ---------------------------------------------------------------------------

func TestSanitizeFixPath_EmptyPath(t *testing.T) {
	_, err := sanitizeFixPath("", []string{"/home"})
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestSanitizeFixPath_RelativePath(t *testing.T) {
	_, err := sanitizeFixPath("relative/path.php", []string{"/home"})
	if err == nil {
		t.Error("expected error for relative path")
	}
}

func TestSanitizeFixPath_OutsideAllowedRoot(t *testing.T) {
	_, err := sanitizeFixPath("/etc/passwd", []string{"/home", "/tmp"})
	if err == nil {
		t.Error("expected error for path outside allowed roots")
	}
	if !strings.Contains(err.Error(), "outside the allowed") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestSanitizeFixPath_ValidHome(t *testing.T) {
	path, err := sanitizeFixPath("/home/alice/public_html/evil.php", []string{"/home"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "/home/alice/public_html/evil.php" {
		t.Errorf("path = %q", path)
	}
}

func TestSanitizeFixPath_ValidTmp(t *testing.T) {
	path, err := sanitizeFixPath("/tmp/miner", []string{"/home", "/tmp"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "/tmp/miner" {
		t.Errorf("path = %q", path)
	}
}

func TestSanitizeFixPath_TraversalCleaned(t *testing.T) {
	path, err := sanitizeFixPath("/home/alice/../bob/file.php", []string{"/home"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "/home/bob/file.php" {
		t.Errorf("path = %q", path)
	}
}

// ---------------------------------------------------------------------------
// remediate.go — isPathWithinOrEqual
// ---------------------------------------------------------------------------

func TestIsPathWithinOrEqual_Equal(t *testing.T) {
	if !isPathWithinOrEqual("/home", "/home") {
		t.Error("equal paths should match")
	}
}

func TestIsPathWithinOrEqual_Within(t *testing.T) {
	if !isPathWithinOrEqual("/home/alice/file", "/home") {
		t.Error("child path should be within base")
	}
}

func TestIsPathWithinOrEqual_Outside(t *testing.T) {
	if isPathWithinOrEqual("/etc/passwd", "/home") {
		t.Error("outside path should not match")
	}
}

func TestIsPathWithinOrEqual_PartialPrefix(t *testing.T) {
	if isPathWithinOrEqual("/homeextra/file", "/home") {
		t.Error("partial prefix should not match")
	}
}

// ---------------------------------------------------------------------------
// remediate.go — ApplyFix edge cases
// ---------------------------------------------------------------------------

func TestApplyFix_UnknownCheckType(t *testing.T) {
	result := ApplyFix("unknown_check_type", "msg", "details")
	if result.Success {
		t.Error("unknown check should not succeed")
	}
	if !strings.Contains(result.Error, "no automated fix available") {
		t.Errorf("wrong error: %s", result.Error)
	}
}

func TestApplyFix_WorldWritableEmptyPath(t *testing.T) {
	result := ApplyFix("world_writable_php", "no path here", "")
	if result.Success {
		t.Error("should fail with no path")
	}
	if !strings.Contains(result.Error, "could not extract file path") {
		t.Errorf("wrong error: %s", result.Error)
	}
}

func TestApplyFix_HtaccessNonHtaccessFile(t *testing.T) {
	result := ApplyFix("htaccess_injection", "", "", "/home/alice/public_html/index.php")
	if result.Success {
		t.Error("should fail for non-.htaccess file")
	}
	if !strings.Contains(result.Error, "only applies to .htaccess") {
		t.Errorf("wrong error: %s", result.Error)
	}
}

func TestApplyFix_HtaccessOutsideAllowedRoot(t *testing.T) {
	// fixHtaccess only allows paths under /home.
	result := ApplyFix("htaccess_injection", "", "", "/tmp/.htaccess")
	if result.Success {
		t.Error("should fail for path outside /home")
	}
	if !strings.Contains(result.Error, "outside the allowed") {
		t.Errorf("wrong error: %s", result.Error)
	}
}

func TestFixHtaccess_NonexistentPath(t *testing.T) {
	result := fixHtaccess("/home/testuser/public_html/.htaccess", "injection found")
	if result.Success {
		t.Error("should fail when file does not exist")
	}
}

func TestFixHtaccess_EmptyPath(t *testing.T) {
	result := fixHtaccess("", "injection found")
	if result.Success {
		t.Error("should fail with empty path")
	}
	if !strings.Contains(result.Error, "could not extract file path") {
		t.Errorf("wrong error: %s", result.Error)
	}
}

// ---------------------------------------------------------------------------
// remediate.go — FixDescription branches
// ---------------------------------------------------------------------------

func TestFixDescription_PhishingPage(t *testing.T) {
	desc := FixDescription("phishing_page", "", "/home/alice/public_html/login.php")
	if !strings.Contains(desc, "Quarantine") {
		t.Errorf("expected Quarantine, got %q", desc)
	}
}

func TestFixDescription_GroupWritable(t *testing.T) {
	desc := FixDescription("group_writable_php", "", "/home/alice/public_html/config.php")
	if !strings.Contains(desc, "644") {
		t.Errorf("expected 644, got %q", desc)
	}
}

func TestFixDescription_HtaccessHandler(t *testing.T) {
	desc := FixDescription("htaccess_handler_abuse", "", "/home/alice/public_html/.htaccess")
	if !strings.Contains(desc, "malicious directives") {
		t.Errorf("expected malicious directives, got %q", desc)
	}
}

func TestFixDescription_NewExecutableInConfig(t *testing.T) {
	desc := FixDescription("new_executable_in_config", "", "/home/alice/.config/miner")
	if !strings.Contains(desc, "Kill") {
		t.Errorf("expected Kill, got %q", desc)
	}
}

func TestFixDescription_NoPathYieldsEmpty(t *testing.T) {
	desc := FixDescription("world_writable_php", "no path here")
	if desc != "" {
		t.Errorf("expected empty, got %q", desc)
	}
}

func TestFixDescription_EmailPhishingNoMsgID(t *testing.T) {
	desc := FixDescription("email_phishing_content", "no message id here")
	if desc != "" {
		t.Errorf("expected empty, got %q", desc)
	}
}

// ---------------------------------------------------------------------------
// remediate.go — extractEximMsgID edge cases
// ---------------------------------------------------------------------------

func TestExtractEximMsgID_NoClosingParen(t *testing.T) {
	got := extractEximMsgID("(message: ABC123-DEF456-GH")
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// remediate.go — fixQuarantineSpoolMessage
// ---------------------------------------------------------------------------

func TestFixQuarantineSpoolMessage_NoMsgID(t *testing.T) {
	result := fixQuarantineSpoolMessage("no message id")
	if result.Success {
		t.Error("should fail when no message ID")
	}
}

func TestFixQuarantineSpoolMessage_InvalidFormat(t *testing.T) {
	result := fixQuarantineSpoolMessage("(message: INVALID)")
	if result.Success {
		t.Error("should fail for invalid format")
	}
	if !strings.Contains(result.Error, "invalid Exim message ID format") {
		t.Errorf("wrong error: %s", result.Error)
	}
}

func TestFixQuarantineSpoolMessage_SpoolNotFound(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	})
	result := fixQuarantineSpoolMessage("(message: 1ABC23-DEFG45-HI)")
	if result.Success {
		t.Error("should fail when spool not found")
	}
	if !strings.Contains(result.Error, "not found") {
		t.Errorf("wrong error: %s", result.Error)
	}
}

// ---------------------------------------------------------------------------
// remediate.go — extractFilePathFromMessage edge cases
// ---------------------------------------------------------------------------

func TestExtractFilePathFromMessage_DevShm(t *testing.T) {
	msg := "Found binary at /dev/shm/.hidden running"
	got := extractFilePathFromMessage(msg)
	if got != "/dev/shm/.hidden" {
		t.Errorf("got %q", got)
	}
}

func TestExtractFilePathFromMessage_EndsWithComma(t *testing.T) {
	msg := "Webshell found: /home/alice/public_html/evil.php, size 1234"
	got := extractFilePathFromMessage(msg)
	if got != "/home/alice/public_html/evil.php" {
		t.Errorf("got %q", got)
	}
}

func TestExtractFilePathFromMessage_EndsWithParen(t *testing.T) {
	msg := "Detected (file: /home/alice/public_html/shell.php)"
	got := extractFilePathFromMessage(msg)
	if got != "/home/alice/public_html/shell.php" {
		t.Errorf("got %q", got)
	}
}

// ---------------------------------------------------------------------------
// emailpasswd.go — parseShadowLine edge cases
// ---------------------------------------------------------------------------

func TestParseShadowLine_ColonAtEnd(t *testing.T) {
	mailbox, hash := parseShadowLine("user:")
	if mailbox != "" || hash != "" {
		t.Errorf("trailing colon should fail: mailbox=%q hash=%q", mailbox, hash)
	}
}

func TestParseShadowLine_ColonAtStart(t *testing.T) {
	mailbox, hash := parseShadowLine(":{SHA512}hash")
	if mailbox != "" || hash != "" {
		t.Errorf("leading colon should fail: mailbox=%q hash=%q", mailbox, hash)
	}
}

// ---------------------------------------------------------------------------
// emailpasswd.go — generateCandidates edge cases
// ---------------------------------------------------------------------------

func TestGenerateCandidates_EmptyDomain(t *testing.T) {
	candidates := generateCandidates("testuser", "")
	found := false
	for _, c := range candidates {
		if strings.Contains(c, "testuser") {
			found = true
			break
		}
	}
	if !found {
		t.Error("should still generate username-based candidates")
	}
}

func TestGenerateCandidates_DomainWithoutDot(t *testing.T) {
	candidates := generateCandidates("info", "localdomain")
	assertContainsLCB(t, candidates, "localdomain")
}

// ---------------------------------------------------------------------------
// emailpasswd.go — parseHIBPCount edge cases
// ---------------------------------------------------------------------------

func TestParseHIBPCount_MalformedLines(t *testing.T) {
	body := "BADFORMAT\nALSO:BAD:TWO\n"
	count := parseHIBPCount(body, "BADFORMAT")
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestParseHIBPCount_NonNumericCount(t *testing.T) {
	body := "ABC123:notanumber\n"
	count := parseHIBPCount(body, "ABC123")
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestParseHIBPCount_EmptyBody(t *testing.T) {
	count := parseHIBPCount("", "ANYTHING")
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// emailpasswd.go — discoverShadowFiles
// ---------------------------------------------------------------------------

func TestDiscoverShadowFiles_NoMatches(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
	})
	files := discoverShadowFiles()
	if len(files) != 0 {
		t.Errorf("expected empty, got %d files", len(files))
	}
}

func TestDiscoverShadowFiles_ParsesAccountAndDomain(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "shadow") {
				return []string{
					"/home/alice/etc/example.com/shadow",
					"/home/bob/etc/test.org/shadow",
				}, nil
			}
			return nil, nil
		},
	})
	files := discoverShadowFiles()
	if len(files) != 2 {
		t.Fatalf("expected 2, got %d", len(files))
	}
	if files[0].account != "alice" || files[0].domain != "example.com" {
		t.Errorf("first file: %+v", files[0])
	}
	if files[1].account != "bob" || files[1].domain != "test.org" {
		t.Errorf("second file: %+v", files[1])
	}
}

func TestDiscoverShadowFiles_ShortPath(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return []string{"/home/shadow"}, nil
		},
	})
	files := discoverShadowFiles()
	if len(files) != 0 {
		t.Errorf("short path should be skipped, got %d", len(files))
	}
}

// ---------------------------------------------------------------------------
// reputation.go — collectRecentIPs with mocked log files
// ---------------------------------------------------------------------------

func TestCollectRecentIPs_SSHLogAccepted(t *testing.T) {
	sshLog := "Apr 13 10:00:00 host sshd: Accepted publickey for root from 203.0.113.10 port 22 ssh2\n"
	tmpDir := t.TempDir()
	sshPath := filepath.Join(tmpDir, "secure")
	if err := os.WriteFile(sshPath, []byte(sshLog), 0600); err != nil {
		t.Fatal(err)
	}

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/var/log/secure" {
				return os.Open(sshPath)
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	ips := collectRecentIPs(cfg)
	if _, ok := ips["203.0.113.10"]; !ok {
		t.Errorf("expected SSH IP 203.0.113.10, got %v", ips)
	}
}

func TestCollectRecentIPs_DovecotAuthFailure(t *testing.T) {
	mailLog := "Apr 13 10:00:00 host dovecot: imap-login: auth failed, rip=198.51.100.5, session=<abc>\n"
	tmpDir := t.TempDir()
	mailPath := filepath.Join(tmpDir, "maillog")
	if err := os.WriteFile(mailPath, []byte(mailLog), 0600); err != nil {
		t.Fatal(err)
	}

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/var/log/maillog" {
				return os.Open(mailPath)
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	ips := collectRecentIPs(cfg)
	if _, ok := ips["198.51.100.5"]; !ok {
		t.Errorf("expected Dovecot IP 198.51.100.5, got %v", ips)
	}
}

func TestCollectRecentIPs_SkipsLoopback(t *testing.T) {
	sshLog := "Accepted password for user from 127.0.0.1 port 22\n"
	tmpDir := t.TempDir()
	sshPath := filepath.Join(tmpDir, "secure")
	if err := os.WriteFile(sshPath, []byte(sshLog), 0600); err != nil {
		t.Fatal(err)
	}

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/var/log/secure" {
				return os.Open(sshPath)
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	ips := collectRecentIPs(cfg)
	if _, ok := ips["127.0.0.1"]; ok {
		t.Error("loopback should be filtered out")
	}
}

func TestCollectRecentIPs_EximAuthFailure(t *testing.T) {
	eximLog := "2026-04-13 10:00:00 H=host [198.51.100.20] F=<a@b.com> authenticator failed\n"
	tmpDir := t.TempDir()
	eximPath := filepath.Join(tmpDir, "exim_mainlog")
	if err := os.WriteFile(eximPath, []byte(eximLog), 0600); err != nil {
		t.Fatal(err)
	}

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/var/log/exim_mainlog" {
				return os.Open(eximPath)
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	ips := collectRecentIPs(cfg)
	if _, ok := ips["198.51.100.20"]; !ok {
		t.Errorf("expected Exim IP 198.51.100.20, got %v", ips)
	}
}

func TestCollectRecentIPs_NoLogs(t *testing.T) {
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			return nil, os.ErrNotExist
		},
	})
	cfg := &config.Config{}
	ips := collectRecentIPs(cfg)
	if len(ips) != 0 {
		t.Errorf("expected empty, got %v", ips)
	}
}

// ---------------------------------------------------------------------------
// reputation.go — loadAllBlockedIPs legacy file
// ---------------------------------------------------------------------------

func TestLoadAllBlockedIPs_LegacyFile(t *testing.T) {
	dir := t.TempDir()
	bf := fmt.Sprintf(`{"ips":[{"ip":"203.0.113.1","expires_at":"%s"},{"ip":"203.0.113.2","expires_at":"%s"}]}`,
		time.Now().Add(1*time.Hour).Format(time.RFC3339),
		time.Now().Add(-1*time.Hour).Format(time.RFC3339))
	if err := os.WriteFile(filepath.Join(dir, "blocked_ips.json"), []byte(bf), 0600); err != nil {
		t.Fatal(err)
	}

	blocked := loadAllBlockedIPs(dir)
	if !blocked["203.0.113.1"] {
		t.Error("active legacy IP should be blocked")
	}
	if blocked["203.0.113.2"] {
		t.Error("expired legacy IP should not be blocked")
	}
}

// ---------------------------------------------------------------------------
// reputation.go — cleanCache caps at maxCacheEntries
// ---------------------------------------------------------------------------

func TestCleanCache_CapsAtMax(t *testing.T) {
	cache := &reputationCache{Entries: make(map[string]*reputationEntry)}
	for i := 0; i < maxCacheEntries+100; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		cache.Entries[ip] = &reputationEntry{
			Score:     i % 100,
			CheckedAt: time.Now().Add(-time.Duration(i) * time.Second),
		}
	}
	cleanCache(cache)
	if len(cache.Entries) > maxCacheEntries {
		t.Errorf("cache should be capped at %d, got %d", maxCacheEntries, len(cache.Entries))
	}
}

// ---------------------------------------------------------------------------
// reputation.go — saveReputationCache / loadReputationCache round-trip
// ---------------------------------------------------------------------------

func TestReputationCacheRoundTrip_MultipleEntries(t *testing.T) {
	dir := t.TempDir()
	cache := &reputationCache{Entries: map[string]*reputationEntry{
		"1.2.3.4":    {Score: 75, Category: "DC", CheckedAt: time.Now()},
		"5.6.7.8":    {Score: 10, Category: "ISP", CheckedAt: time.Now()},
		"9.10.11.12": {Score: -1, Category: "error: timeout", CheckedAt: time.Now()},
	}}
	saveReputationCache(dir, cache)

	loaded := loadReputationCache(dir)
	if len(loaded.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(loaded.Entries))
	}
	if loaded.Entries["5.6.7.8"].Score != 10 {
		t.Errorf("score = %d, want 10", loaded.Entries["5.6.7.8"].Score)
	}
	if loaded.Entries["9.10.11.12"].Score != -1 {
		t.Errorf("error cache score = %d, want -1", loaded.Entries["9.10.11.12"].Score)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func assertContainsLCB(t *testing.T, slice []string, want string) {
	t.Helper()
	for _, s := range slice {
		if s == want {
			return
		}
	}
	t.Errorf("slice does not contain %q", want)
}
