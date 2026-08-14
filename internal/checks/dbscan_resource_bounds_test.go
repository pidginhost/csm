package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/mysqlclient"
)

// The addon-domain expansion turns this cost into a host-wide multiplier.
// Keep the post-content work to one bounded malware query and one bounded spam
// query per site instead of one connection and round trip per signature.
func TestCheckWPPostsBatchesPatternQueries(t *testing.T) {
	previous := runMySQLQuery
	var queries []string
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		queries = append(queries, query)
		return nil
	}
	t.Cleanup(func() { runMySQLQuery = previous })

	checkWPPosts("alice", wpDBCreds{dbName: "wp"}, "wp_")
	if len(queries) != 2 {
		t.Fatalf("post-content query count = %d, want 2", len(queries))
	}
	if got := strings.Count(queries[0], " LIMIT 20)"); got != len(dbMalwarePatterns) {
		t.Errorf("malware query bounded selects = %d, want %d", got, len(dbMalwarePatterns))
	}
	if strings.Contains(queries[0], "'', ''") {
		t.Error("malware query uses trailing empty columns that batch trimming discards")
	}
	if got := strings.Count(queries[0], "'_content_not_required'"); got != len(dbMalwarePatterns)-1 {
		t.Errorf("malware query bounded projections = %d, want %d", got, len(dbMalwarePatterns)-1)
	}
	if got := strings.Count(queries[1], " LIMIT 200)"); got != len(dbSpamPatterns) {
		t.Errorf("spam query bounded selects = %d, want %d", got, len(dbSpamPatterns))
	}
}

func TestCheckWPPostsClassifiesBatchedRows(t *testing.T) {
	previous := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if strings.Contains(query, "post_content_filtered") {
			return []string{
				"0\t17\t<script src=\"https://attacker.workers.dev/payload.js\"></script>",
				"1\t19\t_content_not_required",
			}
		}
		return []string{"0\t23\t<div style=\"display:none\"><a href=\"https://spam.top/buy/viagra\">viagra</a></div>"}
	}
	t.Cleanup(func() { runMySQLQuery = previous })

	findings := checkWPPosts("alice", wpDBCreds{dbName: "wp"}, "wp_")
	var externalScript, evalPattern, spam bool
	for _, finding := range findings {
		switch finding.Check {
		case "db_post_injection":
			externalScript = externalScript || strings.Contains(finding.Details, "17")
			evalPattern = evalPattern || strings.Contains(finding.Details, "19")
		case "db_spam_injection":
			spam = true
		}
	}
	if !externalScript || !evalPattern || !spam {
		t.Fatalf("batched post rows produced findings %+v, want both malware patterns and spam", findings)
	}
}

func TestCheckDatabaseContentRejectsOversizedWPConfig(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "wp-config.php")
	content := "<?php\n" +
		"define('DB_NAME', 'alice_wp');\n" +
		"define('DB_USER', 'alice_wp');\n" +
		strings.Repeat("# padding\n", maxWPConfigBytes/10+2)
	if err := os.WriteFile(configFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, complete := parseWPConfigChecked(configFile); complete {
		t.Fatal("oversized wp-config.php parsed as complete")
	}
	if creds := parseWPConfig(configFile); creds != (wpDBCreds{}) {
		t.Fatalf("oversized wp-config.php returned partial credentials: %+v", creds)
	}
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/home/*/public_html/wp-config.php" {
				return []string{"/home/alice/public_html/wp-config.php"}, nil
			}
			return nil, nil
		},
		open: func(string) (*os.File, error) { return os.Open(configFile) },
		lstat: func(string) (os.FileInfo, error) {
			return os.Stat(configFile)
		},
	})

	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	findings := CheckDatabaseContent(ctx, nil, nil)
	if !incomplete.contains("db_content") {
		t.Fatal("oversized wp-config.php did not mark the database scan incomplete")
	}
	if len(findings) != 1 || findings[0].Check != "db_content_scan_incomplete" {
		t.Fatalf("oversized wp-config.php findings = %+v, want incomplete warning", findings)
	}
}

func TestParseWPConfigRejectsNonRegularFilesWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.php")
	if err := os.WriteFile(target, []byte("define('DB_NAME', 'victim');\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "symlink.php")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if _, complete := parseWPConfigChecked(symlink); complete {
		t.Fatal("symlink wp-config.php parsed as complete")
	}

	fifo := filepath.Join(dir, "wp-config.php")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan bool, 1)
	go func() {
		_, complete := parseWPConfigChecked(fifo)
		done <- complete
	}()
	select {
	case complete := <-done:
		if complete {
			t.Fatal("FIFO wp-config.php parsed as complete")
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO wp-config.php blocked the parser")
	}
}

func TestCheckDatabaseContentReportsQueryFailure(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "wp-config.php")
	if err := os.WriteFile(configFile, []byte("<?php\n"+
		"define('DB_NAME', 'alice_wp');\n"+
		"define('DB_USER', 'alice_wp');\n"+
		"$table_prefix = 'wp_';\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/home/*/public_html/wp-config.php" {
				return []string{"/home/alice/public_html/wp-config.php"}, nil
			}
			return nil, nil
		},
		open: func(string) (*os.File, error) { return os.Open(configFile) },
		lstat: func(string) (os.FileInfo, error) {
			return os.Stat(configFile)
		},
	})
	queryCalls := 0
	mysqlclient.SetPerAccountQueryForTest(func(context.Context, mysqlclient.Creds, string, ...any) ([]string, error) {
		queryCalls++
		return nil, errors.New("database unavailable")
	})
	t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })

	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	findings := CheckDatabaseContent(ctx, nil, nil)
	if !incomplete.contains("db_content") {
		t.Fatal("database query failure did not mark the scan incomplete")
	}
	if queryCalls != 1 {
		t.Fatalf("queries after first database failure = %d, want 1", queryCalls)
	}
	if len(findings) != 1 || findings[0].Check != "db_content_scan_incomplete" {
		t.Fatalf("query failure findings = %+v, want incomplete warning", findings)
	}
}

func TestCheckDatabaseContentReportsUnusableConfig(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing database user",
			body: "<?php\ndefine('DB_NAME', 'alice_wp');\n",
		},
		{
			name: "unsafe table prefix",
			body: "<?php\ndefine('DB_NAME', 'alice_wp');\n" +
				"define('DB_USER', 'alice_wp');\n$table_prefix = 'wp_; DROP TABLE users';\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			configFile := filepath.Join(t.TempDir(), "wp-config.php")
			if err := os.WriteFile(configFile, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			withMockOS(t, &mockOS{
				glob: func(pattern string) ([]string, error) {
					if pattern == "/home/*/public_html/wp-config.php" {
						return []string{"/home/alice/public_html/wp-config.php"}, nil
					}
					return nil, nil
				},
				open: func(string) (*os.File, error) { return os.Open(configFile) },
				lstat: func(string) (os.FileInfo, error) {
					return os.Stat(configFile)
				},
			})

			ctx, incomplete := withIncompleteCheckCollector(context.Background())
			findings := CheckDatabaseContent(ctx, nil, nil)
			if !incomplete.contains("db_content") {
				t.Fatal("unusable wp-config.php did not mark the scan incomplete")
			}
			if len(findings) != 1 || findings[0].Check != "db_content_scan_incomplete" {
				t.Fatalf("unusable wp-config.php findings = %+v, want incomplete warning", findings)
			}
		})
	}
}

func TestRunMySQLQueryUsesScanContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var queryErr error
	mysqlclient.SetPerAccountQueryForTest(func(queryCtx context.Context, _ mysqlclient.Creds, _ string, _ ...any) ([]string, error) {
		queryErr = queryCtx.Err()
		return nil, queryErr
	})
	t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })

	runMySQLQuery(wpDBCreds{dbName: "wp", queryCtx: ctx}, "SELECT 1")
	if !errors.Is(queryErr, context.Canceled) {
		t.Fatalf("database query context error = %v, want context cancellation", queryErr)
	}
}

func TestCheckDatabaseContentDeduplicatesSharedInstall(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "wp-config.php")
	if err := os.WriteFile(configFile, []byte("<?php\n"+
		"define('DB_NAME', 'alice_wp');\n"+
		"define('DB_USER', 'alice_wp');\n"+
		"define('DB_PASSWORD', 'secret');\n"+
		"$table_prefix = 'wp_';\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			switch pattern {
			case "/home/*/public_html/wp-config.php":
				return []string{"/home/alice/public_html/wp-config.php"}, nil
			case "/home/*/*/wp-config.php":
				return []string{
					"/home/alice/public_html/wp-config.php",
					"/home/alice/shop.example.com/wp-config.php",
				}, nil
			default:
				return nil, nil
			}
		},
		open: func(string) (*os.File, error) { return os.Open(configFile) },
		lstat: func(string) (os.FileInfo, error) {
			return os.Stat(configFile)
		},
	})

	previous := runMySQLQuery
	queries := 0
	runMySQLQuery = func(_ wpDBCreds, _ string) []string {
		queries++
		return nil
	}
	t.Cleanup(func() { runMySQLQuery = previous })

	CheckDatabaseContent(context.Background(), nil, nil)
	if queries != 7 {
		t.Errorf("queries for two paths sharing one database = %d, want 7 for one scan", queries)
	}
}

func TestScanMultisiteSecondaryBlogsIsBounded(t *testing.T) {
	previous := runMySQLQuery
	queriedBeyondLimit := false
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if strings.Contains(query, "FROM wp_blogs") {
			rows := make([]string, 0, maxWPSecondaryBlogs+1)
			for id := 2; id < maxWPSecondaryBlogs+3; id++ {
				rows = append(rows, fmt.Sprint(id))
			}
			return rows
		}
		if strings.Contains(query, fmt.Sprintf("wp_%d_", maxWPSecondaryBlogs+2)) {
			queriedBeyondLimit = true
		}
		return nil
	}
	t.Cleanup(func() { runMySQLQuery = previous })

	findings := scanMultisiteSecondaryBlogs(context.Background(), "alice", wpDBCreds{dbName: "network"}, "wp_")
	if queriedBeyondLimit {
		t.Fatal("multisite scanner queried a site beyond its safety limit")
	}
	if len(findings) != 1 || findings[0].Check != "db_content_scan_incomplete" {
		t.Fatalf("bounded multisite scan findings = %+v, want one incomplete finding", findings)
	}
}

func TestDatabaseContentUsesHeavyCheckBudget(t *testing.T) {
	if got := timeoutFor("db_content"); got != heavyCheckTimeout {
		t.Errorf("db_content timeout = %s, want heavy-check budget %s", got, heavyCheckTimeout)
	}
}
