package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// --- parseWPConfig: multisite detection ----------------------------------

func TestParseWPConfigMultisiteFalseByDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wp-config.php")
	body := "<?php\n" +
		"define( 'DB_NAME', 'wp_main' );\n" +
		"define( 'DB_USER', 'wpuser' );\n" +
		"define( 'DB_PASSWORD', 'pw' );\n" +
		"$table_prefix = 'wp_';\n"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	creds := parseWPConfig(path)
	if creds.multisite {
		t.Error("multisite should be false when MULTISITE not declared")
	}
}

func TestParseWPConfigMultisiteTrueDetected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wp-config.php")
	body := "<?php\n" +
		"define( 'DB_NAME', 'wp_net' );\n" +
		"define( 'DB_USER', 'wpuser' );\n" +
		"define( 'DB_PASSWORD', 'pw' );\n" +
		"define( 'WP_ALLOW_MULTISITE', true );\n" +
		"define( 'MULTISITE', true );\n" +
		"$table_prefix = 'wp_';\n"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	creds := parseWPConfig(path)
	if !creds.multisite {
		t.Error("multisite should be true when MULTISITE declared")
	}
}

func TestParseWPConfigMultisiteCommentedOutIsFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wp-config.php")
	body := "<?php\n" +
		"define( 'DB_NAME', 'wp_main' );\n" +
		"define( 'DB_USER', 'wpuser' );\n" +
		"// define( 'MULTISITE', true );\n" +
		"# define( 'MULTISITE', true );\n" +
		"/* define( 'MULTISITE', true ); */\n" +
		"$table_prefix = 'wp_';\n"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	creds := parseWPConfig(path)
	if creds.multisite {
		t.Error("multisite should be false when MULTISITE only appears in comments")
	}
}

func TestParseWPConfigMultisiteFalseLiteralIsFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wp-config.php")
	body := "<?php\n" +
		"define( 'DB_NAME', 'wp_main' );\n" +
		"define( 'MULTISITE', false );\n" +
		"$table_prefix = 'wp_';\n"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	creds := parseWPConfig(path)
	if creds.multisite {
		t.Error("MULTISITE=false should not turn multisite on")
	}
}

// --- extractDefineBool ---------------------------------------------------

func TestExtractDefineBoolHappyPaths(t *testing.T) {
	cases := []struct {
		name string
		line string
		want bool
	}{
		{"canonical", `define( 'MULTISITE', true );`, true},
		{"no-spaces", `define('MULTISITE',true);`, true},
		{"upper-bool", `define( 'MULTISITE', TRUE );`, true},
		{"trailing-comment", `define( 'MULTISITE', true ); // network`, true},
		{"false-literal", `define( 'MULTISITE', false );`, false},
		{"missing-key", `define( 'OTHER', true );`, false},
		{"comment-line", `// define( 'MULTISITE', true );`, false},
		{"hash-comment", `# define( 'MULTISITE', true );`, false},
		{"block-comment", `/* define( 'MULTISITE', true ); */`, false},
		{"non-bool-int", `define( 'MULTISITE', 1 );`, false},
		{"missing-comma", `define( 'MULTISITE' true );`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractDefineBool(c.line, "MULTISITE")
			if got != c.want {
				t.Errorf("got %v, want %v on %q", got, c.want, c.line)
			}
		})
	}
}

// --- isAllDigits ---------------------------------------------------------

func TestIsAllDigits(t *testing.T) {
	pass := []string{"0", "1", "42", "10000"}
	fail := []string{"", "abc", "1a", "-1", "1.5", " 5", "5 "}
	for _, s := range pass {
		if !isAllDigits(s) {
			t.Errorf("isAllDigits(%q) = false, want true", s)
		}
	}
	for _, s := range fail {
		if isAllDigits(s) {
			t.Errorf("isAllDigits(%q) = true, want false", s)
		}
	}
}

// --- scanMultisiteSecondaryBlogs -----------------------------------------

func TestScanMultisiteSecondaryBlogsIteratesActiveIDs(t *testing.T) {
	// Mock mysql so wp_blogs returns three active IDs (2, 3, 5)
	// plus the always-skipped 1. The per-site checkWPOptions and
	// checkWPPosts queries return nothing, so we just verify that
	// the right set of queries was made.
	var queriesMade []string
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			queriesMade = append(queriesMade, joined)
			switch {
			case strings.Contains(joined, "FROM wp_blogs"):
				// Some implementations of `mysql -B -N` print a
				// trailing newline per row; mimic that here.
				return []byte("2\n3\n5\n"), nil
			default:
				// All per-site option/post/user queries return empty.
				return nil, nil
			}
		},
	})

	creds := wpDBCreds{
		dbName:      "wp_net",
		dbUser:      "wpuser",
		dbPass:      "pw",
		dbHost:      "localhost",
		tablePrefix: "wp_",
		multisite:   true,
	}
	_ = scanMultisiteSecondaryBlogs("alice", creds, "wp_")

	// Expect: wp_blogs query exactly once.
	wpBlogsCount := 0
	for _, q := range queriesMade {
		if strings.Contains(q, "FROM wp_blogs") {
			wpBlogsCount++
		}
	}
	if wpBlogsCount != 1 {
		t.Errorf("wp_blogs query count = %d, want 1", wpBlogsCount)
	}

	// Expect: per-site queries for blog IDs 2, 3, 5 -- specifically
	// the per-site prefix shows up in some query argument list.
	for _, id := range []string{"2", "3", "5"} {
		want := "wp_" + id + "_"
		seen := false
		for _, q := range queriesMade {
			if strings.Contains(q, want) {
				seen = true
				break
			}
		}
		if !seen {
			t.Errorf("missing per-site query for blog %s (looked for prefix %q)", id, want)
		}
	}
}

func TestScanMultisiteSecondaryBlogsSkipsBlog1(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "FROM wp_blogs") {
				// Even if the server (somehow) reports blog 1 in
				// the active list, the scanner must skip it.
				return []byte("1\n2\n"), nil
			}
			if strings.Contains(joined, "wp_1_") {
				t.Errorf("scanner queried wp_1_ tables; should skip blog 1")
			}
			return nil, nil
		},
	})
	creds := wpDBCreds{
		dbName: "wp_net", dbUser: "wpuser", dbPass: "pw", dbHost: "localhost",
		tablePrefix: "wp_", multisite: true,
	}
	_ = scanMultisiteSecondaryBlogs("alice", creds, "wp_")
}

func TestScanMultisiteSecondaryBlogsRejectsNonNumericRows(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "FROM wp_blogs") {
				// Defence in depth: if something hostile returns a
				// schema name in place of a numeric ID, the scanner
				// must reject it before constructing a table name.
				return []byte("2; DROP TABLE wp_users; --\nfoo\n3\n"), nil
			}
			if strings.Contains(joined, "DROP TABLE") {
				t.Errorf("scanner injected DROP TABLE into a follow-up query")
			}
			return nil, nil
		},
	})
	creds := wpDBCreds{
		dbName: "wp_net", dbUser: "wpuser", dbPass: "pw", dbHost: "localhost",
		tablePrefix: "wp_", multisite: true,
	}
	_ = scanMultisiteSecondaryBlogs("alice", creds, "wp_")
}

// --- CheckDatabaseContent: end-to-end multisite path ---------------------

// fakeMSWPConfig stubs Glob and Open so CheckDatabaseContent picks
// up exactly one wp-config.php declaring MULTISITE=true.
type fakeMSWPConfig struct {
	mockOS
	body string
}

func (m *fakeMSWPConfig) Glob(pattern string) ([]string, error) {
	if strings.Contains(pattern, "wp-config.php") {
		return []string{"/home/alice/public_html/wp-config.php"}, nil
	}
	return nil, nil
}

func (m *fakeMSWPConfig) Open(name string) (*os.File, error) {
	if name != "/home/alice/public_html/wp-config.php" {
		return nil, os.ErrNotExist
	}
	tmp, err := os.CreateTemp("", "wpconfig*.php")
	if err != nil {
		return nil, err
	}
	if _, err := tmp.WriteString(m.body); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if _, err := tmp.Seek(0, 0); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	return tmp, nil
}

func TestCheckDatabaseContentMultisiteScansMainAndSecondary(t *testing.T) {
	withMockOS(t, &fakeMSWPConfig{
		body: "<?php\n" +
			"define( 'DB_NAME', 'wp_net' );\n" +
			"define( 'DB_USER', 'wpuser' );\n" +
			"define( 'DB_PASSWORD', 'pw' );\n" +
			"define( 'MULTISITE', true );\n" +
			"$table_prefix = 'wp_';\n",
	})

	queries := map[string]int{}
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			queries[joined]++
			if strings.Contains(joined, "FROM wp_blogs") {
				return []byte("2\n3\n"), nil
			}
			return nil, nil
		},
	})

	_ = CheckDatabaseContent(context.Background(), &config.Config{}, &state.Store{})

	// Main site (unprefixed): the existing checkWP* helpers run
	// against `wp_options`, `wp_posts`, `wp_users`. Ensure at
	// least one of them ran.
	mainTouched := false
	for q := range queries {
		if strings.Contains(q, "wp_options") || strings.Contains(q, "wp_posts") || strings.Contains(q, "wp_users") {
			mainTouched = true
			break
		}
	}
	if !mainTouched {
		t.Error("main-site (unprefixed) tables were never queried")
	}

	// Secondary sites: scanner must have used the wp_2_ and wp_3_
	// prefixes for at least one query each.
	for _, id := range []string{"2", "3"} {
		want := "wp_" + id + "_"
		seen := false
		for q := range queries {
			if strings.Contains(q, want) {
				seen = true
				break
			}
		}
		if !seen {
			t.Errorf("multisite blog %s was never queried (expected prefix %q)", id, want)
		}
	}
}
