package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// findWPTransients recursively locates wp-config.php and for each runs
// a mysql query for oversized transients. Tests cover:
//   - depth < 0 → early return
//   - ReadDir error → silent return
//   - skipDir subtree (wp-admin, wp-content, etc.) → not recursed
//   - wp-config.php with missing dbName/dbUser → skipped
//   - wp-config.php with unsafe identifier → skipped
//   - mysql emits usable rows → emits findings with correct severity by size

func TestFindWPTransientsDepthBelowZero(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "wp-config.php"), []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	findWPTransients(tmp, &config.Config{}, 1024, 10240, -1, &findings)
	if len(findings) != 0 {
		t.Errorf("depth<0 should return early, got %d findings", len(findings))
	}
}

func TestFindWPTransientsMissingDir(t *testing.T) {
	var findings []alert.Finding
	findWPTransients("/no-such-dir", &config.Config{}, 1024, 10240, 3, &findings)
	if len(findings) != 0 {
		t.Errorf("missing dir should yield no findings, got %d", len(findings))
	}
}

func TestFindWPTransientsSkipsSkipListDirs(t *testing.T) {
	tmp := t.TempDir()
	// Drop a wp-config.php under wp-admin — the skipDirs whitelist must
	// prevent recursion into that subtree.
	sub := filepath.Join(tmp, "wp-admin")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "wp-config.php"),
		[]byte("<?php define('DB_NAME','x');"), 0644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	findWPTransients(tmp, &config.Config{}, 1024, 10240, 3, &findings)
	if len(findings) != 0 {
		t.Errorf("skipDir subtree should not be recursed, got %d findings", len(findings))
	}
}

func TestFindWPTransientsMissingDBCredentialsSkipped(t *testing.T) {
	tmp := t.TempDir()
	// wp-config.php with no DB_NAME/DB_USER defines.
	if err := os.WriteFile(filepath.Join(tmp, "wp-config.php"),
		[]byte("<?php\n$table_prefix = 'wp_';\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Any cmdExec.Run call here is a bug in the function — fail loudly.
	mockCalls := 0
	withMockCmd(t, &mockCmd{
		runWithEnv: func(string, []string, ...string) ([]byte, error) {
			mockCalls++
			return nil, nil
		},
	})
	var findings []alert.Finding
	findWPTransients(tmp, &config.Config{}, 1024, 10240, 3, &findings)
	if mockCalls != 0 {
		t.Errorf("missing creds should short-circuit before mysql, got %d calls", mockCalls)
	}
	if len(findings) != 0 {
		t.Errorf("no findings expected, got %d", len(findings))
	}
}

func TestFindWPTransientsUnsafeIdentifierSkipped(t *testing.T) {
	tmp := t.TempDir()
	// DB_NAME contains a semicolon — safeIdentifier rejects it, function
	// must skip without executing mysql.
	content := "<?php\n" +
		"define('DB_NAME', 'evil; drop table');\n" +
		"define('DB_USER', 'wp_user');\n" +
		"define('DB_PASSWORD', 'secret');\n" +
		"define('DB_HOST', 'localhost');\n"
	if err := os.WriteFile(filepath.Join(tmp, "wp-config.php"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	calls := 0
	withMockCmd(t, &mockCmd{
		runWithEnv: func(string, []string, ...string) ([]byte, error) {
			calls++
			return nil, nil
		},
	})
	var findings []alert.Finding
	findWPTransients(tmp, &config.Config{}, 1024, 10240, 3, &findings)
	if calls != 0 {
		t.Errorf("unsafe identifier should short-circuit before mysql, got %d calls", calls)
	}
}

func TestFindWPTransientsEmitsWarningAndCriticalBySize(t *testing.T) {
	tmp := t.TempDir()
	content := "<?php\n" +
		"define('DB_NAME', 'wp_site');\n" +
		"define('DB_USER', 'wp_user');\n" +
		"define('DB_PASSWORD', 'secret');\n" +
		"define('DB_HOST', 'localhost');\n" +
		"$table_prefix = 'wp_';\n"
	if err := os.WriteFile(filepath.Join(tmp, "wp-config.php"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	// mysql returns two transients: one over warnBytes (1KB), one over
	// critBytes (10KB). Expected: one Warning + one High severity finding.
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			if name != "mysql" {
				t.Errorf("expected mysql call, got %s", name)
			}
			return []byte("_transient_big	5000\n_transient_huge	20000\n"), nil
		},
	})
	var findings []alert.Finding
	findWPTransients(tmp, &config.Config{}, 1024, 10240, 3, &findings)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (warn+crit), got %d: %+v", len(findings), findings)
	}
	warns, highs := 0, 0
	for _, f := range findings {
		switch f.Severity {
		case alert.Warning:
			warns++
		case alert.High:
			highs++
		}
	}
	if warns != 1 || highs != 1 {
		t.Errorf("expected 1 warn + 1 high, got %d warn %d high", warns, highs)
	}
}
