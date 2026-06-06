package checks

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const sampleWPConfig = `<?php
define( 'DB_NAME', 'alice_wp' );
define( 'DB_USER', 'alice_wp' );
$table_prefix = 'wp_';

/* That's all, stop editing! Happy publishing. */

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
require_once ABSPATH . 'wp-settings.php';
`

// withWPCronOwner injects a deterministic owner so the fix does not depend on
// which OS user runs `go test` (and so the root-owner guard never trips here).
func withWPCronOwner(t *testing.T, name string) {
	t.Helper()
	prev := wpCronOwnerName
	wpCronOwnerName = func(os.FileInfo) (string, error) { return name, nil }
	t.Cleanup(func() { wpCronOwnerName = prev })
}

// wpCronTestEnv builds an account web root with a wp-config.php under a
// t.TempDir() and points fixPerfAllowedRoots at it. Returns the config path
// and its parent docroot.
func wpCronTestEnv(t *testing.T, content string) (cfgPath, docroot string) {
	t.Helper()
	withWPCronOwner(t, "alice")
	root := realTempDir(t)
	withPerfFixRoots(t, root)
	docroot = filepath.Join(root, "alice", "public_html")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath = filepath.Join(docroot, "wp-config.php")
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfgPath, docroot
}

// crontabRecorder is a mockCmd that emulates `crontab -u <user> -l` returning
// a fixed body and captures the content written by `crontab -u <user> <file>`.
type crontabRecorder struct {
	existing      string
	installCalls  int
	lastInstalled string
}

func (c *crontabRecorder) mock() *mockCmd {
	return &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			if name == "crontab" && containsArg(args, "-l") {
				return []byte(c.existing), nil
			}
			return nil, nil
		},
		run: func(name string, args ...string) ([]byte, error) {
			if name == "crontab" && !containsArg(args, "-l") && len(args) > 0 {
				c.installCalls++
				// Install form is `crontab -u <user> <file>`; the last arg is
				// the spool file we wrote. Read it before the caller removes it.
				if b, err := os.ReadFile(args[len(args)-1]); err == nil {
					c.lastInstalled = string(b)
				}
			}
			return nil, nil
		},
	}
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func TestFixDisableWPCronInsertsDefineAndInstallsCron(t *testing.T) {
	cfgPath, docroot := wpCronTestEnv(t, sampleWPConfig)
	rec := &crontabRecorder{existing: ""}
	withMockCmd(t, rec.mock())

	res := FixDisableWPCron(cfgPath, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}

	out, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	if strings.Count(body, "DISABLE_WP_CRON") != 1 {
		t.Fatalf("expected exactly one DISABLE_WP_CRON define, got:\n%s", body)
	}
	if !strings.Contains(body, "define( 'DISABLE_WP_CRON', true )") {
		t.Errorf("define not written in expected form:\n%s", body)
	}
	// Insertion must land before the require of wp-settings.php so the
	// constant is defined before WordPress reads it.
	if di, ri := strings.Index(body, "DISABLE_WP_CRON"), strings.Index(body, "wp-settings.php"); di < 0 || ri < 0 || di > ri {
		t.Errorf("define must appear before wp-settings.php require (define=%d require=%d)", di, ri)
	}

	if rec.installCalls != 1 {
		t.Fatalf("expected exactly one crontab install, got %d", rec.installCalls)
	}
	cron := rec.lastInstalled
	if !strings.Contains(cron, "*/5 * * * *") {
		t.Errorf("cron interval not 5 min:\n%s", cron)
	}
	if !strings.Contains(cron, "cd "+docroot+" &&") {
		t.Errorf("cron missing docroot %q:\n%s", docroot, cron)
	}
	if !strings.Contains(cron, "wp-cron.php") || !strings.Contains(cron, "/usr/local/bin/php") {
		t.Errorf("cron missing php/wp-cron invocation:\n%s", cron)
	}
}

func TestFixDisableWPCronIdempotent(t *testing.T) {
	already := strings.Replace(sampleWPConfig,
		"$table_prefix = 'wp_';",
		"$table_prefix = 'wp_';\ndefine( 'DISABLE_WP_CRON', true );", 1)
	cfgPath, docroot := wpCronTestEnv(t, already)
	// Existing crontab already carries our managed line for this docroot.
	rec := &crontabRecorder{existing: "# CSM WP-Cron " + docroot + "\n*/5 * * * * cd " + docroot + " && /usr/local/bin/php -d max_execution_time=300 wp-cron.php >/dev/null 2>&1\n"}
	withMockCmd(t, rec.mock())

	before, _ := os.ReadFile(cfgPath)
	res := FixDisableWPCron(cfgPath, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
	if !res.Success {
		t.Fatalf("expected success on no-op, got %+v", res)
	}
	after, _ := os.ReadFile(cfgPath)
	if string(before) != string(after) {
		t.Errorf("wp-config.php must be untouched when already disabled")
	}
	if strings.Count(string(after), "DISABLE_WP_CRON") != 1 {
		t.Errorf("must not duplicate the define")
	}
	if rec.installCalls != 0 {
		t.Errorf("must not rewrite crontab when managed line already present, got %d installs", rec.installCalls)
	}
}

func TestFixDisableWPCronInstallsCronWhenDefinePresentButCronMissing(t *testing.T) {
	already := strings.Replace(sampleWPConfig,
		"$table_prefix = 'wp_';",
		"$table_prefix = 'wp_';\ndefine( 'DISABLE_WP_CRON', true );", 1)
	cfgPath, _ := wpCronTestEnv(t, already)
	rec := &crontabRecorder{existing: ""} // no managed line yet
	withMockCmd(t, rec.mock())

	res := FixDisableWPCron(cfgPath, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	if rec.installCalls != 1 {
		t.Errorf("expected cron install when define present but cron absent, got %d", rec.installCalls)
	}
}

func TestFixDisableWPCronRejectsNonConfigFile(t *testing.T) {
	root := realTempDir(t)
	withPerfFixRoots(t, root)
	docroot := filepath.Join(root, "alice", "public_html")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(docroot, "settings.php")
	if err := os.WriteFile(other, []byte("<?php\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := &crontabRecorder{}
	withMockCmd(t, rec.mock())

	res := FixDisableWPCron(other, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
	if res.Success {
		t.Fatalf("expected refusal for non wp-config.php file")
	}
	if rec.installCalls != 0 {
		t.Errorf("must not touch crontab on refusal")
	}
}

func TestFixDisableWPCronRefusesWithoutInsertionPoint(t *testing.T) {
	// No "stop editing" marker and no wp-settings require: refuse rather
	// than corrupt an unfamiliar PHP file.
	bad := "<?php\ndefine( 'DB_NAME', 'x' );\n// nothing else\n"
	cfgPath, _ := wpCronTestEnv(t, bad)
	rec := &crontabRecorder{}
	withMockCmd(t, rec.mock())

	res := FixDisableWPCron(cfgPath, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
	if res.Success {
		t.Fatalf("expected refusal without a safe insertion point")
	}
	out, _ := os.ReadFile(cfgPath)
	if string(out) != bad {
		t.Errorf("file must be unchanged on refusal")
	}
	if rec.installCalls != 0 {
		t.Errorf("must not install cron on refusal")
	}
}

func TestFixDisableWPCronInsertsBeforeRequireWhenNoMarker(t *testing.T) {
	noMarker := "<?php\ndefine( 'DB_NAME', 'x' );\nrequire_once ABSPATH . 'wp-settings.php';\n"
	cfgPath, _ := wpCronTestEnv(t, noMarker)
	rec := &crontabRecorder{}
	withMockCmd(t, rec.mock())

	res := FixDisableWPCron(cfgPath, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
	if !res.Success {
		t.Fatalf("expected success using wp-settings fallback, got %+v", res)
	}
	body, _ := os.ReadFile(cfgPath)
	di, ri := strings.Index(string(body), "DISABLE_WP_CRON"), strings.Index(string(body), "wp-settings.php")
	if di < 0 || ri < 0 || di > ri {
		t.Errorf("define must precede wp-settings require")
	}
}

func TestWPCronIntervalClamping(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{0, "*/5 * * * *"},
		{-3, "*/5 * * * *"},
		{15, "*/15 * * * *"},
		{90, "*/60 * * * *"},
	}
	for _, tc := range cases {
		cfgPath, docroot := wpCronTestEnv(t, sampleWPConfig)
		rec := &crontabRecorder{}
		withMockCmd(t, rec.mock())
		res := FixDisableWPCron(cfgPath, WPCronFixOptions{IntervalMinutes: tc.in, PHPBin: "/usr/local/bin/php"})
		if !res.Success {
			t.Fatalf("interval %d: expected success, got %+v", tc.in, res)
		}
		if !strings.Contains(rec.lastInstalled, tc.want+" cd "+docroot) {
			t.Errorf("interval %d: want schedule %q, cron:\n%s", tc.in, tc.want, rec.lastInstalled)
		}
	}
}

func TestFileOwnerNameRefusesRootOwned(t *testing.T) {
	// /etc/passwd is uid 0 on Linux and macOS; gives a real root-owned inode
	// to exercise the guard without needing privileges.
	info, err := os.Stat("/etc/passwd")
	if err != nil {
		t.Skip("/etc/passwd not available")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		t.Skip("/etc/passwd not root-owned on this host")
	}
	if _, err := fileOwnerName(info); err == nil {
		t.Error("expected refusal for a root-owned file")
	}
}

func FuzzInsertDisableWPCron(f *testing.F) {
	f.Add(sampleWPConfig)
	f.Add("<?php\n")
	f.Add("")
	f.Add("require_once ABSPATH . 'wp-settings.php';")
	f.Fuzz(func(t *testing.T, content string) {
		// Must never panic regardless of file shape.
		_, _ = insertDisableWPCron([]byte(content))
	})
}
