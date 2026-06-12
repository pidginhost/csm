package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func withWPCronSpoolDirs(t *testing.T, dirs ...string) {
	t.Helper()
	prev := wpCronSpoolDirs
	wpCronSpoolDirs = dirs
	t.Cleanup(func() { wpCronSpoolDirs = prev })
}

// migrateCrontabMock serves `crontab -u <user> -l` from a per-user map and
// records installs per user.
type migrateCrontabMock struct {
	crontabs map[string]string
	installs map[string]string
}

func (m *migrateCrontabMock) mock() *mockCmd {
	return &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			if name == "crontab" && containsArg(args, "-l") && len(args) >= 2 {
				return []byte(m.crontabs[args[1]]), nil
			}
			return nil, nil
		},
		run: func(name string, args ...string) ([]byte, error) {
			if name == "crontab" && !containsArg(args, "-l") && len(args) >= 3 {
				if b, err := os.ReadFile(args[len(args)-1]); err == nil {
					m.installs[args[1]] = string(b)
				}
			}
			return nil, nil
		},
	}
}

func wpCronMigrateConfig() *config.Config {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.FixWPCron = true
	cfg.Performance.WPCronFix.IntervalMinutes = 15
	cfg.Performance.WPCronFix.PHPBin = "/usr/local/bin/php"
	return cfg
}

func TestMigrateWPCronCrontabsUpgradesLegacyManagedEntries(t *testing.T) {
	spool := t.TempDir()
	withWPCronSpoolDirs(t, spool)

	opts := WPCronFixOptions{IntervalMinutes: 15, PHPBin: "/usr/local/bin/php"}
	legacyAlice := "# CSM WP-Cron /home/alice/public_html\n" +
		"*/5 * * * * cd '/home/alice/public_html' && '/usr/local/bin/php' -d max_execution_time=300 wp-cron.php >/dev/null 2>&1\n"
	currentBob := "# CSM WP-Cron /home/bob/public_html\n" +
		wpCronJobLine("bob", "/home/bob/public_html", opts) + "\n"
	unmanagedCarol := "*/10 * * * * cd '/home/carol/public_html' && /usr/local/bin/php wp-cron.php\n"

	files := map[string]string{
		"alice": legacyAlice,
		"bob":   currentBob,
		"carol": unmanagedCarol,
	}
	for user, body := range files {
		if err := os.WriteFile(filepath.Join(spool, user), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Invalid account names never reach `crontab -u`, marker or not.
	if err := os.WriteFile(filepath.Join(spool, "Bad User"), []byte(legacyAlice), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := &migrateCrontabMock{crontabs: files, installs: map[string]string{}}
	withMockCmd(t, rec.mock())

	upgraded := MigrateWPCronCrontabs(wpCronMigrateConfig())
	if upgraded != 1 {
		t.Fatalf("MigrateWPCronCrontabs = %d, want 1", upgraded)
	}
	if len(rec.installs) != 1 {
		t.Fatalf("expected exactly one crontab install, got %v", rec.installs)
	}
	got, ok := rec.installs["alice"]
	if !ok {
		t.Fatalf("expected alice's crontab to be upgraded, got installs for %v", rec.installs)
	}
	want := wpCronJobLine("alice", "/home/alice/public_html", opts)
	if !strings.Contains(got, "# CSM WP-Cron /home/alice/public_html\n"+want+"\n") {
		t.Errorf("upgraded crontab missing staggered job line:\n%s", got)
	}
	if strings.Contains(got, "*/5 * * * *") {
		t.Errorf("legacy schedule must be gone:\n%s", got)
	}
}

func TestMigrateWPCronCrontabsRespectsOptIn(t *testing.T) {
	spool := t.TempDir()
	withWPCronSpoolDirs(t, spool)
	legacy := "# CSM WP-Cron /home/alice/public_html\n" +
		"*/5 * * * * cd '/home/alice/public_html' && '/usr/local/bin/php' -d max_execution_time=300 wp-cron.php >/dev/null 2>&1\n"
	if err := os.WriteFile(filepath.Join(spool, "alice"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := &migrateCrontabMock{crontabs: map[string]string{"alice": legacy}, installs: map[string]string{}}
	withMockCmd(t, rec.mock())

	for _, cfg := range []*config.Config{
		func() *config.Config { c := wpCronMigrateConfig(); c.AutoResponse.Enabled = false; return c }(),
		func() *config.Config { c := wpCronMigrateConfig(); c.AutoResponse.FixWPCron = false; return c }(),
	} {
		if got := MigrateWPCronCrontabs(cfg); got != 0 {
			t.Errorf("migration must be gated on the fix_wp_cron opt-in, got %d upgrades", got)
		}
	}
	if len(rec.installs) != 0 {
		t.Errorf("no crontab installs expected when opted out, got %v", rec.installs)
	}
}

func TestMigrateWPCronCrontabsSkipsUnsafeDocroots(t *testing.T) {
	spool := t.TempDir()
	withWPCronSpoolDirs(t, spool)
	// A tampered marker must not drive a crontab rewrite for a relative or
	// dot-dot docroot.
	tampered := "# CSM WP-Cron ../../../etc\n" +
		"*/5 * * * * cd '../../../etc' && '/usr/local/bin/php' -d max_execution_time=300 wp-cron.php >/dev/null 2>&1\n" +
		"# CSM WP-Cron relative/path\n" +
		"*/5 * * * * cd 'relative/path' && '/usr/local/bin/php' -d max_execution_time=300 wp-cron.php >/dev/null 2>&1\n"
	if err := os.WriteFile(filepath.Join(spool, "alice"), []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := &migrateCrontabMock{crontabs: map[string]string{"alice": tampered}, installs: map[string]string{}}
	withMockCmd(t, rec.mock())

	if got := MigrateWPCronCrontabs(wpCronMigrateConfig()); got != 0 {
		t.Errorf("unsafe docroots must be skipped, got %d upgrades", got)
	}
	if len(rec.installs) != 0 {
		t.Errorf("no installs expected for unsafe docroots, got %v", rec.installs)
	}
}
