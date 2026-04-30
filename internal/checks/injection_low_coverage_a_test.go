package checks

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// ===========================================================================
// performance.go helpers
// ===========================================================================

func TestHumanBytesAllBranches(t *testing.T) {
	cases := []struct {
		input int64
		want  string
	}{
		{0, "0B"},
		{512, "0B"},
		{2048, "2K"},
		{5 * 1024 * 1024, "5M"},
		{2 * 1024 * 1024 * 1024, "2.0G"},
	}
	for _, tc := range cases {
		got := humanBytes(tc.input)
		if got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestParseMemoryLimitAllSuffixes(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"256M", 256},
		{"1G", 1024},
		{"8192K", 8},
		{"-1", 0},
		{"", 0},
		{"invalid", 0},
		{"512", 512},
	}
	for _, tc := range cases {
		got := parseMemoryLimit(tc.input)
		if got != tc.want {
			t.Errorf("parseMemoryLimit(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestExtractPHPDefineVariousFormats(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{`define('WP_MEMORY_LIMIT', '256M');`, "256M"},
		{`define("DB_NAME", "mydb");`, "mydb"},
		{`define('DISABLE_WP_CRON', 'true');`, "true"},
		{`define('KEY')`, ""}, // no comma
		{`nocall`, ""},        // no paren
		{`define('K', '');`, ""},
	}
	for _, tc := range cases {
		got := extractPHPDefine(tc.line)
		if got != tc.want {
			t.Errorf("extractPHPDefine(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}

func TestPerfEnabledNilAndExplicit(t *testing.T) {
	cfg := &config.Config{}
	if !perfEnabled(cfg) {
		t.Error("nil Enabled should be treated as true")
	}

	boolTrue := true
	cfg.Performance.Enabled = &boolTrue
	if !perfEnabled(cfg) {
		t.Error("explicit true should be enabled")
	}

	boolFalse := false
	cfg.Performance.Enabled = &boolFalse
	if perfEnabled(cfg) {
		t.Error("explicit false should be disabled")
	}
}

func TestParseLoadAvgBadFormat(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/loadavg" {
				return []byte("bad data"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	_, err := parseLoadAvg()
	if err == nil {
		t.Error("expected error for bad format")
	}
}

func TestParseLoadAvgTooFewFields(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/loadavg" {
				return []byte("1.0 2.0"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	_, err := parseLoadAvg()
	if err == nil {
		t.Error("expected error for too few fields")
	}
}

func TestParseLoadAvgValid(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/loadavg" {
				return []byte("2.50 1.25 0.75 1/200 12345"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	loads, err := parseLoadAvg()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loads[0] != 2.50 || loads[1] != 1.25 || loads[2] != 0.75 {
		t.Errorf("got %v", loads)
	}
}

func TestAccountFromPathVariousShapes(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/home/alice/public_html", "alice"},
		{"/var/www/mysite", "www"},
		{"/srv/http/site", "http"},
	}
	for _, tc := range cases {
		got := accountFromPath(tc.path)
		if got != tc.want {
			t.Errorf("accountFromPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestSafeIdentifierCases(t *testing.T) {
	if !safeIdentifier("wp_") {
		t.Error("wp_ should be safe")
	}
	if safeIdentifier("") {
		t.Error("empty should be unsafe")
	}
	if safeIdentifier("DROP TABLE;") {
		t.Error("SQL injection should be unsafe")
	}
}

// ===========================================================================
// performance.go -- CheckLoadAverage branches
// ===========================================================================

func TestCheckLoadAverageCriticalThreshold(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/loadavg" {
				return []byte("100.0 80.0 60.0 1/200 12345"), nil
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if name == "/proc/cpuinfo" {
				tmp := t.TempDir() + "/cpuinfo"
				_ = os.WriteFile(tmp, []byte("processor\t: 0\n"), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	cfg.Performance.LoadCriticalMultiplier = 5.0
	cfg.Performance.LoadHighMultiplier = 3.0

	findings := CheckLoadAverage(context.Background(), cfg, nil)
	found := false
	for _, f := range findings {
		if f.Severity == alert.Critical && strings.Contains(f.Message, "critical") {
			found = true
		}
	}
	if !found {
		t.Error("expected critical finding for load 100 with 1 core")
	}
}

func TestCheckLoadAverageHighThreshold(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/loadavg" {
				// Use very high load to ensure it exceeds high threshold
				// regardless of cached core count from sync.Once
				return []byte("500.0 300.0 200.0 1/200 12345"), nil
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if name == "/proc/cpuinfo" {
				tmp := t.TempDir() + "/cpuinfo"
				_ = os.WriteFile(tmp, []byte("processor\t: 0\n"), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	cores := getCPUCores() // read actual cached core count
	cfg := &config.Config{}
	// Set critical impossibly high so we only trigger high
	cfg.Performance.LoadCriticalMultiplier = 10000.0
	// Set high so 500 > cores*multiplier
	cfg.Performance.LoadHighMultiplier = 400.0 / float64(cores)

	findings := CheckLoadAverage(context.Background(), cfg, nil)
	found := false
	for _, f := range findings {
		if f.Severity == alert.High && strings.Contains(f.Message, "high") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected high finding for load 500 with %d cores", cores)
	}
}

func TestCheckLoadAverageDisabledByConfig(t *testing.T) {
	disabled := false
	cfg := &config.Config{}
	cfg.Performance.Enabled = &disabled
	findings := CheckLoadAverage(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Error("disabled config should produce no findings")
	}
}

// ===========================================================================
// performance.go -- CheckPHPProcessLoad with lsphp processes
// ===========================================================================

func TestCheckPHPProcessLoadCriticalTotal(t *testing.T) {
	var paths []string
	for i := 0; i < 20; i++ {
		paths = append(paths, fmt.Sprintf("/proc/%d/cmdline", 2000+i))
	}

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "cmdline") {
				return paths, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "cmdline") {
				return []byte("lsphp: worker\x00"), nil
			}
			if strings.HasSuffix(name, "status") {
				return []byte("Name:\tlsphp\nUid:\t1000\t1000\t1000\t1000\n"), nil
			}
			if name == "/etc/passwd" {
				return []byte("alice:x:1000:1000::/home/alice:/bin/bash\n"), nil
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if name == "/proc/cpuinfo" {
				tmp := t.TempDir() + "/cpuinfo"
				_ = os.WriteFile(tmp, []byte("processor\t: 0\n"), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	cfg.Performance.PHPProcessCriticalTotalMult = 2
	cfg.Performance.PHPProcessWarnPerUser = 5

	findings := CheckPHPProcessLoad(context.Background(), cfg, nil)
	hasCritTotal := false
	hasPerUser := false
	for _, f := range findings {
		if f.Severity == alert.Critical && strings.Contains(f.Message, "Total lsphp") {
			hasCritTotal = true
		}
		if f.Severity == alert.High && strings.Contains(f.Message, "Excessive lsphp") {
			hasPerUser = true
		}
	}
	if !hasCritTotal {
		t.Error("expected critical finding for total lsphp exceeding threshold")
	}
	if !hasPerUser {
		t.Error("expected high finding for per-user lsphp exceeding threshold")
	}
}

// ===========================================================================
// performance.go -- CheckSwapAndOOM ISO dmesg parsing
// ===========================================================================

func TestCheckSwapAndOOMIsoTimestampRecent(t *testing.T) {
	now := time.Now()
	ts := now.Format("2006-01-02T15:04:05,000000-0700")

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/proc/meminfo" {
				tmp := t.TempDir() + "/meminfo"
				_ = os.WriteFile(tmp, []byte("MemTotal: 4096000 kB\nMemAvailable: 2048000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "dmesg" {
				for _, a := range args {
					if a == "iso" {
						return []byte(ts + " Out of memory: Killed process 1234\n"), nil
					}
				}
				return nil, fmt.Errorf("no iso support")
			}
			return nil, nil
		},
	})

	findings := CheckSwapAndOOM(context.Background(), &config.Config{}, nil)
	hasOOM := false
	for _, f := range findings {
		if f.Severity == alert.Critical && strings.Contains(f.Message, "OOM") {
			hasOOM = true
		}
	}
	if !hasOOM {
		t.Error("expected OOM finding for recent ISO timestamp")
	}
}

func TestCheckSwapAndOOMHighSwapUsage(t *testing.T) {
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/proc/meminfo" {
				tmp := t.TempDir() + "/meminfo"
				data := "MemTotal: 4096000 kB\nMemAvailable: 2048000 kB\nSwapTotal: 1000000 kB\nSwapFree: 100000 kB\n"
				_ = os.WriteFile(tmp, []byte(data), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return []byte(""), nil
		},
	})

	findings := CheckSwapAndOOM(context.Background(), &config.Config{}, nil)
	hasSwap := false
	for _, f := range findings {
		if strings.Contains(f.Message, "swap") || strings.Contains(f.Message, "Swap") {
			hasSwap = true
		}
	}
	if !hasSwap {
		t.Error("expected swap finding for 90% usage")
	}
}

// ===========================================================================
// performance.go -- CheckPHPHandler LiteSpeed + CGI detection
// ===========================================================================

func TestCheckPHPHandlerWHMAPICGI(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == "/usr/local/lsws/bin/litespeed" {
				return fakeFileInfo{name: "litespeed"}, nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "whmapi1" {
				return []byte(`{"data":{"handlers":[{"version":"ea-php82","handler":"cgi","type":"cgi"}]}}`), nil
			}
			return nil, nil
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	findings := CheckPHPHandler(context.Background(), &config.Config{}, store)
	if len(findings) == 0 {
		t.Error("expected critical finding for CGI handler on LiteSpeed")
	}
	for _, f := range findings {
		if f.Severity != alert.Critical {
			t.Errorf("expected critical severity, got %v", f.Severity)
		}
	}
}

func TestCheckPHPHandlerEA4ConfFallback(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == "/usr/local/lsws/bin/litespeed" {
				return fakeFileInfo{name: "litespeed"}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/cpanel/ea4/ea4.conf" {
				return []byte("ea-php74.handler = cgi\nea-php82.handler = lsapi\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return nil, fmt.Errorf("command not found")
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	findings := CheckPHPHandler(context.Background(), &config.Config{}, store)
	if len(findings) == 0 {
		t.Error("expected finding for ea-php74 CGI handler in ea4.conf")
	}
}

// ===========================================================================
// performance.go -- CheckMySQLConfig all variable branches
// ===========================================================================

func TestCheckMySQLConfigAllBranches(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name != "mysql" {
				return nil, nil
			}
			for _, a := range args {
				if strings.Contains(a, "SHOW GLOBAL VARIABLES") {
					return []byte(
						"join_buffer_size\t8388608\n" +
							"wait_timeout\t86400\n" +
							"interactive_timeout\t86400\n" +
							"max_user_connections\t0\n" +
							"slow_query_log\tOFF\n",
					), nil
				}
				if strings.Contains(a, "SHOW GLOBAL STATUS") {
					return []byte(
						"Innodb_buffer_pool_read_requests\t1000\n" +
							"Innodb_buffer_pool_reads\t200\n" +
							"Created_tmp_disk_tables\t400\n" +
							"Created_tmp_tables\t1000\n",
					), nil
				}
				if strings.Contains(a, "SHOW PROCESSLIST") {
					lines := ""
					for i := 0; i < 60; i++ {
						lines += fmt.Sprintf("%d\tbiguser\tlocalhost\twpdb\tQuery\t%d\tsending data\tSELECT 1\n", i, i)
					}
					return []byte(lines), nil
				}
			}
			return nil, nil
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	cfg := &config.Config{}
	cfg.Performance.MySQLJoinBufferMaxMB = 4
	cfg.Performance.MySQLWaitTimeoutMax = 3600
	cfg.Performance.MySQLMaxConnectionsPerUser = 50

	findings := CheckMySQLConfig(context.Background(), cfg, store)

	checks := map[string]bool{
		"join_buffer_size exceeds": false,
		"wait_timeout is too high": false,
		"interactive_timeout":      false,
		"max_user_connections":     false,
		"slow query log":           false,
		"buffer pool hit ratio":    false,
		"temporary tables on disk": false,
		"holding excessive":        false,
	}
	for _, f := range findings {
		for key := range checks {
			if strings.Contains(f.Message, key) {
				checks[key] = true
			}
		}
	}
	for key, found := range checks {
		if !found {
			t.Errorf("missing finding containing %q", key)
		}
	}
}

// ===========================================================================
// performance.go -- CheckRedisConfig all branches
// ===========================================================================

func TestCheckRedisConfigAllBranches(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == "/usr/bin/redis-cli" {
				return fakeFileInfo{name: "redis-cli"}, nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name != "/usr/bin/redis-cli" {
				return nil, nil
			}
			if len(args) >= 3 {
				switch args[2] {
				case "maxmemory":
					return []byte("maxmemory\n0\n"), nil
				case "maxmemory-policy":
					return []byte("maxmemory-policy\nnoeviction\n"), nil
				case "save":
					return []byte("save\n60 1000\n"), nil
				}
			}
			if len(args) >= 2 {
				switch args[1] {
				case "keyspace":
					return []byte("# Keyspace\ndb0:keys=10000,expires=100,avg_ttl=5000\n"), nil
				case "memory":
					return []byte("used_memory:5368709120\nused_memory_human:5.00G\n"), nil
				}
			}
			return nil, nil
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	cfg := &config.Config{}
	cfg.Performance.RedisLargeDatasetGB = 1
	cfg.Performance.RedisBgsaveMinInterval = 300

	findings := CheckRedisConfig(context.Background(), cfg, store)

	checks := map[string]bool{
		"maxmemory is not set": false,
		"noeviction":           false,
		"non-expiring keys":    false,
		"bgsave interval":      false,
	}
	for _, f := range findings {
		for key := range checks {
			if strings.Contains(f.Message, key) {
				checks[key] = true
			}
		}
	}
	for key, found := range checks {
		if !found {
			t.Errorf("missing Redis finding: %q", key)
		}
	}
}

// ===========================================================================
// performance.go -- scanWPConfigs with excessive memory and insecure config
// ===========================================================================

func TestScanWPConfigsExcessiveMemoryAndInsecure(t *testing.T) {
	wpConfig := "<?php\ndefine('WP_MEMORY_LIMIT', '1G');\n"
	htaccess := "max_execution_time = 0\ndisplay_errors = On\n"

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			return []os.DirEntry{
				testDirEntry{name: "wp-config.php", isDir: false},
				testDirEntry{name: ".htaccess", isDir: false},
			}, nil
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				return []byte(wpConfig), nil
			}
			if strings.HasSuffix(name, ".htaccess") {
				return []byte(htaccess), nil
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	cfg.Performance.WPMemoryLimitMaxMB = 512

	var findings []alert.Finding
	scanWPConfigs("/home/alice/public_html", "alice", cfg, 2, &findings)

	hasMemory := false
	hasExecTime := false
	hasDisplay := false
	for _, f := range findings {
		if strings.Contains(f.Message, "WP_MEMORY_LIMIT") {
			hasMemory = true
		}
		if strings.Contains(f.Message, "max_execution_time") {
			hasExecTime = true
		}
		if strings.Contains(f.Message, "display_errors") {
			hasDisplay = true
		}
	}
	if !hasMemory {
		t.Error("expected finding for excessive WP_MEMORY_LIMIT")
	}
	if !hasExecTime {
		t.Error("expected finding for max_execution_time=0")
	}
	if !hasDisplay {
		t.Error("expected finding for display_errors=On")
	}
}

// ===========================================================================
// performance.go -- scanWPCron
// ===========================================================================

func TestScanWPCronNotDisabled(t *testing.T) {
	wpConfig := "<?php\ndefine('DB_NAME','wp');\n"

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			return []os.DirEntry{testDirEntry{name: "wp-config.php", isDir: false}}, nil
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				return []byte(wpConfig), nil
			}
			return nil, os.ErrNotExist
		},
	})

	var findings []alert.Finding
	scanWPCron("/home/alice/public_html", "alice", 2, &findings)
	if len(findings) == 0 {
		t.Error("expected warning for WP-Cron not disabled")
	}
}

func TestScanWPCronDisabledTrue(t *testing.T) {
	wpConfig := "<?php\ndefine('DISABLE_WP_CRON', 'true');\n"

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			return []os.DirEntry{testDirEntry{name: "wp-config.php", isDir: false}}, nil
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				return []byte(wpConfig), nil
			}
			return nil, os.ErrNotExist
		},
	})

	var findings []alert.Finding
	scanWPCron("/home/alice/public_html", "alice", 2, &findings)
	if len(findings) != 0 {
		t.Error("DISABLE_WP_CRON=true should produce no findings")
	}
}

func TestScanWPCronDisabledFalse(t *testing.T) {
	wpConfig := "<?php\ndefine('DISABLE_WP_CRON', 'false');\n"

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			return []os.DirEntry{testDirEntry{name: "wp-config.php", isDir: false}}, nil
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				return []byte(wpConfig), nil
			}
			return nil, os.ErrNotExist
		},
	})

	var findings []alert.Finding
	scanWPCron("/home/alice/public_html", "alice", 2, &findings)
	if len(findings) == 0 {
		t.Error("DISABLE_WP_CRON=false should produce a warning")
	}
}

// ===========================================================================
// performance.go -- scanErrorLogs depth and skip dirs
// ===========================================================================

func TestScanErrorLogsSkipsDirs(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			return []os.DirEntry{
				testDirEntry{name: "cache", isDir: true},
				testDirEntry{name: "node_modules", isDir: true},
				testDirEntry{name: "error_log", isDir: false},
			}, nil
		},
	})

	var findings []alert.Finding
	// testDirEntry.Info() returns size=100, use threshold > 100 so error_log is not "bloated"
	scanErrorLogs("/home/alice/public_html", 1024, 3, &findings)
	if len(findings) != 0 {
		t.Error("small error_log should not produce findings")
	}
}

func TestScanErrorLogsDepthExhausted(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			return []os.DirEntry{testDirEntry{name: "error_log", isDir: false}}, nil
		},
	})

	var findings []alert.Finding
	scanErrorLogs("/home/alice/public_html", 1, -1, &findings)
	if len(findings) != 0 {
		t.Error("negative depth should not scan anything")
	}
}

// ===========================================================================
// performance.go -- findWPTransients with transient data
// ===========================================================================

func TestFindWPTransientsWithResults(t *testing.T) {
	wpConfig := "<?php\ndefine('DB_NAME','testdb');\ndefine('DB_USER','testuser');\ndefine('DB_PASSWORD','pass');\ndefine('DB_HOST','localhost');\n$table_prefix = 'wp_';\n"

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			return []os.DirEntry{testDirEntry{name: "wp-config.php", isDir: false}}, nil
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				return []byte(wpConfig), nil
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				tmp := t.TempDir() + "/wp-config.php"
				_ = os.WriteFile(tmp, []byte(wpConfig), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			return []byte(
				"_transient_big_cache\t20000000\n" +
					"_transient_medium_cache\t3000000\n",
			), nil
		},
	})

	cfg := &config.Config{}
	warnBytes := int64(1) * 1024 * 1024
	critBytes := int64(10) * 1024 * 1024

	var findings []alert.Finding
	findWPTransients("/home/alice/public_html", cfg, warnBytes, critBytes, 2, &findings)

	hasHigh := false
	hasWarn := false
	for _, f := range findings {
		if f.Severity == alert.High {
			hasHigh = true
		}
		if f.Severity == alert.Warning {
			hasWarn = true
		}
	}
	if !hasHigh {
		t.Error("expected High finding for 20MB transient")
	}
	if !hasWarn {
		t.Error("expected Warning finding for 3MB transient")
	}
}

// ===========================================================================
// web.go -- checkHtaccessFile
// ===========================================================================

func TestCheckHtaccessFileSuspiciousDirectives(t *testing.T) {
	content := "auto_prepend_file /tmp/evil.php\nphp_value disable_functions none\n"
	tmp := t.TempDir() + "/.htaccess"
	_ = os.WriteFile(tmp, []byte(content), 0644)

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			return os.Open(tmp)
		},
	})

	suspicious := []string{"auto_prepend_file", "php_value disable_functions"}
	safe := []string{"wordfence-waf.php"}

	var findings []alert.Finding
	checkHtaccessFile(tmp, suspicious, safe, &findings)
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(findings))
	}
}

func TestCheckHtaccessFileCommentSkipped(t *testing.T) {
	content := "# auto_prepend_file /tmp/evil.php\n"
	tmp := t.TempDir() + "/.htaccess"
	_ = os.WriteFile(tmp, []byte(content), 0644)

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			return os.Open(tmp)
		},
	})

	var findings []alert.Finding
	checkHtaccessFile(tmp, []string{"auto_prepend_file"}, nil, &findings)
	if len(findings) != 0 {
		t.Error("commented lines should not produce findings")
	}
}

func TestCheckHtaccessFileSafePatternWordfence(t *testing.T) {
	content := "auto_prepend_file wordfence-waf.php\n"
	tmp := t.TempDir() + "/.htaccess"
	_ = os.WriteFile(tmp, []byte(content), 0644)

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			return os.Open(tmp)
		},
	})

	var findings []alert.Finding
	checkHtaccessFile(tmp, []string{"auto_prepend_file"}, []string{"wordfence-waf.php"}, &findings)
	if len(findings) != 0 {
		t.Error("wordfence-waf.php should be safe")
	}
}

func TestCheckHtaccessFileExecCGIBlock(t *testing.T) {
	content := "Options -ExecCGI\nSetHandler application/x-httpd-php\n"
	tmp := t.TempDir() + "/.htaccess"
	_ = os.WriteFile(tmp, []byte(content), 0644)

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			return os.Open(tmp)
		},
	})

	var findings []alert.Finding
	checkHtaccessFile(tmp, []string{"sethandler"}, []string{"-execcgi"}, &findings)
	if len(findings) != 0 {
		t.Error("SetHandler with -ExecCGI block should not flag")
	}
}

func TestCheckHtaccessFileAddHandlerDangerousExt(t *testing.T) {
	content := "AddHandler cgi-script .haxor\n"
	tmp := t.TempDir() + "/.htaccess"
	_ = os.WriteFile(tmp, []byte(content), 0644)

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			return os.Open(tmp)
		},
	})

	var findings []alert.Finding
	checkHtaccessFile(tmp, []string{"addhandler"}, []string{}, &findings)

	hasAbuse := false
	for _, f := range findings {
		if f.Check == "htaccess_handler_abuse" && strings.Contains(f.Message, ".haxor") {
			hasAbuse = true
		}
	}
	if !hasAbuse {
		t.Error("expected htaccess_handler_abuse finding for .haxor extension")
	}
}

func TestCheckHtaccessFileAddTypeStandardMIME(t *testing.T) {
	content := "AddType application/javascript .js\n"
	tmp := t.TempDir() + "/.htaccess"
	_ = os.WriteFile(tmp, []byte(content), 0644)

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			return os.Open(tmp)
		},
	})

	var findings []alert.Finding
	checkHtaccessFile(tmp, []string{"addtype"}, nil, &findings)
	if len(findings) != 0 {
		t.Error("AddType with standard MIME should not flag")
	}
}

func TestCheckHtaccessFileSetHandlerNone(t *testing.T) {
	content := "SetHandler none\n"
	tmp := t.TempDir() + "/.htaccess"
	_ = os.WriteFile(tmp, []byte(content), 0644)

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			return os.Open(tmp)
		},
	})

	var findings []alert.Finding
	checkHtaccessFile(tmp, []string{"sethandler"}, nil, &findings)
	if len(findings) != 0 {
		t.Error("SetHandler none is a security measure, should not flag")
	}
}

func TestCheckHtaccessFileAddHandlerStandardCGI(t *testing.T) {
	content := "AddHandler cgi-script .cgi .pl\n"
	tmp := t.TempDir() + "/.htaccess"
	_ = os.WriteFile(tmp, []byte(content), 0644)

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			return os.Open(tmp)
		},
	})

	var findings []alert.Finding
	checkHtaccessFile(tmp, []string{"addhandler"}, nil, &findings)
	if len(findings) != 0 {
		t.Error("AddHandler for .cgi/.pl should not flag as suspicious")
	}
}

func TestCheckHtaccessFileDrupalSecurity(t *testing.T) {
	content := "SetHandler drupal_security_do_not_remove\n"
	tmp := t.TempDir() + "/.htaccess"
	_ = os.WriteFile(tmp, []byte(content), 0644)

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			return os.Open(tmp)
		},
	})

	var findings []alert.Finding
	checkHtaccessFile(tmp, []string{"sethandler"}, nil, &findings)
	if len(findings) != 0 {
		t.Error("Drupal security handler should not be flagged")
	}
}

// ===========================================================================
// web.go -- extractUser
// ===========================================================================

func TestExtractUserFromPathVariants(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/home/alice/public_html", "alice"},
		{"/var/www/html", "unknown"},
		{"/home/bob", "bob"},
	}
	for _, tc := range cases {
		got := extractUser(tc.path)
		if got != tc.want {
			t.Errorf("extractUser(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// ===========================================================================
// web.go -- CheckWPCore with verification failure
// ===========================================================================

func TestCheckWPCoreVerificationFailure(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "wp-config.php") {
				return []string{"/home/alice/public_html/wp-config.php"}, nil
			}
			return nil, nil
		},
	})
	withMockCmd(t, &mockCmd{
		runContext: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name == "wp" {
				return []byte("Warning: File should not exist: wp-content/debug.php\n"), fmt.Errorf("exit 1")
			}
			return nil, nil
		},
	})

	findings := CheckWPCore(context.Background(), &config.Config{}, nil)
	hasIntegrity := false
	for _, f := range findings {
		if f.Check == "wp_core_integrity" {
			hasIntegrity = true
		}
	}
	if !hasIntegrity {
		t.Error("expected wp_core_integrity finding for failed verification")
	}
}

// ===========================================================================
// emailscan.go -- scanEximMessage all indicator branches
//
// Each fixture below is a real cPanel-Exim -H spool blob: line 1 message-id,
// line 2 "<user> <uid> <gid>", line 3 envelope sender, line 4 "<seconds>
// <usec>", optional "-flag" lines, recipient count, recipient(s), blank line
// separator, then RFC 5322 headers prefixed with "NNNX " (3 digits + flag
// or space + space). The earlier inline "From: ...\n" mocks were aspirational;
// the real spool format is what production scanEximMessage now consumes via
// internal/emailspool.
// ===========================================================================

// eximSpool builds a minimal but parseable cPanel-Exim -H blob with the given
// RFC 5322 header lines (each line MUST be in NNNX form already, e.g.
// "048F From: alice@example.com"). Used by the TestScanEximMessage* fixtures
// below.
func eximSpool(headerLines ...string) string {
	body := "msg-H\n" +
		"alice 1000 1000\n" +
		"<alice@example.com>\n" +
		"1700000000 0\n" +
		"-local\n" +
		"1\n" +
		"recipient@example.com\n" +
		"\n"
	for _, ln := range headerLines {
		body += ln + "\n"
	}
	return body
}

func TestScanEximMessageReplyToMismatch(t *testing.T) {
	headers := eximSpool(
		"048F From: alice@example.com",
		"039R Reply-To: attacker@evil.com",
	)

	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if strings.HasSuffix(name, "-H") {
				return fakeFileInfo{name: "msg-H"}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "-H") {
				return []byte(headers), nil
			}
			if strings.HasSuffix(name, "-D") {
				return []byte("Normal email body content."), nil
			}
			return nil, os.ErrNotExist
		},
	})

	result := scanEximMessage("ABC123", "alice@example.com", &config.Config{})
	if result == nil {
		t.Fatal("expected finding for Reply-To mismatch")
	}
	if !strings.Contains(result.Details, "Reply-To mismatch") {
		t.Errorf("expected Reply-To mismatch indicator, got: %s", result.Details)
	}
}

func TestScanEximMessageSuspiciousMailer(t *testing.T) {
	headers := eximSpool(
		"049F From: sender@example.com",
		"030  X-Mailer: PHPMailer 6.0",
	)

	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if strings.HasSuffix(name, "-H") {
				return fakeFileInfo{name: "msg-H"}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "-H") {
				return []byte(headers), nil
			}
			if strings.HasSuffix(name, "-D") {
				return []byte("Normal body"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	result := scanEximMessage("ABC123", "sender@example.com", &config.Config{})
	if result == nil {
		t.Fatal("expected finding for suspicious mailer")
	}
	if !strings.Contains(result.Details, "suspicious mailer") {
		t.Errorf("expected suspicious mailer indicator, got: %s", result.Details)
	}
}

func TestScanEximMessageSpoofedBrand(t *testing.T) {
	headers := eximSpool(
		"055F From: PayPal Security <noreply@randomsite.com>",
	)

	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if strings.HasSuffix(name, "-H") {
				return fakeFileInfo{name: "msg-H"}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "-H") {
				return []byte(headers), nil
			}
			if strings.HasSuffix(name, "-D") {
				return []byte(""), nil
			}
			return nil, os.ErrNotExist
		},
	})

	result := scanEximMessage("ABC123", "noreply@randomsite.com", &config.Config{})
	if result == nil {
		t.Fatal("expected finding for spoofed brand")
	}
	if !strings.Contains(result.Details, "spoofed brand") {
		t.Errorf("expected spoofed brand indicator, got: %s", result.Details)
	}
}

func TestScanEximMessagePhishingURLsAndLanguage(t *testing.T) {
	headers := eximSpool(
		"049F From: sender@example.com",
	)
	body := "Please verify your account at https://evil.workers.dev/login " +
		"confirm your identity or your account will be suspended unless you act now " +
		"click here to verify"

	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if strings.HasSuffix(name, "-H") {
				return fakeFileInfo{name: "msg-H"}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "-H") {
				return []byte(headers), nil
			}
			if strings.HasSuffix(name, "-D") {
				return []byte(body), nil
			}
			return nil, os.ErrNotExist
		},
	})

	result := scanEximMessage("ABC123", "sender@example.com", &config.Config{})
	if result == nil {
		t.Fatal("expected finding for phishing content")
	}
	if !strings.Contains(result.Details, "phishing URL") {
		t.Error("expected phishing URL indicator")
	}
	if !strings.Contains(result.Details, "credential harvesting") {
		t.Error("expected credential harvesting indicator")
	}
}

func TestScanEximMessageBase64HTML(t *testing.T) {
	headers := eximSpool(
		"049F From: sender@example.com",
		"048  Content-Transfer-Encoding: base64",
		"030  Content-Type: text/html",
	)

	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if strings.HasSuffix(name, "-H") {
				return fakeFileInfo{name: "msg-H"}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "-H") {
				return []byte(headers), nil
			}
			if strings.HasSuffix(name, "-D") {
				return []byte("PGh0bWw+"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	result := scanEximMessage("ABC123", "sender@example.com", &config.Config{})
	if result == nil {
		t.Fatal("expected finding for base64 HTML")
	}
	if !strings.Contains(result.Details, "base64-encoded HTML") {
		t.Errorf("expected base64 HTML indicator, got: %s", result.Details)
	}
}

func TestScanEximMessageCriticalSeverity(t *testing.T) {
	headers := eximSpool(
		"055F From: PayPal Security <noreply@randomsite.com>",
		"036R Reply-To: hacker@evil.com",
		"025  X-Mailer: PHPMailer",
	)
	body := "verify your account at https://evil.workers.dev confirm your identity your account will be suspended unless"

	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if strings.HasSuffix(name, "-H") {
				return fakeFileInfo{name: "msg-H"}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "-H") {
				return []byte(headers), nil
			}
			if strings.HasSuffix(name, "-D") {
				return []byte(body), nil
			}
			return nil, os.ErrNotExist
		},
	})

	result := scanEximMessage("ABC123", "noreply@randomsite.com", &config.Config{})
	if result == nil {
		t.Fatal("expected finding with multiple indicators")
	}
	if result.Severity != alert.Critical {
		t.Errorf("expected Critical severity for 3+ indicators, got %v", result.Severity)
	}
}

func TestScanEximMessageNoHeaders(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	})

	result := scanEximMessage("ABC123", "sender@example.com", &config.Config{})
	if result != nil {
		t.Error("expected nil for missing spool files")
	}
}

// ===========================================================================
// emailscan.go -- CheckOutboundEmailContent with exim_mainlog
// ===========================================================================

func TestCheckOutboundEmailContentParsesLog(t *testing.T) {
	// Regex: ^\S+\s+(\S+)\s+<=\s+(\S+) expects:
	// <timestamp> <msgID> <= <sender>
	logLines := "1681234567 ABC123 <= sender@example.com H=mail.example.com\n" +
		"1681234568 ABC123 => victim@target.com R=remote\n" +
		"1681234569 DEF456 <= <> H=bounce\n"

	headers := eximSpool(
		"048F From: PayPal <sender@example.com>",
		"036R Reply-To: hacker@evil.com",
	)

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "exim_mainlog") {
				tmp := t.TempDir() + "/exim_mainlog"
				_ = os.WriteFile(tmp, []byte(logLines), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if strings.Contains(name, "exim_mainlog") {
				return fakeFileInfo{name: "exim_mainlog", size: int64(len(logLines))}, nil
			}
			if strings.HasSuffix(name, "-H") {
				return fakeFileInfo{name: "ABC123-H"}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "-H") {
				return []byte(headers), nil
			}
			if strings.HasSuffix(name, "-D") {
				return []byte("Normal body"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckOutboundEmailContent(context.Background(), &config.Config{}, nil)
	if len(findings) == 0 {
		t.Error("expected findings from parsed exim log with Reply-To mismatch")
	}
}

// ===========================================================================
// phpconfig.go -- analyzePHPINI all branches
// ===========================================================================

func TestAnalyzePHPINIDisableFunctionsCleared(t *testing.T) {
	content := "disable_functions = \n"
	dangerous := analyzePHPINI(content)
	hasClear := false
	for _, d := range dangerous {
		if strings.Contains(d, "disable_functions cleared") {
			hasClear = true
		}
	}
	if !hasClear {
		t.Error("expected 'disable_functions cleared' for empty value")
	}
}

func TestAnalyzePHPINIDisableFunctionsNone(t *testing.T) {
	content := "disable_functions = none\n"
	dangerous := analyzePHPINI(content)
	hasClear := false
	for _, d := range dangerous {
		if strings.Contains(d, "disable_functions cleared") {
			hasClear = true
		}
	}
	if !hasClear {
		t.Error("expected 'disable_functions cleared' for 'none' value")
	}
}

func TestAnalyzePHPINIDisableFunctionsMissingDangerous(t *testing.T) {
	content := "disable_functions = phpinfo,getenv\n"
	dangerous := analyzePHPINI(content)
	hasExec := false
	for _, d := range dangerous {
		if strings.Contains(d, "exec not in disable_functions") {
			hasExec = true
		}
	}
	if !hasExec {
		t.Error("expected 'exec not in disable_functions'")
	}
}

func TestAnalyzePHPINIAllowURLInclude(t *testing.T) {
	content := "allow_url_include = on\n"
	dangerous := analyzePHPINI(content)
	hasRemote := false
	for _, d := range dangerous {
		if strings.Contains(d, "allow_url_include") {
			hasRemote = true
		}
	}
	if !hasRemote {
		t.Error("expected allow_url_include warning")
	}
}

func TestAnalyzePHPINIOpenBasedirCleared(t *testing.T) {
	content := "open_basedir = /\n"
	dangerous := analyzePHPINI(content)
	hasBasedir := false
	for _, d := range dangerous {
		if strings.Contains(d, "open_basedir") {
			hasBasedir = true
		}
	}
	if !hasBasedir {
		t.Error("expected open_basedir warning for / value")
	}
}

func TestAnalyzePHPINICommentedLinesSkipped(t *testing.T) {
	content := "; disable_functions = \n# disable_functions = \n"
	dangerous := analyzePHPINI(content)
	for _, d := range dangerous {
		if strings.Contains(d, "disable_functions cleared") {
			t.Error("commented lines should not trigger disable_functions cleared")
		}
	}
}

// ===========================================================================
// phpconfig.go -- CheckPHPConfigChanges with real change detection
// ===========================================================================

func TestCheckPHPConfigChangesDetectsChange(t *testing.T) {
	callCount := 0
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.HasSuffix(name, "alice") {
				return []os.DirEntry{testDirEntry{name: "public_html", isDir: true}}, nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if strings.HasSuffix(name, ".user.ini") {
				return fakeFileInfo{name: ".user.ini"}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, ".user.ini") {
				callCount++
				if callCount <= 1 {
					return []byte("disable_functions = exec,system\n"), nil
				}
				return []byte("disable_functions = \nallow_url_include = on\nopen_basedir = /\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	findings1 := CheckPHPConfigChanges(context.Background(), &config.Config{}, store)
	if len(findings1) != 0 {
		t.Error("first run should not produce findings (baseline)")
	}

	findings2 := CheckPHPConfigChanges(context.Background(), &config.Config{}, store)
	if len(findings2) == 0 {
		t.Error("second run should detect dangerous config change")
	}
}

// ===========================================================================
// dns_ssl.go -- CheckDNSZoneChanges with zone file changes
// ===========================================================================

func TestCheckDNSZoneChangesTargetedChange(t *testing.T) {
	callCount := 0
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/var/named" {
				return []os.DirEntry{
					testDirEntry{name: "example.com.db", isDir: false},
					testDirEntry{name: "other.com.db", isDir: false},
					testDirEntry{name: "skip.txt", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, ".db") {
				callCount++
				if callCount <= 2 {
					return []byte("zone data v1"), nil
				}
				if strings.Contains(name, "example.com") {
					return []byte("zone data v2 CHANGED"), nil
				}
				return []byte("zone data v1"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	findings1 := CheckDNSZoneChanges(context.Background(), &config.Config{}, store)
	if len(findings1) != 0 {
		t.Error("first run should not produce findings")
	}

	findings2 := CheckDNSZoneChanges(context.Background(), &config.Config{}, store)
	if len(findings2) == 0 {
		t.Error("expected finding for changed DNS zone")
	}
	for _, f := range findings2 {
		if f.Check != "dns_zone_change" {
			t.Errorf("unexpected check: %s", f.Check)
		}
	}
}

func TestCheckDNSZoneChangesBulkSuppressed(t *testing.T) {
	callCount := 0
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/var/named" {
				var entries []os.DirEntry
				for i := 0; i < 10; i++ {
					entries = append(entries, testDirEntry{name: fmt.Sprintf("zone%d.db", i), isDir: false})
				}
				return entries, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, ".db") {
				callCount++
				if callCount <= 10 {
					return []byte("zone data v1"), nil
				}
				return []byte("zone data v2"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	_ = CheckDNSZoneChanges(context.Background(), &config.Config{}, store)

	findings := CheckDNSZoneChanges(context.Background(), &config.Config{}, store)
	if len(findings) != 0 {
		t.Error("bulk zone changes (>5) should be suppressed")
	}
}

// ===========================================================================
// dns_ssl.go -- CheckSSLCertIssuance with new log files
// ===========================================================================

func TestCheckSSLCertIssuanceNewActivity(t *testing.T) {
	callCount := 0
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/var/cpanel/logs/autossl" {
				callCount++
				if callCount <= 1 {
					return []os.DirEntry{
						testDirEntry{name: "autossl_20260410.log", isDir: false},
						testDirEntry{name: "autossl_20260411.log", isDir: false},
					}, nil
				}
				return []os.DirEntry{
					testDirEntry{name: "autossl_20260410.log", isDir: false},
					testDirEntry{name: "autossl_20260411.log", isDir: false},
					testDirEntry{name: "autossl_20260413.log", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "autossl") {
				tmp := t.TempDir() + "/autossl.log"
				content := "Certificate for example.com issued successfully\nSSL installed for test.com\n"
				_ = os.WriteFile(tmp, []byte(content), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	findings1 := CheckSSLCertIssuance(context.Background(), &config.Config{}, store)
	if len(findings1) != 0 {
		t.Error("first run should not produce findings (baseline)")
	}

	findings2 := CheckSSLCertIssuance(context.Background(), &config.Config{}, store)
	if len(findings2) == 0 {
		t.Error("expected findings for new SSL certificate issuance")
	}
	for _, f := range findings2 {
		if f.Check != "ssl_cert_issued" {
			t.Errorf("unexpected check: %s", f.Check)
		}
	}
}

func TestCheckSSLCertIssuanceNoChange(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/var/cpanel/logs/autossl" {
				return []os.DirEntry{
					testDirEntry{name: "autossl.log", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	_ = CheckSSLCertIssuance(context.Background(), &config.Config{}, store)
	findings := CheckSSLCertIssuance(context.Background(), &config.Config{}, store)
	if len(findings) != 0 {
		t.Error("same log count should not produce findings")
	}
}
