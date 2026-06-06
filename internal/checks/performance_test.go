package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/redisinfo"
	"github.com/pidginhost/csm/internal/state"
)

// dmesgMock returns a CmdRunner that fails the ISO dmesg probe (forcing the
// -T fallback) and answers the -T probe with the given line.
func dmesgMock(tLine string) *mockCmd {
	return &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name != "dmesg" {
				return nil, nil
			}
			for _, a := range args {
				if a == "iso" {
					return nil, fmt.Errorf("--time-format unsupported")
				}
			}
			return []byte(tLine), nil
		},
	}
}

func oomFinding(findings []alert.Finding) bool {
	for _, f := range findings {
		if f.Check == "perf_memory" && strings.Contains(f.Message, "OOM") {
			return true
		}
	}
	return false
}

func TestCheckSwapAndOOM_NonISOFallbackIgnoresStaleOOM(t *testing.T) {
	// Regression: the -T (non-ISO) dmesg fallback never time-filtered, so a
	// days-old OOM event fired a Critical every scan. The fallback must apply
	// the same 1-hour cutoff the ISO path uses.
	stale := "[Mon Jan  2 00:00:00 2017] Out of memory: Killed process 1234 (php)"
	withMockCmd(t, dmesgMock(stale))

	if oomFinding(CheckSwapAndOOM(context.Background(), testPerfConfig(), nil)) {
		t.Error("stale OOM event must not produce a finding via the -T fallback")
	}
}

func TestCheckSwapAndOOM_NonISOFallbackIgnoresUndatedOOM(t *testing.T) {
	undated := "[12345.678] Out of memory: Killed process 1234 (php)"
	withMockCmd(t, dmesgMock(undated))

	if oomFinding(CheckSwapAndOOM(context.Background(), testPerfConfig(), nil)) {
		t.Error("undated OOM event must not produce a finding via the -T fallback")
	}
}

func TestCheckSwapAndOOM_NonISOFallbackReportsRecentOOM(t *testing.T) {
	// A genuinely recent OOM in the -T fallback path must still fire.
	recent := fmt.Sprintf("[%s] Out of memory: Killed process 4321 (php)",
		time.Now().Add(-2*time.Minute).Format("Mon Jan _2 15:04:05 2006"))
	withMockCmd(t, dmesgMock(recent))

	if !oomFinding(CheckSwapAndOOM(context.Background(), testPerfConfig(), nil)) {
		t.Error("recent OOM event must produce a finding via the -T fallback")
	}
}

func testPerfConfig() *config.Config {
	cfg := &config.Config{}
	t := true
	cfg.Performance.Enabled = &t
	cfg.Performance.LoadHighMultiplier = 1.0
	cfg.Performance.LoadCriticalMultiplier = 2.0
	cfg.Performance.PHPProcessWarnPerUser = 20
	cfg.Performance.PHPProcessCriticalTotalMult = 5
	cfg.Performance.ErrorLogWarnSizeMB = 50
	cfg.Performance.MySQLJoinBufferMaxMB = 64
	cfg.Performance.MySQLWaitTimeoutMax = 3600
	cfg.Performance.MySQLMaxConnectionsPerUser = 10
	cfg.Performance.RedisBgsaveMinInterval = 900
	cfg.Performance.RedisLargeDatasetGB = 4
	cfg.Performance.WPMemoryLimitMaxMB = 512
	cfg.Performance.WPTransientWarnMB = 1
	cfg.Performance.WPTransientCriticalMB = 10
	cfg.StatePath = "/tmp/csm-test-perf"
	return cfg
}

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{0, "0B"},
		{512, "0B"},
		{1024, "1K"},
		{1048576, "1M"},
		{1073741824, "1.0G"},
		{23622320128, "22.0G"},
	}
	for _, tt := range tests {
		got := humanBytes(tt.input)
		if got != tt.expected {
			t.Errorf("humanBytes(%d) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestExtractPHPDefine(t *testing.T) {
	tests := []struct {
		line     string
		expected string
	}{
		{line: "define( 'DB_NAME', 'mydb' );", expected: "mydb"},
		{line: "define(\"DB_USER\", \"root\");", expected: "root"},
		{line: "define('DB_PASSWORD', 'p@ss');", expected: "p@ss"},
	}
	for _, tt := range tests {
		got := extractPHPDefine(tt.line)
		if got != tt.expected {
			t.Errorf("extractPHPDefine(%q) = %q, want %q", tt.line, got, tt.expected)
		}
	}
}

func TestSafeIdentifier(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"valid_name", true},
		{"user123", true},
		{"", false},
		{"'; DROP TABLE", false},
		{"name with spaces", false},
		{"semi;colon", false},
	}
	for _, tt := range tests {
		got := safeIdentifier(tt.input)
		if got != tt.valid {
			t.Errorf("safeIdentifier(%q) = %v, want %v", tt.input, got, tt.valid)
		}
	}
}

func TestPerfEnabled(t *testing.T) {
	t.Run("nil pointer defaults to enabled", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Performance.Enabled = nil
		if !perfEnabled(cfg) {
			t.Error("expected perfEnabled to return true when Enabled is nil")
		}
	})

	t.Run("false disables", func(t *testing.T) {
		cfg := &config.Config{}
		f := false
		cfg.Performance.Enabled = &f
		if perfEnabled(cfg) {
			t.Error("expected perfEnabled to return false when Enabled is false")
		}
	})

	t.Run("true enables", func(t *testing.T) {
		cfg := &config.Config{}
		tr := true
		cfg.Performance.Enabled = &tr
		if !perfEnabled(cfg) {
			t.Error("expected perfEnabled to return true when Enabled is true")
		}
	})
}

func TestCheckRedisConfigUsesRawUint64ForHeadroomRatio(t *testing.T) {
	redisinfo.SetMemoryUsageForTest(func(context.Context) (uint64, uint64, error) {
		return 1 << 63, (1 << 63) + (1 << 62), nil
	})
	redisinfo.SetKeyspaceStatsForTest(func(context.Context) (redisinfo.KeyspaceStat, error) {
		return redisinfo.KeyspaceStat{}, nil
	})
	redisinfo.SetConfigGetForTest(func(_ context.Context, name string) (string, error) {
		switch name {
		case "maxmemory":
			return "1", nil
		case "maxmemory-policy":
			return "allkeys-lru", nil
		default:
			return "", nil
		}
	})
	t.Cleanup(func() {
		redisinfo.SetMemoryUsageForTest(nil)
		redisinfo.SetKeyspaceStatsForTest(nil)
		redisinfo.SetConfigGetForTest(nil)
	})

	findings := CheckRedisConfig(context.Background(), testPerfConfig(), nil)
	for _, finding := range findings {
		if strings.Contains(finding.Message, "Redis used memory") {
			t.Fatalf("unexpected Redis memory headroom finding for 66.7%% usage: %+v", finding)
		}
	}
}

// redisNonExpiringFixture wires a Redis with maxmemory set, a given eviction
// policy, and a 98.9% non-expiring keyspace (the cluster6 shape).
func redisNonExpiringFixture(t *testing.T, policy string) []alert.Finding {
	return redisNonExpiringFixtureWithPolicyError(t, policy, nil)
}

func redisNonExpiringFixtureWithPolicyError(t *testing.T, policy string, policyErr error) []alert.Finding {
	t.Helper()
	redisinfo.SetMemoryUsageForTest(func(context.Context) (uint64, uint64, error) {
		return 502 << 20, 22 << 30, nil // 502M used / 22G max -> tons of headroom
	})
	redisinfo.SetKeyspaceStatsForTest(func(context.Context) (redisinfo.KeyspaceStat, error) {
		return redisinfo.KeyspaceStat{TotalKeys: 826095, TotalExpires: 8934}, nil
	})
	redisinfo.SetConfigGetForTest(func(_ context.Context, name string) (string, error) {
		switch name {
		case "maxmemory":
			return "23622320128", nil
		case "maxmemory-policy":
			return policy, policyErr
		default:
			return "", nil
		}
	})
	t.Cleanup(func() {
		redisinfo.SetMemoryUsageForTest(nil)
		redisinfo.SetKeyspaceStatsForTest(nil)
		redisinfo.SetConfigGetForTest(nil)
	})
	return CheckRedisConfig(context.Background(), testPerfConfig(), nil)
}

func nonExpiringFinding(findings []alert.Finding) (alert.Finding, bool) {
	for _, f := range findings {
		if strings.Contains(f.Message, "non-expiring keys") {
			return f, true
		}
	}
	return alert.Finding{}, false
}

func hasNonExpiringFinding(findings []alert.Finding) bool {
	_, ok := nonExpiringFinding(findings)
	return ok
}

// allkeys-* policies evict any key under pressure, so a high non-expiring
// ratio is harmless: the warning is a false alarm and must be suppressed.
func TestCheckRedisConfig_NonExpiringSuppressedUnderAllkeysPolicy(t *testing.T) {
	for _, policy := range []string{"allkeys-lru", "allkeys-lfu", "allkeys-random"} {
		if hasNonExpiringFinding(redisNonExpiringFixture(t, policy)) {
			t.Errorf("policy %s: non-expiring warning must be suppressed (allkeys-* evicts non-TTL keys)", policy)
		}
	}
}

// volatile-* policies evict only keys carrying a TTL. A 98.9% non-expiring
// ratio shrinks the eviction pool to almost nothing, so the instance behaves
// like noeviction under memory pressure -> the warning must still fire.
func TestCheckRedisConfig_NonExpiringWarnsUnderVolatilePolicy(t *testing.T) {
	for _, policy := range []string{"volatile-lru", "volatile-lfu", "volatile-ttl", "volatile-random"} {
		if !hasNonExpiringFinding(redisNonExpiringFixture(t, policy)) {
			t.Errorf("policy %s: non-expiring warning must fire (volatile-* cannot evict non-TTL keys)", policy)
		}
	}
}

// noeviction cannot evict at all; the non-expiring ratio compounds the risk,
// so the warning fires alongside the dedicated noeviction finding.
func TestCheckRedisConfig_NonExpiringWarnsUnderNoeviction(t *testing.T) {
	if !hasNonExpiringFinding(redisNonExpiringFixture(t, "noeviction")) {
		t.Error("noeviction: non-expiring warning must fire")
	}
}

func TestCheckRedisConfig_NonExpiringWarnsWhenPolicyUnavailable(t *testing.T) {
	findings := redisNonExpiringFixtureWithPolicyError(t, "noeviction", fmt.Errorf("config get failed"))

	for _, finding := range findings {
		if finding.Message == "Redis maxmemory-policy is noeviction" {
			t.Fatalf("config-get error must not produce dedicated noeviction finding: %+v", finding)
		}
	}

	finding, ok := nonExpiringFinding(findings)
	if !ok {
		t.Fatal("missing non-expiring warning when policy is unavailable")
	}
	if !strings.Contains(finding.Details, "maxmemory-policy is unavailable") {
		t.Fatalf("non-expiring detail should explain unavailable policy, got %q", finding.Details)
	}
}

func TestCheckRedisConfig_NonExpiringDetailExplainsPolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		want   string
	}{
		{
			name:   "volatile",
			policy: "volatile-lru",
			want:   `maxmemory-policy "volatile-lru" only evicts keys with a TTL`,
		},
		{
			name:   "noeviction",
			policy: "noeviction",
			want:   "maxmemory-policy noeviction does not evict keys",
		},
		{
			name:   "unknown",
			policy: "unknown-policy",
			want:   `maxmemory-policy "unknown-policy" may leave non-expiring keys unreclaimable`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding, ok := nonExpiringFinding(redisNonExpiringFixture(t, tt.policy))
			if !ok {
				t.Fatalf("missing non-expiring warning for policy %s", tt.policy)
			}
			if !strings.Contains(finding.Details, tt.want) {
				t.Fatalf("non-expiring detail = %q, want substring %q", finding.Details, tt.want)
			}
		})
	}
}

func TestCheckLoadAverage_Disabled(t *testing.T) {
	cfg := &config.Config{}
	f := false
	cfg.Performance.Enabled = &f

	findings := CheckLoadAverage(context.Background(), cfg, nil)
	if findings != nil {
		t.Errorf("expected nil findings when disabled, got %v", findings)
	}
}

func TestCheckSwapAndOOM_NoCrash(t *testing.T) {
	cfg := testPerfConfig()
	// Should not panic regardless of system state; ignore returned findings.
	_ = CheckSwapAndOOM(context.Background(), cfg, nil)
}

func TestCheckWPCron_UsesConfiguredAccountRoots(t *testing.T) {
	cfg := testPerfConfig()
	tmp := t.TempDir()
	webroot := filepath.Join(tmp, "srv", "sites", "example.com", "public")
	if err := os.MkdirAll(webroot, 0755); err != nil {
		t.Fatal(err)
	}
	wpConfig := filepath.Join(webroot, "wp-config.php")
	if err := os.WriteFile(wpConfig, []byte("<?php\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg.AccountRoots = []string{filepath.Join(tmp, "srv", "sites", "*", "public")}

	store, err := state.Open(filepath.Join(tmp, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	findings := CheckWPCron(context.Background(), cfg, store)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Check != "perf_wp_cron" {
		t.Fatalf("expected perf_wp_cron finding, got %q", findings[0].Check)
	}
	if findings[0].Message != "WP-Cron not disabled for example.com" {
		t.Fatalf("unexpected finding message: %q", findings[0].Message)
	}
}
