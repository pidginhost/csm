package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

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

func TestCheckLoadAverage_Disabled(t *testing.T) {
	cfg := &config.Config{}
	f := false
	cfg.Performance.Enabled = &f

	findings := CheckLoadAverage(cfg, nil)
	if findings != nil {
		t.Errorf("expected nil findings when disabled, got %v", findings)
	}
}

func TestCheckSwapAndOOM_NoCrash(t *testing.T) {
	cfg := testPerfConfig()
	// Should not panic regardless of system state; ignore returned findings.
	_ = CheckSwapAndOOM(cfg, nil)
}
