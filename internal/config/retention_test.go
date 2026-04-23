package config

import (
	"os"
	"path/filepath"
	"testing"
)

// baseRetentionCfg returns a minimally-valid Config so Validate()'s
// unrelated checks don't swamp the retention-specific assertions.
func baseRetentionCfg() *Config {
	cfg := &Config{Hostname: "test"}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"a@b.com"}
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.Email.From = "csm@test.com"
	cfg.Alerts.MaxPerHour = 10
	return cfg
}

func TestRetentionDefaultsWhenBlockAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	if err := os.WriteFile(path, []byte("hostname: test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Retention.Enabled {
		t.Error("retention.enabled should default to false (opt-in)")
	}
	if cfg.Retention.FindingsDays != 90 {
		t.Errorf("findings_days = %d, want 90", cfg.Retention.FindingsDays)
	}
	if cfg.Retention.HistoryDays != 30 {
		t.Errorf("history_days = %d, want 30", cfg.Retention.HistoryDays)
	}
	if cfg.Retention.ReputationDays != 180 {
		t.Errorf("reputation_days = %d, want 180", cfg.Retention.ReputationDays)
	}
	if cfg.Retention.SweepInterval != "24h" {
		t.Errorf("sweep_interval = %q, want \"24h\"", cfg.Retention.SweepInterval)
	}
	if cfg.Retention.CompactMinSizeMB != 128 {
		t.Errorf("compact_min_size_mb = %d, want 128", cfg.Retention.CompactMinSizeMB)
	}
	if cfg.Retention.CompactFillRatio != 0.5 {
		t.Errorf("compact_fill_ratio = %v, want 0.5", cfg.Retention.CompactFillRatio)
	}
}

func TestRetentionDefaultsFillEmptyBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	body := "hostname: test\nretention:\n  enabled: true\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !cfg.Retention.Enabled {
		t.Error("retention.enabled was not parsed as true")
	}
	// Unspecified sub-keys still fall back to defaults.
	if cfg.Retention.FindingsDays != 90 {
		t.Errorf("findings_days = %d, want 90 default", cfg.Retention.FindingsDays)
	}
	if cfg.Retention.HistoryDays != 30 {
		t.Errorf("history_days = %d, want 30 default", cfg.Retention.HistoryDays)
	}
}

func TestRetentionCustomValuesPreserved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	body := "" +
		"hostname: test\n" +
		"retention:\n" +
		"  enabled: true\n" +
		"  findings_days: 14\n" +
		"  history_days: 7\n" +
		"  reputation_days: 365\n" +
		"  sweep_interval: \"6h\"\n" +
		"  compact_min_size_mb: 256\n" +
		"  compact_fill_ratio: 0.3\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Retention.FindingsDays != 14 {
		t.Errorf("findings_days = %d, want 14", cfg.Retention.FindingsDays)
	}
	if cfg.Retention.HistoryDays != 7 {
		t.Errorf("history_days = %d, want 7", cfg.Retention.HistoryDays)
	}
	if cfg.Retention.ReputationDays != 365 {
		t.Errorf("reputation_days = %d, want 365", cfg.Retention.ReputationDays)
	}
	if cfg.Retention.SweepInterval != "6h" {
		t.Errorf("sweep_interval = %q, want \"6h\"", cfg.Retention.SweepInterval)
	}
	if cfg.Retention.CompactMinSizeMB != 256 {
		t.Errorf("compact_min_size_mb = %d, want 256", cfg.Retention.CompactMinSizeMB)
	}
	if cfg.Retention.CompactFillRatio != 0.3 {
		t.Errorf("compact_fill_ratio = %v, want 0.3", cfg.Retention.CompactFillRatio)
	}
}

func TestValidateRetentionSweepIntervalBad(t *testing.T) {
	cfg := baseRetentionCfg()
	cfg.Retention.Enabled = true
	cfg.Retention.SweepInterval = "notaduration"
	if !hasResult(Validate(cfg), "error", "retention.sweep_interval") {
		t.Error("expected error for bad sweep_interval")
	}
}

func TestValidateRetentionSweepIntervalEmptyWhileDisabled(t *testing.T) {
	cfg := baseRetentionCfg()
	// Retention disabled; sweep_interval unvalidated even if empty.
	if hasResult(Validate(cfg), "error", "retention.sweep_interval") {
		t.Error("should not error on retention.sweep_interval when retention is disabled")
	}
}

func TestValidateRetentionDaysNegative(t *testing.T) {
	cfg := baseRetentionCfg()
	cfg.Retention.Enabled = true
	cfg.Retention.FindingsDays = -1
	if !hasResult(Validate(cfg), "error", "retention.findings_days") {
		t.Error("expected error for negative findings_days")
	}
}

func TestValidateRetentionFillRatioOutOfRange(t *testing.T) {
	for _, v := range []float64{-0.1, 0, 1.01, 5.0} {
		cfg := baseRetentionCfg()
		cfg.Retention.Enabled = true
		cfg.Retention.CompactFillRatio = v
		if !hasResult(Validate(cfg), "error", "retention.compact_fill_ratio") {
			t.Errorf("expected error for compact_fill_ratio=%v", v)
		}
	}
}

func TestValidateRetentionCompactSizeNegative(t *testing.T) {
	cfg := baseRetentionCfg()
	cfg.Retention.Enabled = true
	cfg.Retention.CompactMinSizeMB = -1
	if !hasResult(Validate(cfg), "error", "retention.compact_min_size_mb") {
		t.Error("expected error for negative compact_min_size_mb")
	}
}

func TestValidateRetentionAllValidNoErrors(t *testing.T) {
	cfg := baseRetentionCfg()
	cfg.Retention.Enabled = true
	cfg.Retention.FindingsDays = 90
	cfg.Retention.HistoryDays = 30
	cfg.Retention.ReputationDays = 180
	cfg.Retention.SweepInterval = "24h"
	cfg.Retention.CompactMinSizeMB = 128
	cfg.Retention.CompactFillRatio = 0.5
	results := Validate(cfg)
	for _, r := range results {
		if r.Level == "error" && len(r.Field) >= 10 && r.Field[:10] == "retention." {
			t.Errorf("unexpected retention.* error: %v", r)
		}
	}
}
