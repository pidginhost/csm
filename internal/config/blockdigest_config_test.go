package config

import (
	"testing"
	"time"
)

func loadBD(t *testing.T, yaml string) *Config {
	t.Helper()
	cfg, err := LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	return cfg
}

func TestBlockDigestDefaultsAppliedWhenEnabled(t *testing.T) {
	cfg := loadBD(t, "alerts:\n  block_digest:\n    enabled: true\n")
	bd := cfg.Alerts.BlockDigest
	if bd.Interval != "1h" {
		t.Errorf("interval default = %q, want 1h", bd.Interval)
	}
	if bd.SendOn != "any" {
		t.Errorf("send_on default = %q, want any", bd.SendOn)
	}
	if bd.MinBlock != 1 {
		t.Errorf("min_block default = %d, want 1", bd.MinBlock)
	}
}

func TestBlockDigestExplicitZeroMinBlockSurvives(t *testing.T) {
	cfg := loadBD(t, "alerts:\n  block_digest:\n    enabled: true\n    min_block: 0\n")
	if cfg.Alerts.BlockDigest.MinBlock != 0 {
		t.Errorf("explicit min_block 0 overwritten to %d", cfg.Alerts.BlockDigest.MinBlock)
	}
}

func TestBlockDigestBlankMinBlockUsesDefault(t *testing.T) {
	cfg := loadBD(t, "alerts:\n  block_digest:\n    enabled: true\n    min_block:\n")
	if cfg.Alerts.BlockDigest.MinBlock != 1 {
		t.Errorf("blank min_block = %d, want default 1", cfg.Alerts.BlockDigest.MinBlock)
	}
}

func TestBlockDigestIntervalAccessor(t *testing.T) {
	cfg := loadBD(t, "alerts:\n  block_digest:\n    enabled: true\n    interval: \"30m\"\n")
	if got := cfg.BlockDigestInterval(); got != 30*time.Minute {
		t.Errorf("BlockDigestInterval = %v, want 30m", got)
	}
	empty := &Config{}
	if got := empty.BlockDigestInterval(); got != time.Hour {
		t.Errorf("empty BlockDigestInterval = %v, want 1h", got)
	}
}

func TestBlockDigestValidationRejectsBadValues(t *testing.T) {
	cfg := &Config{}
	cfg.Alerts.BlockDigest.Enabled = true
	cfg.Alerts.BlockDigest.SendOn = "sometimes"
	cfg.Alerts.BlockDigest.Channel = "pager"
	cfg.Alerts.BlockDigest.Interval = "soon"
	cfg.Alerts.BlockDigest.Countries = []string{"ROM"}
	cfg.Alerts.BlockDigest.MinBlock = -1
	cfg.Alerts.MaxPerHour = 10
	results := Validate(cfg)
	wantFields := map[string]bool{
		"alerts.block_digest.send_on":   false,
		"alerts.block_digest.channel":   false,
		"alerts.block_digest.interval":  false,
		"alerts.block_digest.countries": false,
		"alerts.block_digest.min_block": false,
	}
	for _, r := range results {
		if r.Level == "error" {
			if _, ok := wantFields[r.Field]; ok {
				wantFields[r.Field] = true
			}
		}
	}
	for f, seen := range wantFields {
		if !seen {
			t.Errorf("expected validation error for %s, none found", f)
		}
	}
}

func TestBlockDigestValidationRejectsDisabledDeliveryChannel(t *testing.T) {
	t.Run("email channel requires email alerts", func(t *testing.T) {
		cfg := baseValidationConfig()
		cfg.Alerts.Email.Enabled = false
		cfg.Alerts.Webhook.Enabled = true
		cfg.Alerts.Webhook.URL = "https://alerts.example.test/hook"
		cfg.Alerts.BlockDigest.Enabled = true
		cfg.Alerts.BlockDigest.Channel = "email"

		results := Validate(cfg)
		if !hasResult(results, "error", "alerts.block_digest.channel") {
			t.Fatalf("expected channel error for disabled email alerts; results=%v", results)
		}
	})

	t.Run("webhook channel requires webhook alerts", func(t *testing.T) {
		cfg := baseValidationConfig()
		cfg.Alerts.BlockDigest.Enabled = true
		cfg.Alerts.BlockDigest.Channel = "webhook"

		results := Validate(cfg)
		if !hasResult(results, "error", "alerts.block_digest.channel") {
			t.Fatalf("expected channel error for disabled webhook alerts; results=%v", results)
		}
	})
}
