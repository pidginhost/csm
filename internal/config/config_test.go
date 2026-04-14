package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "csm-config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString("hostname: test\n")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Hostname != "test" {
		t.Errorf("hostname = %q, want 'test'", cfg.Hostname)
	}
	if cfg.Thresholds.MailQueueWarn != 500 {
		t.Errorf("mail_queue_warn = %d, want 500", cfg.Thresholds.MailQueueWarn)
	}
	if cfg.Thresholds.DeepScanIntervalMin != 60 {
		t.Errorf("deep_scan_interval = %d, want 60", cfg.Thresholds.DeepScanIntervalMin)
	}
	if cfg.Alerts.MaxPerHour != 30 {
		t.Errorf("max_per_hour = %d, want 30", cfg.Alerts.MaxPerHour)
	}
	if cfg.StatePath != "/opt/csm/state" {
		t.Errorf("state_path = %q, want '/opt/csm/state'", cfg.StatePath)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		wantError int
	}{
		{
			name: "empty hostname",
			cfg: func() Config {
				c := Config{Hostname: ""}
				c.Alerts.MaxPerHour = 10
				return c
			}(),
			wantError: 2, // hostname + no alert method
		},
		{
			name: "placeholder hostname",
			cfg: func() Config {
				c := Config{Hostname: "SET_HOSTNAME_HERE"}
				c.Alerts.MaxPerHour = 10
				return c
			}(),
			wantError: 2,
		},
		{
			name: "email enabled no recipients",
			cfg: func() Config {
				c := Config{Hostname: "test"}
				c.Alerts.Email.Enabled = true
				c.Alerts.Email.SMTP = "localhost:25"
				c.Alerts.Email.From = "csm@test.com"
				c.Alerts.MaxPerHour = 10
				return c
			}(),
			wantError: 1,
		},
		{
			name: "webhook enabled no URL",
			cfg: func() Config {
				c := Config{Hostname: "test"}
				c.Alerts.Webhook.Enabled = true
				c.Alerts.MaxPerHour = 10
				return c
			}(),
			wantError: 1,
		},
		{
			name: "valid config",
			cfg: func() Config {
				c := Config{Hostname: "test"}
				c.Alerts.Email.Enabled = true
				c.Alerts.Email.To = []string{"admin@test.com"}
				c.Alerts.Email.SMTP = "localhost:25"
				c.Alerts.Email.From = "csm@test.com"
				c.Alerts.MaxPerHour = 10
				return c
			}(),
			wantError: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := Validate(&tt.cfg)
			errors := 0
			for _, r := range results {
				if r.Level == "error" {
					errors++
				}
			}
			if errors != tt.wantError {
				t.Errorf("Validate() returned %d errors, want %d: %v", errors, tt.wantError, results)
			}
		})
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "csm-config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	_, _ = tmpFile.WriteString("invalid: [yaml: {{{\n")
	tmpFile.Close()

	_, err = Load(tmpFile.Name())
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := Load("/nonexistent/path/csm.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestConfig_SMTPBruteForceDefaultsApplied(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "csm.yaml")
	if err := os.WriteFile(path, []byte("hostname: \"\"\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := map[string]int{
		"SMTPBruteForceThreshold":    5,
		"SMTPBruteForceWindowMin":    10,
		"SMTPBruteForceSuppressMin":  60,
		"SMTPBruteForceSubnetThresh": 8,
		"SMTPAccountSprayThreshold":  12,
		"SMTPBruteForceMaxTracked":   20000,
	}
	got := map[string]int{
		"SMTPBruteForceThreshold":    cfg.Thresholds.SMTPBruteForceThreshold,
		"SMTPBruteForceWindowMin":    cfg.Thresholds.SMTPBruteForceWindowMin,
		"SMTPBruteForceSuppressMin":  cfg.Thresholds.SMTPBruteForceSuppressMin,
		"SMTPBruteForceSubnetThresh": cfg.Thresholds.SMTPBruteForceSubnetThresh,
		"SMTPAccountSprayThreshold":  cfg.Thresholds.SMTPAccountSprayThreshold,
		"SMTPBruteForceMaxTracked":   cfg.Thresholds.SMTPBruteForceMaxTracked,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d", k, got[k], v)
		}
	}
}
