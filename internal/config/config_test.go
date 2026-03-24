package config

import (
	"os"
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
	if cfg.Alerts.MaxPerHour != 10 {
		t.Errorf("max_per_hour = %d, want 10", cfg.Alerts.MaxPerHour)
	}
	if cfg.StatePath != "/opt/csm/state" {
		t.Errorf("state_path = %q, want '/opt/csm/state'", cfg.StatePath)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr int
	}{
		{
			name:    "empty hostname",
			cfg:     Config{Hostname: ""},
			wantErr: 2, // hostname + no alert method
		},
		{
			name:    "placeholder hostname",
			cfg:     Config{Hostname: "SET_HOSTNAME_HERE"},
			wantErr: 2,
		},
		{
			name: "email enabled no recipients",
			cfg: func() Config {
				c := Config{Hostname: "test"}
				c.Alerts.Email.Enabled = true
				c.Alerts.Email.SMTP = "localhost:25"
				return c
			}(),
			wantErr: 1,
		},
		{
			name: "webhook enabled no URL",
			cfg: func() Config {
				c := Config{Hostname: "test"}
				c.Alerts.Webhook.Enabled = true
				return c
			}(),
			wantErr: 1,
		},
		{
			name: "valid config",
			cfg: func() Config {
				c := Config{Hostname: "test"}
				c.Alerts.Email.Enabled = true
				c.Alerts.Email.To = []string{"admin@test.com"}
				c.Alerts.Email.SMTP = "localhost:25"
				return c
			}(),
			wantErr: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := Validate(&tt.cfg)
			if len(errs) != tt.wantErr {
				t.Errorf("Validate() returned %d errors, want %d: %v", len(errs), tt.wantErr, errs)
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
