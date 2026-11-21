package config

import (
	"strings"
	"testing"
	"time"
)

func loadBackup(t *testing.T, yaml string) *Config {
	t.Helper()
	cfg, err := LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	return cfg
}

func backupValidationErrors(cfg *Config) []ValidationResult {
	var out []ValidationResult
	for _, r := range Validate(cfg) {
		if r.Level == "error" && strings.HasPrefix(r.Field, "backup") {
			out = append(out, r)
		}
	}
	return out
}

func TestBackupDefaults(t *testing.T) {
	cfg := loadBackup(t, "{}\n")
	want := BackupConfig{
		Schedule:       "24h",
		DestinationDir: "/var/lib/csm/backups",
		Filename:       "csm-{date}.csmbak",
		RetentionDays:  14,
	}
	if cfg.Backup != want {
		t.Fatalf("defaults = %+v, want %+v", cfg.Backup, want)
	}
	cfg.Backup.Enabled = true
	if _, err := ParseBackup(cfg); err != nil {
		t.Fatalf("enabled defaults refused: %v", err)
	}
	if errs := backupValidationErrors(cfg); len(errs) != 0 {
		t.Fatalf("enabled defaults fail validation: %v", errs)
	}
}

// Filling the default over an explicit 0 would start deleting archives the
// operator meant to keep.
func TestBackupExplicitZeroRetentionIsRefused(t *testing.T) {
	cfg := loadBackup(t, "backup:\n  enabled: true\n  retention_days: 0\n")
	if cfg.Backup.RetentionDays != 0 {
		t.Fatalf("explicit retention_days 0 replaced by %d", cfg.Backup.RetentionDays)
	}
	errs := backupValidationErrors(cfg)
	if len(errs) != 1 || !strings.Contains(errs[0].Message, "retention_days") {
		t.Fatalf("validation = %v, want one retention_days error", errs)
	}
}

func TestBackupDisabledBlockIsNotValidated(t *testing.T) {
	cfg := loadBackup(t, "backup:\n  filename: plain.csmbak\n")
	if errs := backupValidationErrors(cfg); len(errs) != 0 {
		t.Fatalf("disabled block failed validation: %v", errs)
	}
}

func TestParseBackupRefusesUnsafeValues(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"unparseable schedule", func(c *Config) { c.Backup.Schedule = "daily" }, "backup.schedule"},
		{"schedule under an hour", func(c *Config) { c.Backup.Schedule = "30m" }, "backup.schedule"},
		{"relative destination", func(c *Config) { c.Backup.DestinationDir = "var/lib/csm/backups" }, "backup.destination_dir"},
		{"destination with dot-dot", func(c *Config) { c.Backup.DestinationDir = "/var/lib/csm/../../etc" }, "backup.destination_dir"},
		{"destination with trailing slash", func(c *Config) { c.Backup.DestinationDir = "/var/lib/csm/backups/" }, "backup.destination_dir"},
		{"destination outside the sandbox grant", func(c *Config) { c.Backup.DestinationDir = "/var/backups" }, "/var/lib/csm"},
		{"destination inside state_path", func(c *Config) { c.Backup.DestinationDir = "/var/lib/csm/state/backups" }, "state_path"},
		{"destination inside rules_dir", func(c *Config) {
			c.Signatures.RulesDir = "/var/lib/csm/rules"
			c.Backup.DestinationDir = "/var/lib/csm/rules/backups"
		}, "rules_dir"},
		{"filename breaks checksum line", func(c *Config) { c.Backup.Filename = "{date}\nother" }, "backup.filename"},
		{"filename without date", func(c *Config) { c.Backup.Filename = "csm.csmbak" }, "backup.filename"},
		{"filename with two dates", func(c *Config) { c.Backup.Filename = "csm-{date}-{date}.csmbak" }, "backup.filename"},
		{"filename with a separator", func(c *Config) { c.Backup.Filename = "sub/csm-{date}.csmbak" }, "backup.filename"},
		{"negative retention", func(c *Config) { c.Backup.RetentionDays = -1 }, "backup.retention_days"},
		{"retention past the cap", func(c *Config) { c.Backup.RetentionDays = 3651 }, "backup.retention_days"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := loadBackup(t, "backup:\n  enabled: true\n")
			tc.mutate(cfg)
			_, err := ParseBackup(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseBackup error = %v, want one naming %q", err, tc.want)
			}
			if errs := backupValidationErrors(cfg); len(errs) != 1 {
				t.Fatalf("validation = %v, want one backup error", errs)
			}
		})
	}
}

func TestBackupArchiveNamesRoundTrip(t *testing.T) {
	cfg := loadBackup(t, "backup:\n  enabled: true\n")
	plan, err := ParseBackup(cfg)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 21, 3, 4, 5, 0, time.FixedZone("UTC+2", 2*3600))
	name := plan.ArchiveName(at)
	if name != "csm-20261121T010405Z.csmbak" {
		t.Fatalf("ArchiveName = %q", name)
	}
	got, ok := plan.ArchiveTime(name)
	if !ok || !got.Equal(at) {
		t.Fatalf("ArchiveTime(%q) = %v, %t; want %v", name, got, ok, at)
	}
	for _, other := range []string{
		name + ".sha256",
		"x" + name,
		"csm-2026-11-21.csmbak",
		"csm-20261321T010405Z.csmbak",
		"csm-20261121T10405Z.csmbak",
		"csm-20261121T010405Z.csmbak.tmp",
		"csm-export-bbolt-123456.snap",
		"csm-.csmbak",
	} {
		if _, ok := plan.ArchiveTime(other); ok {
			t.Errorf("ArchiveTime accepted %q", other)
		}
	}
}

func TestDaemonStartupWithInvalidBackupPlan(t *testing.T) {
	cfg := loadBackup(t, "backup:\n  enabled: true\n  schedule: daily\n")
	cfg.Retention.CompactFillRatio = 2
	var backup, retention string
	for _, r := range ValidateDaemonStartup(cfg) {
		switch r.Field {
		case "backup":
			backup = r.Level
		case "retention.compact_fill_ratio":
			retention = r.Level
		}
	}
	if backup != "warn" || retention != "error" {
		t.Fatalf("startup validation: backup %q, retention %q", backup, retention)
	}
}
