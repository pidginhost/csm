package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const removedKeysYAML = `hostname: host.example
alerts:
  webhook:
    enabled: false
    per_finding: true
thresholds:
  mail_queue_warn: 7
  state_expiry_hours: 24
  wp_core_check_interval_min: 60
  webshell_scan_interval_min: 30
  filesystem_scan_interval_min: 30
email_protection:
  php_relay:
    rate_window_min: 9
    reputation_failures_per_24h: 3
    baseline_sigma: 3.0
    baseline_observation_days: 7
  forward_guard:
    quarantine_retention_days: 21
    skip_forwarders: ["a@example.com"]
`

var wantRemovedKeys = []string{
	"alerts.webhook.per_finding",
	"thresholds.state_expiry_hours",
	"thresholds.wp_core_check_interval_min",
	"thresholds.webshell_scan_interval_min",
	"thresholds.filesystem_scan_interval_min",
	"email_protection.php_relay.reputation_failures_per_24h",
	"email_protection.php_relay.baseline_sigma",
	"email_protection.php_relay.baseline_observation_days",
	"email_protection.forward_guard.skip_forwarders",
}

// A host upgraded with one of the removed settings still in csm.yaml must
// keep starting: the key is dropped, its siblings are kept, and the operator
// learns which keys to delete.
func TestLoadBytesDropsRemovedKeysAndRecordsThem(t *testing.T) {
	cfg, err := LoadBytes([]byte(removedKeysYAML))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if !reflect.DeepEqual(cfg.RemovedKeys, wantRemovedKeys) {
		t.Fatalf("RemovedKeys = %v, want %v", cfg.RemovedKeys, wantRemovedKeys)
	}
	if cfg.Thresholds.MailQueueWarn != 7 {
		t.Errorf("mail_queue_warn = %d, want 7 (sibling of a removed key)", cfg.Thresholds.MailQueueWarn)
	}
	if cfg.EmailProtection.PHPRelay.RateWindowMin != 9 {
		t.Errorf("rate_window_min = %d, want 9", cfg.EmailProtection.PHPRelay.RateWindowMin)
	}
	if cfg.EmailProtection.ForwardGuard.QuarantineRetentionDays != 21 {
		t.Errorf("quarantine_retention_days = %d, want 21", cfg.EmailProtection.ForwardGuard.QuarantineRetentionDays)
	}
}

func TestLoadBytesWithoutRemovedKeysRecordsNone(t *testing.T) {
	cfg, err := LoadBytes([]byte("hostname: host.example\nthresholds:\n  mail_queue_warn: 7\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(cfg.RemovedKeys) != 0 {
		t.Fatalf("RemovedKeys = %v, want none", cfg.RemovedKeys)
	}
}

func TestRemovedKeysInYAMLMerge(t *testing.T) {
	data := []byte("thresholds:\n  <<: &legacy {state_expiry_hours: 24}\n  mail_queue_warn: 7\n")
	cfg, err := LoadBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.RemovedKeys, []string{"thresholds.state_expiry_hours"}) || cfg.Thresholds.MailQueueWarn != 7 {
		t.Fatalf("removed keys = %v, mail queue warning = %d", cfg.RemovedKeys, cfg.Thresholds.MailQueueWarn)
	}
	clean, err := LoadBytes([]byte("thresholds: {mail_queue_warn: 7}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if changes := Diff(cfg, clean); len(changes) != 0 {
		t.Fatalf("removal metadata changed reload policy: %v", changes)
	}
}

func TestLoadWithDirDropsRemovedKeysFromFragments(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "csm.yaml")
	confd := filepath.Join(dir, "conf.d")
	must(t, os.MkdirAll(confd, 0o700))
	must(t, os.WriteFile(main, []byte("hostname: host.example\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(confd, "10-old.yaml"), []byte("thresholds:\n  state_expiry_hours: 5\n  mail_queue_warn: 3\n"), 0o600))

	cfg, err := LoadWithDir(main, confd)
	if err != nil {
		t.Fatalf("LoadWithDir: %v", err)
	}
	if !reflect.DeepEqual(cfg.RemovedKeys, []string{"thresholds.state_expiry_hours"}) {
		t.Fatalf("RemovedKeys = %v", cfg.RemovedKeys)
	}
	if cfg.Thresholds.MailQueueWarn != 3 {
		t.Errorf("mail_queue_warn = %d, want 3", cfg.Thresholds.MailQueueWarn)
	}
	must(t, os.WriteFile(filepath.Join(confd, "10-old.yaml"), []byte("thresholds:\n  mail_queue_warn: 3\n"), 0o600))
	clean, err := LoadWithDir(main, confd)
	if err != nil {
		t.Fatal(err)
	}
	if len(clean.RemovedKeys) != 0 || len(Diff(cfg, clean)) != 0 {
		t.Fatal("removing a retired fragment key must clear its warning without changing live policy")
	}
}

func TestValidateWarnsAboutRemovedKeys(t *testing.T) {
	cfg, err := LoadBytes([]byte(removedKeysYAML))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	results := Validate(cfg)
	for _, key := range wantRemovedKeys {
		found := false
		for _, r := range results {
			if r.Field == key && r.Level == "warn" && strings.Contains(r.Message, "removed") {
				found = true
			}
			if r.Field == key && r.Level == "error" {
				t.Errorf("removed key %s must warn, not fail validation: %s", key, r.Message)
			}
		}
		if !found {
			t.Errorf("no removal warning for %s", key)
		}
	}
}

// A removed key must not also be a live field, or the strip would silently
// discard a real setting.
func TestRemovedKeysAreNotConfigFields(t *testing.T) {
	for _, key := range removedKeys {
		if configFieldExists(reflect.TypeOf(Config{}), strings.Split(key, ".")) {
			t.Errorf("%s is listed as removed but Config still declares it", key)
		}
	}
}

func configFieldExists(typ reflect.Type, path []string) bool {
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct || len(path) == 0 {
		return false
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if yamlFieldName(field) != path[0] {
			continue
		}
		if len(path) == 1 {
			return true
		}
		return configFieldExists(field.Type, path[1:])
	}
	return false
}
