package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func readFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "csm_fixture.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestYAMLEditReplacesScalarAndPreservesUntouchedBytes(t *testing.T) {
	in := readFixture(t)
	out, err := YAMLEdit(in, []YAMLChange{
		{Path: []string{"thresholds", "mail_queue_warn"}, Value: 750},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "mail_queue_warn: 750") {
		t.Errorf("scalar not replaced: %s", out)
	}
	if !strings.Contains(string(out), "# Raise this if scanner starts hitting it under load") {
		t.Errorf("comment adjacent to edited scalar was lost")
	}
	if !strings.Contains(string(out), "# Operator set this to ops@ after the 2026-03 incident") {
		t.Errorf("comment in unrelated section was lost")
	}
	untouchedBlock := "alerts:\n  email:\n    enabled: true\n    # Operator set this to ops@ after the 2026-03 incident\n    to:\n      - ops@example.com\n    from: csm@example.com\n  max_per_hour: 30\n"
	if !strings.Contains(string(out), untouchedBlock) {
		t.Errorf("untouched block drifted:\n%s", out)
	}
}

func TestYAMLEditReplacesListValue(t *testing.T) {
	in := readFixture(t)
	out, err := YAMLEdit(in, []YAMLChange{
		{Path: []string{"alerts", "email", "to"}, Value: []string{"sec@example.com", "oncall@example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var decoded Config
	if err := yaml.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("output does not decode: %v", err)
	}
	want := []string{"sec@example.com", "oncall@example.com"}
	if !reflect.DeepEqual(decoded.Alerts.Email.To, want) {
		t.Errorf("To = %v, want %v", decoded.Alerts.Email.To, want)
	}
}

func TestYAMLEditRoundTripsNewKey(t *testing.T) {
	in := readFixture(t)
	out, err := YAMLEdit(in, []YAMLChange{
		{Path: []string{"auto_response", "kill_processes"}, Value: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	var decoded Config
	if err := yaml.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("output does not decode: %v", err)
	}
	if !decoded.AutoResponse.KillProcesses {
		t.Errorf("new key not reflected in decoded config")
	}
}

func TestYAMLEditDecodesBackToIntendedConfig(t *testing.T) {
	in := readFixture(t)
	out, err := YAMLEdit(in, []YAMLChange{
		{Path: []string{"thresholds", "mail_queue_warn"}, Value: 999},
		{Path: []string{"auto_response", "block_ips"}, Value: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadBytes(out)
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Thresholds.MailQueueWarn != 999 {
		t.Errorf("MailQueueWarn = %d", cfg.Thresholds.MailQueueWarn)
	}
	if cfg.AutoResponse.BlockIPs {
		t.Errorf("BlockIPs still true")
	}
}

func TestYAMLEditNullValueRoundTrip(t *testing.T) {
	in := []byte("performance:\n  enabled: true\n  php_process_warn_per_user: 20\n")
	out, err := YAMLEdit(in, []YAMLChange{
		{Path: []string{"performance", "enabled"}, Value: nil},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "enabled: true") {
		t.Errorf("enabled still true in output: %s", out)
	}
	var raw map[string]interface{}
	if err := yaml.Unmarshal(out, &raw); err != nil {
		t.Fatalf("raw yaml decode: %v", err)
	}
	performance, _ := raw["performance"].(map[string]interface{})
	if v, ok := performance["enabled"]; !ok || v != nil {
		t.Errorf("raw performance.enabled = %#v, want explicit null", v)
	}
	cfg, err := LoadBytes(out)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Performance.Enabled == nil || !*cfg.Performance.Enabled {
		t.Errorf("expected default true, got %v", cfg.Performance.Enabled)
	}
}

func FuzzYAMLEdit(f *testing.F) {
	seed, _ := os.ReadFile(filepath.Join("testdata", "csm_fixture.yaml"))
	f.Add(seed, "thresholds.mail_queue_warn", "500")
	f.Add(seed, "alerts.max_per_hour", "30")
	f.Fuzz(func(t *testing.T, data []byte, path, value string) {
		if len(path) == 0 || len(path) > 128 {
			t.Skip()
		}
		parts := strings.Split(path, ".")
		for _, p := range parts {
			if p == "" {
				t.Skip()
			}
		}
		out, err := YAMLEdit(data, []YAMLChange{{Path: parts, Value: value}})
		if err != nil {
			return
		}
		var check yaml.Node
		if err := yaml.Unmarshal(out, &check); err != nil {
			t.Errorf("output does not re-parse: %v", err)
		}
	})
}
