package config

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDropperDetectionDefaults(t *testing.T) {
	cfg, err := LoadBytes([]byte("hostname: test\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if !cfg.Thresholds.DropperDetection {
		t.Error("dropper_detection must default to true")
	}
	if cfg.Thresholds.DropperUnlinkTTLSec != DefaultDropperUnlinkTTLSec {
		t.Errorf("dropper_unlink_ttl_sec = %d, want default %d",
			cfg.Thresholds.DropperUnlinkTTLSec, DefaultDropperUnlinkTTLSec)
	}
}

func TestDropperDetectionExplicitFalseSticks(t *testing.T) {
	cfg, err := LoadBytes([]byte("thresholds:\n  dropper_detection: false\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Thresholds.DropperDetection {
		t.Error("operator-set dropper_detection: false must not be overridden by defaults")
	}
}

func TestDropperUnlinkTTLValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		ttl  string
		ok   bool
	}{
		{"in range", "300", true},
		{"minimum", "30", true},
		{"maximum", "3600", true},
		{"too small", "5", false},
		{"too large", "86400", false},
		{"negative", "-1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadBytes([]byte("thresholds:\n  dropper_unlink_ttl_sec: " + tc.ttl + "\n"))
			if err != nil {
				t.Fatalf("LoadBytes: %v", err)
			}
			var failed bool
			for _, r := range Validate(cfg) {
				if r.Level == "error" && r.Field == "thresholds.dropper_unlink_ttl_sec" {
					failed = true
				}
			}
			if tc.ok && failed {
				t.Errorf("ttl %s must validate, got failures: %+v", tc.ttl, Validate(cfg))
			}
			if !tc.ok && !failed {
				t.Errorf("ttl %s must fail validation", tc.ttl)
			}
		})
	}
}

func TestPackagedDefaultCarriesDropperKeys(t *testing.T) {
	data, err := os.ReadFile("../../build/packaging/csm.yaml.default")
	if err != nil {
		t.Skipf("packaged default config not readable from this layout: %v", err)
	}
	assertDropperKeys(t, data, "packaged default")
}

func TestProductionReferenceCarriesDropperKeys(t *testing.T) {
	data, err := os.ReadFile("../../configs/csm.yaml.production.example")
	if err != nil {
		t.Skipf("production reference config not readable from this layout: %v", err)
	}
	assertDropperKeys(t, data, "production reference")
}

func assertDropperKeys(t *testing.T, data []byte, label string) {
	t.Helper()
	cfg, err := LoadBytes(data)
	if err != nil {
		t.Fatalf("LoadBytes %s: %v", label, err)
	}
	if !cfg.Thresholds.DropperDetection {
		t.Errorf("%s must ship with dropper_detection enabled", label)
	}
	if cfg.Thresholds.DropperUnlinkTTLSec != DefaultDropperUnlinkTTLSec {
		t.Errorf("%s dropper_unlink_ttl_sec = %d, want %d",
			label, cfg.Thresholds.DropperUnlinkTTLSec, DefaultDropperUnlinkTTLSec)
	}
	var raw struct {
		Thresholds map[string]any `yaml:"thresholds"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatalf("yaml.Unmarshal %s: %v", label, err)
	}
	for _, key := range []string{"dropper_detection", "dropper_unlink_ttl_sec"} {
		if _, ok := raw.Thresholds[key]; !ok {
			t.Errorf("%s missing thresholds.%s (defaults must ship in all templates)", label, key)
		}
	}
}
