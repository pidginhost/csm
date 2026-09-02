package config

import (
	"strings"
	"testing"
)

func TestPAMBruteforceThresholdDefaults(t *testing.T) {
	cfg, err := LoadBytes([]byte("hostname: test\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Thresholds.PAMBruteforceThreshold != 5 || cfg.Thresholds.PAMBruteforceWindowMin != 10 {
		t.Fatalf("PAM defaults = %d failures in %d min, want 5 in 10",
			cfg.Thresholds.PAMBruteforceThreshold, cfg.Thresholds.PAMBruteforceWindowMin)
	}
}

func TestPAMBruteforceThresholdValidation(t *testing.T) {
	cfg, err := LoadBytes([]byte("hostname: test\nthresholds:\n  pam_bruteforce_threshold: 1\n  pam_bruteforce_window_min: 2000\n"))
	if err != nil {
		t.Fatal(err)
	}
	var fields []string
	for _, r := range Validate(cfg) {
		if r.Level == "error" && strings.HasPrefix(r.Field, "thresholds.pam_bruteforce_") {
			fields = append(fields, r.Field)
		}
	}
	if len(fields) != 2 {
		t.Fatalf("validation errors = %v, want both pam_bruteforce keys rejected", fields)
	}
}
