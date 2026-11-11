package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// Tests for parseSessionTimestamp, parseCpanelLogin, parsePurgeAccount,
// decodeHexString, and parseTimeMin are in coverage_test.go.

// --- multiIPThreshold / multiIPWindowMin ------------------------------

func TestMultiIPThresholdDefault(t *testing.T) {
	cfg := &config.Config{}
	if got := multiIPThreshold(cfg); got != 3 {
		t.Errorf("default = %d, want 3", got)
	}
}

func TestMultiIPThresholdConfigured(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.MultiIPLoginThreshold = 5
	if got := multiIPThreshold(cfg); got != 5 {
		t.Errorf("got %d, want 5", got)
	}
}

func TestMultiIPWindowMinDefault(t *testing.T) {
	cfg := &config.Config{}
	if got := multiIPWindowMin(cfg); got != 60 {
		t.Errorf("default = %d, want 60", got)
	}
}

func TestMultiIPWindowMinConfigured(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.MultiIPLoginWindowMin = 120
	if got := multiIPWindowMin(cfg); got != 120 {
		t.Errorf("got %d, want 120", got)
	}
}
