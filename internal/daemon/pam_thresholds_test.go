package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// The PAM brute-force trigger used to borrow multi_ip_login_threshold (default
// 3, "IPs per account") for its per-IP failure count, so tuning the account
// spray detector silently retuned SSH/mail brute-force blocking and the
// documented default of 5 failures in 10 minutes was never what ran.
func TestPAMThresholdsUseDedicatedKeys(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.MultiIPLoginThreshold = 3
	cfg.Thresholds.MultiIPLoginWindowMin = 60

	threshold, window, _ := pamThresholds(cfg)
	if threshold != defaultPAMFailureThreshold || window != time.Duration(defaultPAMFailureWindowMin)*time.Minute {
		t.Fatalf("multi-IP login keys leaked into PAM thresholds: %d failures in %s", threshold, window)
	}

	cfg.Thresholds.PAMBruteforceThreshold = 7
	cfg.Thresholds.PAMBruteforceWindowMin = 15
	threshold, window, _ = pamThresholds(cfg)
	if threshold != 7 || window != 15*time.Minute {
		t.Fatalf("dedicated PAM keys ignored: %d failures in %s", threshold, window)
	}
}

func TestPAMCleanupUsesConfiguredWindow(t *testing.T) {
	now := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	cfg := &config.Config{}
	cfg.Thresholds.PAMBruteforceWindowMin = 60
	p := &PAMListener{
		cfg: cfg,
		failures: map[string]*pamFailureTracker{
			"198.51.100.1": {lastSeen: now.Add(-45 * time.Minute)},
			"198.51.100.2": {lastSeen: now.Add(-61 * time.Minute)},
		},
	}

	p.cleanupAt(now)
	if _, ok := p.failures["198.51.100.1"]; !ok {
		t.Fatal("cleanup removed a failure tracker still inside the configured window")
	}
	if _, ok := p.failures["198.51.100.2"]; ok {
		t.Fatal("cleanup retained a failure tracker older than the configured window")
	}
}
