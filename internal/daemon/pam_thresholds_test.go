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
