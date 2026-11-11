package checks

import (
	"context"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// Session record parsing is tested in session_log_test.go; decodeHexString
// and parseTimeMin are in coverage_test.go.

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

// --- extractRequestURIChecks ------------------------------------------

func TestExtractRequestURIChecksStandard(t *testing.T) {
	line := `203.0.113.5 - - [12/Apr/2026] "POST /login HTTP/1.1" 200 1234`
	if got := extractRequestURIChecks(line); got != "POST /login HTTP/1.1" {
		t.Errorf("got %q", got)
	}
}

func TestExtractRequestURIChecksNoQuotes(t *testing.T) {
	if got := extractRequestURIChecks("no quotes here"); got != "" {
		t.Errorf("got %q", got)
	}
}

// --- CheckCpanelLogins session_log records ----------------------------

// A host without a zone in session_log writes "[2006-01-02 15:04:05]". The
// realtime and shadow-change readers accept it, so the scan must too.
func TestCheckCpanelLoginsReadsBareTimestamp(t *testing.T) {
	stamp := time.Now().Add(-time.Minute).Format("2006-01-02 15:04:05")
	log := "[" + stamp + "] info [cpaneld] 203.0.113.42 NEW alice:token address=203.0.113.42,app=cpaneld,method=handle_form_login\n"
	withMockOS(t, &mockOS{open: openTempLog(t, log)})
	assertSourceIP(t, CheckCpanelLogins(context.Background(), &config.Config{}, newTestStore(t)), "cpanel_login", "203.0.113.42")
}

// A login from the host itself or from an origin that is not an address
// names no client to report or count.
func TestCheckCpanelLoginsSkipsLocalAndNonAddressOrigins(t *testing.T) {
	stamp := time.Now().Add(-time.Minute).Format("2006-01-02 15:04:05 -0700")
	for _, origin := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "internal", "not-an-address"} {
		t.Run(origin, func(t *testing.T) {
			log := "[" + stamp + "] info [cpaneld] " + origin + " NEW alice:token address=" + origin + ",app=cpaneld,method=handle_form_login\n"
			withMockOS(t, &mockOS{open: openTempLog(t, log)})
			for _, f := range CheckCpanelLogins(context.Background(), &config.Config{}, newTestStore(t)) {
				t.Errorf("unexpected %s finding: %s", f.Check, f.Message)
			}
		})
	}
}
