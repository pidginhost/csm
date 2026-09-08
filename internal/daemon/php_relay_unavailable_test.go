package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// Every phprelay control handler answered a nil controller with
// "phprelay controller not wired (Phase O2)". On a production cPanel host
// that sent the operator looking for unimplemented code. The feature is
// implemented and correctly ordered -- startControlListener runs before
// startPHPRelay, so the controller is attached when it is built at all.
//
// The real cause is the platform gate in startPHPRelay:
//
//	if !d.cfg.EmailProtection.PHPRelay.Enabled { return }
//
// The host's csm.yaml carried no php_relay block at all, so the setting
// defaulted to false and the controller was never constructed. The message
// has to name the setting the operator can act on, not a phase number that
// means nothing outside the repository.
func TestPHPRelayUnavailableReasonNamesTheSetting(t *testing.T) {
	cfg := &config.Config{}
	cfg.EmailProtection.PHPRelay.Enabled = false

	err := phpRelayUnavailableError(cfg, true /* cPanel host */)
	if err == nil {
		t.Fatal("no error for a disabled relay guard")
	}
	msg := err.Error()
	if !strings.Contains(msg, "email_protection.php_relay.enabled") {
		t.Errorf("message does not name the setting to change: %q", msg)
	}
	if strings.Contains(msg, "Phase O2") || strings.Contains(strings.ToLower(msg), "not wired") {
		t.Errorf("message still claims the controller is unimplemented: %q", msg)
	}
}

// On a non-cPanel host the setting is not the reason and telling the
// operator to flip it would waste their time -- the platform gate rejects
// the host before the setting is ever consulted.
func TestPHPRelayUnavailableReasonReportsPlatformFirst(t *testing.T) {
	cfg := &config.Config{}
	cfg.EmailProtection.PHPRelay.Enabled = true

	msg := phpRelayUnavailableError(cfg, false /* not cPanel */).Error()
	if !strings.Contains(strings.ToLower(msg), "cpanel") {
		t.Errorf("message does not give the platform as the reason: %q", msg)
	}
	if strings.Contains(msg, "email_protection.php_relay.enabled") {
		t.Errorf("message points at a setting that would not help: %q", msg)
	}
}

// Enabled on a supported platform and still no controller means something
// failed at startup. Claiming it is disabled would be wrong and would send
// the operator to change a setting that is already correct.
func TestPHPRelayUnavailableReasonAdmitsUnknownCause(t *testing.T) {
	cfg := &config.Config{}
	cfg.EmailProtection.PHPRelay.Enabled = true

	msg := phpRelayUnavailableError(cfg, true).Error()
	if strings.Contains(msg, "email_protection.php_relay.enabled") {
		t.Errorf("blamed the setting though it is enabled: %q", msg)
	}
	if !strings.Contains(strings.ToLower(msg), "log") {
		t.Errorf("message gives the operator nowhere to look: %q", msg)
	}
}

// A nil config must not panic a control handler.
func TestPHPRelayUnavailableReasonHandlesNilConfig(t *testing.T) {
	if err := phpRelayUnavailableError(nil, true); err == nil {
		t.Fatal("nil config produced no error")
	}
}
