package daemon

import (
	"errors"
	"fmt"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

// phpRelayUnavailableError explains why no PHP-relay controller exists.
//
// Every handler used to answer "phprelay controller not wired (Phase O2)",
// which reads as "this feature has not been written yet". It has been: the
// wiring runs from startPHPRelay, and startControlListener runs before it, so
// the controller is attached whenever it is built. What stops it being built
// is the platform gate -- a non-cPanel host, or the feature switched off (its
// default, and absent entirely from a config that predates the key).
//
// Reporting the gate that actually closed lets the operator act. Naming a
// phase number sends them to read source they do not have.
func phpRelayUnavailableError(cfg *config.Config, isCPanel bool) error {
	if !isCPanel {
		return errors.New("php_relay guard is inactive: it supports cPanel hosts only")
	}
	if cfg == nil || !cfg.EmailProtection.PHPRelay.Enabled {
		return fmt.Errorf("php_relay guard is disabled: set email_protection.php_relay.enabled: true in csm.yaml, then %s", rehashAndRestartHint)
	}
	// Enabled on a supported platform and still absent: startup failed. Do
	// not blame a setting that is already correct.
	return errors.New("php_relay guard is enabled but did not start; check the daemon log for php_relay errors at startup")
}

// rehashAndRestartHint is the standard follow-up after a csm.yaml edit. The
// config hash is part of the integrity baseline, so a restart without a
// rehash makes the daemon refuse to start.
const rehashAndRestartHint = "run `csm rehash && systemctl restart csm`"

// phpRelayUnavailable is the handler-side wrapper: handlers hold a daemon,
// not a platform verdict.
func (c *ControlListener) phpRelayUnavailable() error {
	var cfg *config.Config
	if c.d != nil {
		cfg = c.d.cfg
	}
	return phpRelayUnavailableError(cfg, platform.Detect().IsCPanel())
}
