package config

import (
	"fmt"
	"strings"
)

// Operating modes for the Mode field.
const (
	// ModeEnforce is the default: every subsystem is governed by its own
	// switch and CSM keeps its host integration files current.
	ModeEnforce = "enforce"
	// ModeObserve declares that CSM must not change host state on this
	// host. Detection, correlation, alerting and the audit sinks all run;
	// nothing writes outside CSM's own state, log and quarantine trees.
	ModeObserve = "observe"
)

// ObserveMode reports whether this host runs in the observe posture.
func (cfg *Config) ObserveMode() bool {
	return normalizeMode(cfg.Mode) == ModeObserve
}

func normalizeMode(mode string) string {
	return strings.ToLower(strings.TrimSpace(mode))
}

// observeConflict names one config key whose value would let CSM change host
// state, and the value an observe-mode host has to use instead.
type observeConflict struct {
	key  string
	want string
}

// observeConflicts lists every enabled subsystem that writes outside CSM's own
// trees. Keeping the list here rather than at each call site means a new
// state-changing subsystem is one entry away from being covered, and the
// privileged-operation inventory can point operators at a single key.
func observeConflicts(cfg *Config) []observeConflict {
	var out []observeConflict
	add := func(on bool, key, want string) {
		if on {
			out = append(out, observeConflict{key: key, want: want})
		}
	}

	add(cfg.AutoResponse.Enabled, "auto_response.enabled", "false")
	add(cfg.Firewall != nil && cfg.Firewall.Enabled, "firewall.enabled", "false")
	add(cfg.PHPShield.Enabled, "php_shield.enabled", "false")
	add(cfg.BPFEnforcement.Enabled, "bpf_enforcement.enabled", "false")
	add(cfg.EmailProtection.ForwardGuard.Enabled, "email_protection.forward_guard.enabled", "false")
	add(cfg.EmailAV.QuarantineInfected, "email_av.quarantine_infected", "false")
	add(cfg.AutoResponse.PHPRelay.Freeze != nil && *cfg.AutoResponse.PHPRelay.Freeze,
		"auto_response.php_relay.freeze", "false")
	add(cfg.AutoResponse.MailAuthRecovery.RestartEnabled,
		"auto_response.mail_auth_recovery.restart_enabled", "false")
	add(cfg.VirtualPatchMode() == VirtualPatchAuto,
		"auto_response.virtual_patch_exposed_files", "off or manual")

	return out
}

// validateMode rejects an unknown mode, and rejects an observe-mode config
// that still enables a subsystem which writes to the host. Every conflicting
// key is named in one error so an operator fixes the file in one pass.
func validateMode(cfg *Config) error {
	switch normalizeMode(cfg.Mode) {
	case ModeEnforce:
		return nil
	case ModeObserve:
	default:
		return fmt.Errorf("mode: %q is not a valid mode (use %q or %q)", cfg.Mode, ModeEnforce, ModeObserve)
	}

	conflicts := observeConflicts(cfg)
	if len(conflicts) == 0 {
		return nil
	}
	parts := make([]string, 0, len(conflicts))
	for _, c := range conflicts {
		parts = append(parts, fmt.Sprintf("%s (set %s)", c.key, c.want))
	}
	return fmt.Errorf("mode: observe forbids changing host state, but these keys still enable it: %s",
		strings.Join(parts, ", "))
}
