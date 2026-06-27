package daemon

import "os"

// phpShieldScriptPath is where the installer deploys the PHP auto_prepend
// shield. It must match cmd/csm/installer.go phpShieldPath; the daemon uses it
// only to detect whether the shield is actually installed before tailing its
// event log.
const phpShieldScriptPath = "/opt/csm/php_shield.php"

// phpShieldInstalled reports whether the PHP shield script is deployed on disk.
func phpShieldInstalled() bool {
	_, err := os.Stat(phpShieldScriptPath)
	return err == nil
}

// phpShieldWatchDecision decides, from the config flag and whether the shield
// script is installed, whether the daemon should tail the shield event log and
// whether it should warn that the shield is enabled but not installed.
//
// When php_shield.enabled is true but the shield was never installed (or an
// upgrade wiped /opt/csm), tailing the event log spins the missing-file log
// watcher retry forever. Instead we warn once with a remediation hint, so the
// misprovision is surfaced rather than masked or spammed.
func phpShieldWatchDecision(enabled, scriptExists bool) (watch, warnNotInstalled bool) {
	if !enabled {
		return false, false
	}
	if scriptExists {
		return true, false
	}
	return false, true
}
