package checks

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pidginhost/csm/internal/quarantinefs"
)

// fixCrontabAllowedRoots limits suspicious_crontab remediation to the cron
// spool. Declared as a var so tests can redirect it under t.TempDir()
// without touching the real /var/spool/cron.
var fixCrontabAllowedRoots = []string{"/var/spool/cron"}

// fixSuspiciousCrontab copies a user crontab matching known-bad persistence
// markers into quarantine, writes a restore-ready metadata sidecar, and then
// truncates the live file to empty. Truncation (not deletion) keeps cron(8)
// from re-reading stale content and preserves the caller's ability to
// inspect file perms while the malware is gone.
func fixSuspiciousCrontab(path string) RemediationResult {
	if path == "" {
		return RemediationResult{Error: "could not extract file path from finding"}
	}

	path, info, err := resolveExistingFixPath(path, fixCrontabAllowedRoots)
	if err != nil {
		return RemediationResult{Error: err.Error()}
	}

	data, err := osFS.ReadFile(path)
	if err != nil {
		return RemediationResult{Error: fmt.Sprintf("cannot read: %v", err)}
	}

	user := filepath.Base(path)
	qPath := newQuarantinePath(quarantineDir, "crontab_"+user)

	meta := quarantineMetadata(path, info, "suspicious_crontab remediation")
	if err := storeQuarantineBackup(qPath, data, meta, 0600); err != nil {
		return RemediationResult{Error: fmt.Sprintf("cannot create durable crontab backup: %v", err)}
	}

	// Truncate live crontab. 0600 is the mode cron(8) enforces for user
	// spool files; any other mode makes cron skip the file with a warning.
	// #nosec G306 -- cron(8) rejects world-readable user crontabs, so 0600
	// is the only safe mode for /var/spool/cron/<user>.
	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		return RemediationResult{Error: fmt.Sprintf("cannot truncate crontab: %v", err)}
	}
	if err := quarantinefs.SyncFilePath(path); err != nil {
		return RemediationResult{Error: fmt.Sprintf("crontab truncated but not synced; recovery copy retained at %s: %v", qPath, err)}
	}

	return RemediationResult{
		Success:     true,
		Action:      fmt.Sprintf("quarantined crontab %s -> %s and truncated", path, qPath),
		Description: fmt.Sprintf("Truncated %d-byte crontab; copy saved to quarantine", len(data)),
	}
}
