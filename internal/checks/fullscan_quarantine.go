package checks

import (
	"fmt"
	"os"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

// eligibleFullScanChecks is the set of check types that map to a pure file
// quarantine (fixQuarantine) in ApplyFix. These are the only checks eligible
// for full-scan --quarantine remediation.
//
// Explicitly excluded:
//   - backdoor_binary, new_executable_in_config → fixKillAndQuarantine (process kill forbidden)
//   - htaccess_* → file edit, not a move
//   - email_phishing_content → Exim spool, not a regular file
//   - suspicious_crontab → crontab truncate, not a pure file move
//   - world_writable_php, group_writable_php → chmod, not a move
var eligibleFullScanChecks = map[string]bool{
	"webshell":               true,
	"new_webshell_file":      true,
	"obfuscated_php":         true,
	"php_dropper":            true,
	"suspicious_php_content": true,
	"new_php_in_languages":   true,
	"new_php_in_upgrade":     true,
	"phishing_page":          true,
	"phishing_directory":     true,
}

// QuarantineFindingFile quarantines the file a malware/webshell finding points
// at, for the full-scan --quarantine path. It reuses fixQuarantine (move to the
// quarantine dir + .meta sidecar) and deliberately covers ONLY the pure
// file-quarantine check set — it never kills processes, cleans databases, or
// touches the firewall. Returns eligible=false for any finding that is not a
// quarantinable malware/webshell FILE finding (caller marks those
// "left_for_review").
//
// The job runs unattended, so it gets the same bar the scheduled auto-response
// applies: only a Critical finding (two converging indicators) may act, only on
// a regular file that is not a symlink, never on a whole directory, and a
// WordPress core, plugin or theme file is cleaned in place rather than moved,
// because moving it takes the site down while only the injected code had to go.
func QuarantineFindingFile(f alert.Finding) (RemediationResult, bool) {
	if !eligibleFullScanChecks[f.Check] || f.FilePath == "" || f.Severity != alert.Critical {
		return RemediationResult{}, false
	}
	info, err := osFS.Lstat(f.FilePath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return RemediationResult{}, false
	}
	if ShouldCleanInsteadOfQuarantine(f.FilePath) {
		clean := CleanInfectedFile(f.FilePath)
		switch {
		case clean.Cleaned:
			return RemediationResult{
				Success:           true,
				Action:            fmt.Sprintf("cleaned %s in place", f.FilePath),
				Description:       fmt.Sprintf("Removed: %s (backup: %s)", strings.Join(clean.Removals, "; "), clean.BackupPath),
				RemediationStatus: "cleaned",
			}, true
		case clean.Error == "":
			// Nothing the cleaner recognises: a core file with no removable
			// injection is an operator decision, not a move.
			return RemediationResult{}, false
		default:
			// Moving a WordPress core, plugin or theme file after the safer
			// clean failed defeats this branch's purpose and can take the site
			// down. Leave the file in place and report the failed remediation.
			return RemediationResult{Error: fmt.Sprintf("cleaning %s in place: %s", f.FilePath, clean.Error)}, true
		}
	}
	return fixQuarantine(f.FilePath), true
}
