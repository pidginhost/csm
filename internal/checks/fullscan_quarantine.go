package checks

import "github.com/pidginhost/csm/internal/alert"

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
func QuarantineFindingFile(f alert.Finding) (RemediationResult, bool) {
	if !eligibleFullScanChecks[f.Check] {
		return RemediationResult{}, false
	}
	if f.FilePath == "" {
		return RemediationResult{}, false
	}
	return fixQuarantine(f.FilePath), true
}
