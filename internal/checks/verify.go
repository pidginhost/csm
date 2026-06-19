package checks

import (
	"fmt"
	"os"
	"path/filepath"
)

// VerifyResult reports whether a finding's underlying condition still holds.
//
// Checked is false when the finding's check type has no cheap, reliable
// single-target re-check (the caller should tell the operator to dismiss after
// manual review or run a full account scan). When Checked is true, Resolved
// reports whether the condition is gone and the finding can be cleared.
type VerifyResult struct {
	Checked  bool   `json:"checked"`
	Resolved bool   `json:"resolved"`
	Detail   string `json:"detail"`
}

// VerifyFinding re-evaluates a finding's condition against the live filesystem
// so an operator can confirm a manual fix without waiting for the next scan.
// It only reads state; it never modifies anything.
func VerifyFinding(checkType, message, details string, filePath ...string) VerifyResult {
	path := selectFindingPath(message, filePath...)

	switch checkType {
	case "world_writable_php":
		return verifyWriteBit(path, 0002, "world-writable")
	case "group_writable_php":
		return verifyWriteBit(path, 0020, "group-writable")
	case "webshell", "new_webshell_file", "obfuscated_php", "php_dropper",
		"suspicious_php_content", "new_php_in_languages", "new_php_in_upgrade",
		"phishing_page", "phishing_directory", "backdoor_binary",
		"new_executable_in_config":
		// These fixes quarantine/remove the file. The honest, cheap signal is
		// presence: if the flagged path is gone it was remediated; if it is
		// still there the threat file remains (we do not re-run content
		// scanning here, which would be heavy and could mask a partial clean).
		return verifyPathAbsent(path, fixQuarantineAllowedRoots)
	case "htaccess_injection", "htaccess_handler_abuse",
		"htaccess_auto_prepend", "htaccess_errordocument_hijack",
		"htaccess_filesmatch_shield", "htaccess_header_injection",
		"htaccess_php_in_uploads", "htaccess_spam_redirect",
		"htaccess_user_agent_cloak":
		return verifyHtaccessClean(path)
	case "email_phishing_content":
		return verifyEximSpoolAbsent(message)
	case "suspicious_crontab":
		return verifyCrontabClear(path)
	default:
		return VerifyResult{Checked: false, Detail: fmt.Sprintf("no automated re-check available for '%s'", checkType)}
	}
}

func verifyWriteBit(path string, bit os.FileMode, label string) VerifyResult {
	if path == "" {
		return VerifyResult{Checked: false, Detail: "could not extract file path from finding"}
	}
	clean, err := sanitizeFixPath(path, fixPermissionsAllowedRoots)
	if err != nil {
		return VerifyResult{Checked: false, Detail: err.Error()}
	}
	info, err := osFS.Lstat(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("file no longer exists: %s", clean)}
		}
		return VerifyResult{Checked: false, Detail: fmt.Sprintf("cannot stat: %v", err)}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return VerifyResult{Checked: false, Detail: "path is a symlink; not auto-verifiable"}
	}
	if info.Mode().Perm()&bit == 0 {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("file is no longer %s (mode %o)", label, info.Mode().Perm())}
	}
	return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("file is still %s (mode %o)", label, info.Mode().Perm())}
}

func verifyPathAbsent(path string, roots []string) VerifyResult {
	if path == "" {
		return VerifyResult{Checked: false, Detail: "could not extract file path from finding"}
	}
	clean, err := sanitizeFixPath(path, roots)
	if err != nil {
		return VerifyResult{Checked: false, Detail: err.Error()}
	}
	if _, err := osFS.Lstat(clean); err != nil {
		if os.IsNotExist(err) {
			return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("file no longer present (removed or quarantined): %s", clean)}
		}
		return VerifyResult{Checked: false, Detail: fmt.Sprintf("cannot stat: %v", err)}
	}
	return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("file is still present: %s", clean)}
}

func verifyHtaccessClean(path string) VerifyResult {
	if path == "" {
		return VerifyResult{Checked: false, Detail: "could not extract file path from finding"}
	}
	clean, err := sanitizeFixPath(path, fixHtaccessAllowedRoots)
	if err != nil {
		return VerifyResult{Checked: false, Detail: err.Error()}
	}
	if filepath.Base(clean) != ".htaccess" {
		return VerifyResult{Checked: false, Detail: "not a .htaccess file; not auto-verifiable"}
	}
	if _, err := osFS.Lstat(clean); err != nil {
		if os.IsNotExist(err) {
			return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf(".htaccess no longer exists: %s", clean)}
		}
		return VerifyResult{Checked: false, Detail: fmt.Sprintf("cannot stat: %v", err)}
	}
	findings, _ := AuditHtaccessFile(clean)
	if len(findings) == 0 {
		return VerifyResult{Checked: true, Resolved: true, Detail: "no malicious directives remain in .htaccess"}
	}
	return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("%d malicious directive(s) still present in .htaccess", len(findings))}
}

func verifyEximSpoolAbsent(message string) VerifyResult {
	msgID := extractEximMsgID(message)
	if msgID == "" {
		return VerifyResult{Checked: false, Detail: "could not extract Exim message ID from finding"}
	}
	if !eximMsgIDRegex.MatchString(msgID) {
		return VerifyResult{Checked: false, Detail: fmt.Sprintf("invalid Exim message ID format: %s", msgID)}
	}
	for _, dir := range eximSpoolDirs {
		if _, err := osFS.Stat(filepath.Join(dir, msgID+"-H")); err == nil {
			return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("spool message %s is still queued", msgID)}
		}
	}
	return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("spool message %s no longer present (delivered or removed)", msgID)}
}

func verifyCrontabClear(path string) VerifyResult {
	if path == "" {
		return VerifyResult{Checked: false, Detail: "could not extract crontab path from finding"}
	}
	clean, err := sanitizeFixPath(path, fixCrontabAllowedRoots)
	if err != nil {
		return VerifyResult{Checked: false, Detail: err.Error()}
	}
	info, err := osFS.Lstat(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("crontab no longer exists: %s", clean)}
		}
		return VerifyResult{Checked: false, Detail: fmt.Sprintf("cannot stat: %v", err)}
	}
	if info.Size() == 0 {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("crontab is empty: %s", clean)}
	}
	// A non-empty crontab may still be legitimate; re-scanning its content is
	// out of scope for a single-finding re-check, so report it as still
	// present rather than guessing.
	return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("crontab is still present and non-empty: %s", clean)}
}
