package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// presenceVerifiableChecks are findings whose remediation removes or
// quarantines a single flagged file, so the honest, cheap re-check is "is the
// flagged path still there?". Resolving only on confirmed absence (never on a
// stat error) cannot falsely clear a still-present threat. We deliberately do
// NOT re-run content scanning here: a file that is still present but edited
// stays reported, so a partial clean is never mistaken for a fix.
var presenceVerifiableChecks = []string{
	"webshell", "webshell_realtime", "webshell_content_realtime",
	"new_webshell_file",
	"obfuscated_php", "obfuscated_php_realtime",
	"php_dropper_realtime",
	"suspicious_php_content", "suspicious_file",
	"new_php_in_sensitive_dir", "new_php_in_uploads", "new_suspicious_php",
	"php_in_sensitive_dir_realtime", "php_in_uploads_realtime",
	"nulled_plugin", "symlink_attack",
	"backdoor_binary", "new_executable_in_config",
	"executable_in_config_realtime", "executable_in_tmp_realtime",
	"cgi_backdoor_realtime", "cgi_suspicious_location_realtime",
	"yara_match_realtime", "signature_match_realtime",
	"phishing_page", "phishing_directory", "phishing_php",
	"phishing_kit_archive", "phishing_kit_realtime", "phishing_iframe",
	"phishing_redirector", "phishing_credential_log", "phishing_realtime",
	"credential_log_realtime",
}

// htaccessVerifiableChecks re-audit the .htaccess and resolve when no malicious
// directive remains (or the file is gone).
var htaccessVerifiableChecks = []string{
	"htaccess_injection", "htaccess_injection_realtime", "htaccess_handler_abuse",
	"htaccess_auto_prepend", "htaccess_errordocument_hijack",
	"htaccess_filesmatch_shield", "htaccess_header_injection",
	"htaccess_php_in_uploads", "htaccess_spam_redirect",
	"htaccess_user_agent_cloak",
}

// findingVerifiers maps a finding's Check to a read-only re-check. A check not
// present here has no automated re-check -- either an event finding (a brute
// force, a past login: history cannot be re-evaluated by reading current state)
// or a condition we cannot yet cheaply and safely confirm. CanVerify reports
// membership so the Web UI shows the "Re-check" action only where it can act.
var findingVerifiers = buildFindingVerifiers()

func buildFindingVerifiers() map[string]func(checkType, message, details, path string) VerifyResult {
	m := map[string]func(checkType, message, details, path string) VerifyResult{}
	register := func(fn func(checkType, message, details, path string) VerifyResult, names ...string) {
		for _, n := range names {
			m[n] = fn
		}
	}

	register(func(_, _, _, p string) VerifyResult { return verifyWriteBit(p, 0002, "world-writable") },
		"world_writable_php")
	register(func(_, _, _, p string) VerifyResult { return verifyWriteBit(p, 0020, "group-writable") },
		"group_writable_php")
	register(func(_, _, _, p string) VerifyResult { return verifyPathAbsent(p, fixQuarantineAllowedRoots) },
		presenceVerifiableChecks...)
	register(func(_, _, _, p string) VerifyResult { return verifyHtaccessClean(p) },
		htaccessVerifiableChecks...)
	register(func(_, msg, _, _ string) VerifyResult { return verifyEximSpoolAbsent(msg) },
		"email_phishing_content")
	register(func(_, _, _, p string) VerifyResult { return verifyCrontabClear(p) },
		"suspicious_crontab")
	register(func(_, _, details, _ string) VerifyResult { return verifyOutdatedPlugins(details) },
		"outdated_plugins")
	register(func(_, _, details, _ string) VerifyResult { return verifyWPCoreIntegrity(details) },
		"wp_core_integrity")
	register(func(_, msg, _, _ string) VerifyResult { return verifyUID0Account(msg) },
		"uid0_account")
	register(func(_, _, _, p string) VerifyResult { return verifySuidCleared(p) },
		"suid_binary")
	register(func(_, msg, _, _ string) VerifyResult { return verifyRPMIntegrity(msg) },
		"rpm_integrity")
	register(func(_, msg, _, _ string) VerifyResult { return verifyDpkgIntegrity(msg) },
		"dpkg_integrity")
	return m
}

// VerifyFinding re-evaluates a finding's condition against the live filesystem
// so an operator can confirm a manual fix without waiting for the next scan.
// It only reads state; it never modifies anything.
func VerifyFinding(checkType, message, details string, filePath ...string) VerifyResult {
	path := selectFindingPath(message, filePath...)
	if fn, ok := findingVerifiers[checkType]; ok {
		return fn(checkType, message, details, path)
	}
	return VerifyResult{Checked: false, Detail: fmt.Sprintf("no automated re-check available for '%s'", checkType)}
}

// CanVerify reports whether VerifyFinding has an automated re-check for the
// given check type. The Web UI gates the per-finding "Re-check" action on this
// so it never shows a button that could only report "not auto-verifiable".
func CanVerify(checkType string) bool {
	_, ok := findingVerifiers[checkType]
	return ok
}

func verifyWriteBit(path string, bit os.FileMode, label string) VerifyResult {
	if path == "" {
		return VerifyResult{Checked: false, Detail: "could not extract file path from finding"}
	}
	clean, info, exists, err := readOnlyFixPath(path, fixPermissionsAllowedRoots)
	if err != nil {
		return VerifyResult{Checked: false, Detail: err.Error()}
	}
	if !exists {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("file no longer exists: %s", clean)}
	}
	if !info.Mode().IsRegular() {
		return VerifyResult{Checked: false, Detail: "path is not a regular file; not auto-verifiable"}
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
	clean, exists, err := readOnlyPathPresence(path, roots)
	if err != nil {
		return VerifyResult{Checked: false, Detail: err.Error()}
	}
	if !exists {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("file no longer present (removed or quarantined): %s", clean)}
	}
	return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("file is still present: %s", clean)}
}

func verifyHtaccessClean(path string) VerifyResult {
	if path == "" {
		return VerifyResult{Checked: false, Detail: "could not extract file path from finding"}
	}
	clean, info, exists, err := readOnlyFixPath(path, fixHtaccessAllowedRoots)
	if err != nil {
		return VerifyResult{Checked: false, Detail: err.Error()}
	}
	if filepath.Base(clean) != ".htaccess" {
		return VerifyResult{Checked: false, Detail: "not a .htaccess file; not auto-verifiable"}
	}
	if !exists {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf(".htaccess no longer exists: %s", clean)}
	}
	if !info.Mode().IsRegular() {
		return VerifyResult{Checked: false, Detail: ".htaccess path is not a regular file; not auto-verifiable"}
	}
	content, err := readFilePreservingIdentity(clean, info)
	if err != nil {
		return VerifyResult{Checked: false, Detail: fmt.Sprintf("cannot read .htaccess: %v", err)}
	}
	findings, _ := auditHtaccessContent(clean, content)
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
		if _, err := osFS.Lstat(filepath.Join(dir, msgID+"-H")); err == nil {
			return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("spool message %s is still queued", msgID)}
		} else if !os.IsNotExist(err) {
			return VerifyResult{Checked: false, Detail: fmt.Sprintf("cannot stat spool message %s: %v", msgID, err)}
		}
	}
	return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("spool message %s no longer present (delivered or removed)", msgID)}
}

func verifyCrontabClear(path string) VerifyResult {
	if path == "" {
		return VerifyResult{Checked: false, Detail: "could not extract crontab path from finding"}
	}
	clean, info, exists, err := readOnlyFixPath(path, fixCrontabAllowedRoots)
	if err != nil {
		return VerifyResult{Checked: false, Detail: err.Error()}
	}
	if !exists {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("crontab no longer exists: %s", clean)}
	}
	if !info.Mode().IsRegular() {
		return VerifyResult{Checked: false, Detail: "crontab path is not a regular file; not auto-verifiable"}
	}
	if info.Size() == 0 {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("crontab is empty: %s", clean)}
	}
	// A non-empty crontab may still be legitimate; re-scanning its content is
	// out of scope for a single-finding re-check, so report it as still
	// present rather than guessing.
	return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("crontab is still present and non-empty: %s", clean)}
}

func readOnlyFixPath(path string, allowedRoots []string) (string, os.FileInfo, bool, error) {
	clean, err := sanitizeFixPath(path, allowedRoots)
	if err != nil {
		return "", nil, false, err
	}
	root := matchingAllowedRoot(clean, allowedRoots)
	if root == "" {
		return "", nil, false, fmt.Errorf("file path is outside the allowed remediation roots: %s", clean)
	}

	current := root
	info, err := osFS.Lstat(current)
	if err != nil {
		if os.IsNotExist(err) {
			return clean, nil, false, nil
		}
		return "", nil, false, fmt.Errorf("cannot stat: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", nil, false, fmt.Errorf("symlinked paths are not eligible for automated verification: %s", current)
	}
	if current == clean {
		return clean, info, true, nil
	}

	rel, err := filepath.Rel(current, clean)
	if err != nil {
		return "", nil, false, fmt.Errorf("cannot resolve path under allowed root: %v", err)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if !info.IsDir() {
			return "", nil, false, fmt.Errorf("path ancestor is not a directory; not auto-verifiable: %s", current)
		}
		current = filepath.Join(current, part)
		info, err = osFS.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				return clean, nil, false, nil
			}
			return "", nil, false, fmt.Errorf("cannot stat: %v", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", nil, false, fmt.Errorf("symlinked paths are not eligible for automated verification: %s", current)
		}
		if i < len(parts)-1 && !info.IsDir() {
			return "", nil, false, fmt.Errorf("path ancestor is not a directory; not auto-verifiable: %s", current)
		}
	}
	return clean, info, true, nil
}

func readOnlyPathPresence(path string, allowedRoots []string) (string, bool, error) {
	clean, err := sanitizeFixPath(path, allowedRoots)
	if err != nil {
		return "", false, err
	}
	root := matchingAllowedRoot(clean, allowedRoots)
	if root == "" {
		return "", false, fmt.Errorf("file path is outside the allowed remediation roots: %s", clean)
	}

	current := root
	info, err := osFS.Lstat(current)
	if err != nil {
		if os.IsNotExist(err) {
			return clean, false, nil
		}
		return "", false, fmt.Errorf("cannot stat: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", false, fmt.Errorf("symlinked paths are not eligible for automated verification: %s", current)
	}
	if current == clean {
		return clean, true, nil
	}

	rel, err := filepath.Rel(current, clean)
	if err != nil {
		return "", false, fmt.Errorf("cannot resolve path under allowed root: %v", err)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if !info.IsDir() {
			return "", false, fmt.Errorf("path ancestor is not a directory; not auto-verifiable: %s", current)
		}
		current = filepath.Join(current, part)
		info, err = osFS.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				return clean, false, nil
			}
			return "", false, fmt.Errorf("cannot stat: %v", err)
		}
		if i < len(parts)-1 {
			if info.Mode()&os.ModeSymlink != 0 {
				return "", false, fmt.Errorf("symlinked paths are not eligible for automated verification: %s", current)
			}
			if !info.IsDir() {
				return "", false, fmt.Errorf("path ancestor is not a directory; not auto-verifiable: %s", current)
			}
		}
	}
	return clean, true, nil
}

func matchingAllowedRoot(path string, allowedRoots []string) string {
	var best string
	for _, root := range allowedRoots {
		cleanRoot := filepath.Clean(strings.TrimSpace(root))
		if isPathWithinOrEqual(path, cleanRoot) && len(cleanRoot) > len(best) {
			best = cleanRoot
		}
	}
	return best
}
