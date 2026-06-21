package checks

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/yara"
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

// VerifyInput carries everything a finding verifier may need. ContentSHA256 and
// DetectLogic are populated only for content findings emitted with a fingerprint.
type VerifyInput struct {
	Check, Message, Details, Path string
	ContentSHA256, DetectLogic    string
}

// presenceVerifiableChecks are findings whose remediation removes or
// quarantines a single flagged file, so the honest, cheap re-check is "is the
// flagged path still there?". Content-family checks are handled by
// reverifyContentFinding only when this package can re-run the same classifier
// that produced them; realtime PHP heuristic findings stay presence-based.
var presenceVerifiableChecks = []string{
	"webshell", "webshell_realtime",
	"webshell_content_realtime", "obfuscated_php_realtime",
	"php_dropper_realtime",
	"new_webshell_file", "new_suspicious_php",
	"new_php_in_sensitive_dir", "new_php_in_uploads",
	"php_in_sensitive_dir_realtime", "php_in_uploads_realtime",
	"suspicious_file",
	"nulled_plugin", "symlink_attack",
	"backdoor_binary", "new_executable_in_config",
	"executable_in_config_realtime", "executable_in_tmp_realtime",
	"cgi_backdoor_realtime", "cgi_suspicious_location_realtime",
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

var (
	contentSignatureScanner = signatures.Global
	contentYARAScanner      = yara.Active
)

func buildFindingVerifiers() map[string]func(VerifyInput) VerifyResult {
	m := map[string]func(VerifyInput) VerifyResult{}
	register := func(fn func(VerifyInput) VerifyResult, names ...string) {
		for _, n := range names {
			m[n] = fn
		}
	}

	register(func(in VerifyInput) VerifyResult { return verifyWriteBit(in.Path, 0002, "world-writable") },
		"world_writable_php")
	register(func(in VerifyInput) VerifyResult { return verifyWriteBit(in.Path, 0020, "group-writable") },
		"group_writable_php")
	register(func(in VerifyInput) VerifyResult { return verifyPathAbsent(in.Path, fixQuarantineAllowedRoots) },
		presenceVerifiableChecks...)
	register(reverifyContentFinding, contentReverifiableChecks...)
	register(func(in VerifyInput) VerifyResult { return verifyHtaccessClean(in.Path) },
		htaccessVerifiableChecks...)
	register(func(in VerifyInput) VerifyResult { return verifyEximSpoolAbsent(in.Message) },
		"email_phishing_content")
	register(func(in VerifyInput) VerifyResult { return verifyCrontabClear(in.Path) },
		"suspicious_crontab")
	register(func(in VerifyInput) VerifyResult { return verifyOutdatedPlugins(in.Details) },
		"outdated_plugins")
	register(func(in VerifyInput) VerifyResult { return verifyWPCoreIntegrity(in.Details) },
		"wp_core_integrity")
	register(func(in VerifyInput) VerifyResult { return verifyUID0Account(in.Message) },
		"uid0_account")
	register(func(in VerifyInput) VerifyResult { return verifySuidCleared(in.Path) },
		"suid_binary")
	register(func(in VerifyInput) VerifyResult { return verifyRPMIntegrity(in.Message) },
		"rpm_integrity")
	register(func(in VerifyInput) VerifyResult { return verifyDpkgIntegrity(in.Message) },
		"dpkg_integrity")
	register(func(in VerifyInput) VerifyResult { return verifyDBOptionsInjection(in.Message, in.Details) },
		"db_options_injection")
	register(func(in VerifyInput) VerifyResult { return verifyDBSiteurlHijack(in.Message, in.Details) },
		"db_siteurl_hijack")
	register(func(in VerifyInput) VerifyResult { return verifyDBPostInjection(in.Message, in.Details) },
		"db_post_injection")
	register(func(in VerifyInput) VerifyResult { return verifyDBSpamInjection(in.Message, in.Details) },
		"db_spam_injection")
	register(func(in VerifyInput) VerifyResult { return verifyDrupalSettingsInjection(in.Message, in.Details) },
		"drupal_settings_injection")
	register(func(in VerifyInput) VerifyResult { return verifyDrupalContentInjection(in.Message, in.Details) },
		"drupal_content_injection")
	register(func(in VerifyInput) VerifyResult { return verifyJoomlaExtensionsInjection(in.Message, in.Details) },
		"joomla_extensions_injection")
	register(func(in VerifyInput) VerifyResult { return verifyJoomlaContentInjection(in.Message, in.Details) },
		"joomla_content_injection")
	register(func(in VerifyInput) VerifyResult { return verifyMagentoSettingsInjection(in.Message, in.Details) },
		"magento_settings_injection")
	register(func(in VerifyInput) VerifyResult { return verifyMagentoContentInjection(in.Message, in.Details) },
		"magento_content_injection")
	register(func(in VerifyInput) VerifyResult { return verifyOpenCartSettingsInjection(in.Message, in.Details) },
		"opencart_settings_injection")
	register(func(in VerifyInput) VerifyResult { return verifyOpenCartContentInjection(in.Message, in.Details) },
		"opencart_content_injection")
	register(func(in VerifyInput) VerifyResult { return verifyDBObject(in.Message, in.Details, false) },
		"db_unexpected_trigger", "db_unexpected_event",
		"db_unexpected_procedure", "db_unexpected_function")
	register(func(in VerifyInput) VerifyResult { return verifyDBObject(in.Message, in.Details, true) },
		"db_malicious_trigger", "db_malicious_event",
		"db_malicious_procedure", "db_malicious_function")
	register(func(in VerifyInput) VerifyResult { return verifyDBMagicTokenUser(in.Message, in.Details) },
		"db_magic_token_user")
	register(func(in VerifyInput) VerifyResult { return verifyDBRogueAdmin(in.Message, in.Details) },
		"db_rogue_admin")
	register(func(in VerifyInput) VerifyResult { return verifyDBSuspiciousAdminEmail(in.Message, in.Details) },
		"db_suspicious_admin_email")
	register(func(in VerifyInput) VerifyResult { return verifyDrupalAdminInjection(in.Message, in.Details) },
		"drupal_admin_injection")
	register(func(in VerifyInput) VerifyResult { return verifyJoomlaAdminInjection(in.Message, in.Details) },
		"joomla_admin_injection")
	register(func(in VerifyInput) VerifyResult { return verifyMagentoAdminInjection(in.Message, in.Details) },
		"magento_admin_injection")
	register(func(in VerifyInput) VerifyResult { return verifyOpenCartAdminInjection(in.Message, in.Details) },
		"opencart_admin_injection")
	return m
}

// VerifyFinding re-evaluates a finding by check type + message/details/path.
// Preserved signature for CLI/legacy callers; carries no content fingerprint.
func VerifyFinding(checkType, message, details string, filePath ...string) VerifyResult {
	return VerifyFindingInput(VerifyInput{
		Check: checkType, Message: message, Details: details,
		Path: selectFindingPath(message, filePath...),
	})
}

// VerifyFindingInput re-evaluates a finding from a full VerifyInput. Callers
// that verify content findings must provide the stored detection fingerprint.
func VerifyFindingInput(in VerifyInput) VerifyResult {
	if in.Path == "" {
		in.Path = selectFindingPath(in.Message)
	}
	if fn, ok := findingVerifiers[in.Check]; ok {
		return fn(in)
	}
	return VerifyResult{Checked: false, Detail: fmt.Sprintf("no automated re-check available for '%s'", in.Check)}
}

// reverifyContentFinding re-runs the content classifier that originally
// produced the finding. It resolves only when the file is gone OR the file's
// bytes are byte-for-byte identical to detection time AND the current
// classifier no longer flags them -- a superseded-heuristic false positive.
// A file modified since detection is never auto-cleared to prevent partial
// cleans or evasion edits from being mistaken for a fix.
func reverifyContentFinding(in VerifyInput) VerifyResult {
	if in.Path == "" {
		return VerifyResult{Checked: false, Detail: "could not extract file path from finding"}
	}
	clean, info, exists, err := readOnlyFixPath(in.Path, fixQuarantineAllowedRoots)
	if err != nil {
		return VerifyResult{Checked: false, Detail: err.Error()}
	}
	if !exists {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("file no longer present (removed or quarantined): %s", clean)}
	}
	if !info.Mode().IsRegular() {
		return VerifyResult{Checked: false, Detail: "path is not a regular file; not auto-verifiable"}
	}
	matched, label, currentHash, err := contentStillMatches(in.Check, clean, info)
	if err != nil {
		return VerifyResult{Checked: false, Detail: err.Error()}
	}
	if matched {
		return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("still flagged by current detection logic: %s", label)}
	}
	switch {
	case in.ContentSHA256 != "" && currentHash != "" && currentHash == in.ContentSHA256:
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf(
			"identical content (sha256 unchanged) is no longer flagged by current detection logic (%s) -- superseded-heuristic false positive",
			ContentDetectionVersion())}
	case in.ContentSHA256 != "":
		return VerifyResult{Checked: true, Resolved: false, Detail: "file modified since detection (sha256 mismatch); not auto-cleared -- run a full rescan or review manually"}
	default:
		return VerifyResult{Checked: true, Resolved: false, Detail: "current detection logic no longer flags this file, but no detection-time fingerprint exists to rule out modification; review and dismiss if benign"}
	}
}

// contentStillMatches re-runs the appropriate classifier for the check type.
// For files small enough to fingerprint, the returned hash and classifier result
// come from the same opened content snapshot.
func contentStillMatches(check, path string, info os.FileInfo) (bool, string, string, error) {
	switch check {
	case "signature_match_realtime":
		s := contentSignatureScanner()
		if s == nil || s.RuleCount() == 0 {
			return false, "", "", fmt.Errorf("signature scanner unavailable")
		}
		snap, err := readContentSnapshotForReverify(path, info)
		if err != nil {
			return false, "", "", fmt.Errorf("cannot read file: %v", err)
		}
		if hits := s.ScanContent(snap.data, strings.ToLower(filepath.Ext(path))); len(hits) > 0 {
			return true, fmt.Sprintf("%d signature match(es)", len(hits)), snap.sha256, nil
		}
		return false, "", snap.sha256, nil
	case "yara_match_realtime":
		y := contentYARAScanner()
		if y == nil || y.RuleCount() == 0 {
			return false, "", "", fmt.Errorf("YARA scanner unavailable")
		}
		snap, err := readContentSnapshotForReverify(path, info)
		if err != nil {
			return false, "", "", fmt.Errorf("cannot read file: %v", err)
		}
		if hits := y.ScanBytes(snap.data); len(hits) > 0 {
			return true, fmt.Sprintf("%d YARA rule match(es)", len(hits)), snap.sha256, nil
		}
		return false, "", snap.sha256, nil
	default: // PHP heuristic content family
		res, currentHash, err := analyzePHPContentForReverify(path, info)
		if err != nil {
			return false, "", "", fmt.Errorf("cannot read file: %v", err)
		}
		if res.severity >= 0 {
			return true, strings.Join(res.indicators, ", "), currentHash, nil
		}
		return false, "", currentHash, nil
	}
}

func analyzePHPContentForReverify(path string, expected os.FileInfo) (phpAnalysisResult, string, error) {
	if expected != nil && expected.Size() <= contentFingerprintMaxBytes {
		snap, err := readContentSnapshotForReverify(path, expected)
		if err != nil {
			return phpAnalysisResult{}, "", err
		}
		res := analyzePHPContentReaderAt(path, bytes.NewReader(snap.data), int64(len(snap.data)))
		if !res.readOK {
			return phpAnalysisResult{}, "", fmt.Errorf("content read failed")
		}
		return res, snap.sha256, nil
	}

	f, info, err := openReadOnlyPreservingIdentity(path, expected)
	if err != nil {
		return phpAnalysisResult{}, "", err
	}
	defer func() { _ = f.Close() }()

	res := analyzePHPContentReaderAt(path, f, info.Size())
	if !res.readOK {
		return phpAnalysisResult{}, "", fmt.Errorf("content read failed")
	}
	return res, "", nil
}

type reverifyContentSnapshot struct {
	data   []byte
	sha256 string
}

func readContentSnapshotForReverify(path string, expected os.FileInfo) (reverifyContentSnapshot, error) {
	f, info, err := openReadOnlyPreservingIdentity(path, expected)
	if err != nil {
		return reverifyContentSnapshot{}, err
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(f)
	if err != nil {
		return reverifyContentSnapshot{}, err
	}
	after, err := f.Stat()
	if err != nil {
		return reverifyContentSnapshot{}, err
	}
	if !sameFileIdentity(after, info) || !sameCleanContentShape(after, info) {
		return reverifyContentSnapshot{}, fmt.Errorf("file changed during verification")
	}
	if int64(len(data)) != info.Size() {
		return reverifyContentSnapshot{}, fmt.Errorf("file changed during verification")
	}

	var digest string
	if info.Size() <= contentFingerprintMaxBytes {
		sum := sha256.Sum256(data)
		digest = fmt.Sprintf("%x", sum)
	}
	return reverifyContentSnapshot{data: data, sha256: digest}, nil
}

func openReadOnlyPreservingIdentity(path string, expected os.FileInfo) (*os.File, os.FileInfo, error) {
	// #nosec G304 -- path was validated by readOnlyFixPath against remediation
	// roots; O_NOFOLLOW plus sameFileIdentity fails closed on inode swap.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !sameFileIdentity(info, expected) || !sameCleanContentShape(info, expected) {
		_ = f.Close()
		return nil, nil, fmt.Errorf("file changed during verification")
	}
	return f, info, nil
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
