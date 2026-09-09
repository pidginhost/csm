package checks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/pidginhost/csm/internal/actionlog"
)

// quarantineMoveChecks are the findings whose manual fix, and whose
// full-scan quarantine, is a plain move of the named file into quarantine.
// The automatic responder's broader set lives in autoQuarantineChecks; the
// full-scan set must stay equal to this one (pinned by test).
var quarantineMoveChecks = map[string]bool{
	"webshell":               true,
	"new_webshell_file":      true,
	"obfuscated_php":         true,
	"suspicious_php_content": true,
	"new_php_in_languages":   true,
	"new_php_in_upgrade":     true,
	"phishing_page":          true,
	"phishing_directory":     true,
}

// eximMsgIDRegex validates Exim message ID format. Exim 4.96 and older use
// 6-6-2 ids; Exim 4.97 and newer use 6-11-4 ids.
var eximMsgIDRegex = regexp.MustCompile(`^[0-9A-Za-z]{6}-(?:[0-9A-Za-z]{6}-[0-9A-Za-z]{2}|[0-9A-Za-z]{11}-[0-9A-Za-z]{4})$`)

// Allowed roots for each fix action. Declared as vars (not consts) so tests
// can redirect remediation under t.TempDir() without writing to real /home,
// /tmp, or /var/spool. Production must not mutate these at runtime.
// A nil list means "the platform's account roots" (plus, for quarantine,
// the temp trees in quarantineExtraRoots); see effectiveFixRoots.
var (
	fixPermissionsAllowedRoots []string
	fixQuarantineAllowedRoots  []string
	fixHtaccessAllowedRoots    []string
	eximSpoolDirs              = []string{"/var/spool/exim/input", "/var/spool/exim4/input"}
)

// chmodFunc performs the permission change for fixPermissions. It is a var so
// tests can simulate failures (e.g. a read-only mount returning EROFS) without
// an actual read-only filesystem, and assert an already-compliant file is
// never chmodded.
var chmodFunc = os.Chmod

// RemediationResult describes the outcome of a fix action.
type RemediationResult struct {
	Success     bool   `json:"success"`
	Action      string `json:"action"`      // human-readable description of what was done
	Description string `json:"description"` // what fix was applied
	Error       string `json:"error,omitempty"`
	// RemediationStatus lets a caller that supports more than one successful
	// disposition distinguish an in-place clean from whole-file quarantine.
	// It is transport metadata, not part of the generic remediation API.
	RemediationStatus string `json:"-"`
	// Reverted marks a virtual patch that had to be written again because
	// something removed or damaged CSM's earlier block -- typically a backup
	// plugin rewriting the .htaccess it owns.
	Reverted bool `json:"reverted,omitempty"`
}

// FixDescription returns a human-readable description of what the fix will do
// for a given check type and file path. Returns empty string if no fix is available.
func FixDescription(checkType, message string, filePath ...string) string {
	path := selectFindingPath(message, filePath...)
	if isHtaccessHardenedFinding(checkType) {
		if path != "" {
			return fmt.Sprintf("Remove malicious directives from %s", path)
		}
		return ""
	}

	if quarantineMoveChecks[checkType] {
		if path != "" {
			return fmt.Sprintf("Quarantine %s to /opt/csm/quarantine/", path)
		}
		return ""
	}

	switch checkType {
	case "world_writable_php", "group_writable_php":
		if path != "" {
			return fmt.Sprintf("Set permissions to 644 on %s", path)
		}
	case "backdoor_binary", "new_executable_in_config":
		if path != "" {
			return fmt.Sprintf("Kill process and quarantine %s", path)
		}
	case "suspicious_crontab":
		if path != "" {
			return fmt.Sprintf("Quarantine and truncate crontab %s", path)
		}
		return "Quarantine and truncate crontab"
	case "htaccess_injection", "htaccess_handler_abuse":
		if path != "" {
			return fmt.Sprintf("Remove malicious directives from %s", path)
		}
	case "email_phishing_content":
		msgID := extractEximMsgID(message)
		if msgID != "" {
			return fmt.Sprintf("Quarantine Exim spool message %s", msgID)
		}
	}
	return ""
}

// HasFix returns true if the check type has a known automated fix.
func HasFix(checkType string) bool {
	if isHtaccessHardenedFinding(checkType) || quarantineMoveChecks[checkType] {
		return true
	}
	fixableChecks := map[string]bool{
		"world_writable_php":       true,
		"group_writable_php":       true,
		"backdoor_binary":          true,
		"new_executable_in_config": true,
		"htaccess_injection":       true,
		"htaccess_handler_abuse":   true,
		"email_phishing_content":   true,
		"suspicious_crontab":       true,
	}
	return fixableChecks[checkType]
}

// ApplyFix executes the remediation action for a finding.
func ApplyFix(ctx context.Context, checkType, message, details string, filePath ...string) RemediationResult {
	if err := ctx.Err(); err != nil {
		return RemediationResult{Error: err.Error()}
	}
	path := selectFindingPath(message, filePath...)
	if isHtaccessHardenedFinding(checkType) {
		// CleanHtaccessFile re-runs the full detector registry, so a single
		// action removes every malicious directive the audit found.
		return CleanHtaccessFile(path)
	}

	if quarantineMoveChecks[checkType] {
		return fixQuarantine(path)
	}

	switch checkType {
	case "world_writable_php", "group_writable_php":
		return fixPermissions(path, checkType)
	case "backdoor_binary", "new_executable_in_config":
		return fixKillAndQuarantine(ctx, path, details)
	case "htaccess_injection", "htaccess_handler_abuse":
		return fixHtaccess(path, message)
	case "email_phishing_content":
		return fixQuarantineSpoolMessage(message)
	case "suspicious_crontab":
		return fixSuspiciousCrontab(path)
	default:
		return RemediationResult{Error: fmt.Sprintf("no automated fix available for check type '%s'", checkType)}
	}
}

// fixPermissions sets file permissions to 0644. checkType selects which write
// bit is the dangerous one: world-writable (0002) for world_writable_php,
// group-writable (0020) for group_writable_php.
//
// If the file no longer carries that bit -- because an operator already fixed
// it by hand, or it changed since the scan -- the finding is treated as
// already resolved and no chmod is attempted. This is the path an operator
// hits when they manually correct perms and then click "Apply automated fix":
// rather than erroring, the finding clears.
func fixPermissions(path, checkType string) RemediationResult {
	if path == "" {
		return RemediationResult{Error: "could not extract file path from finding"}
	}

	path, info, err := resolveExistingFixPath(path, effectiveFixRoots(fixPermissionsAllowedRoots))
	if err != nil {
		return RemediationResult{Error: err.Error()}
	}

	oldMode := info.Mode().Perm()
	dangerBit, label := os.FileMode(0002), "world-writable"
	if checkType == "group_writable_php" {
		dangerBit, label = 0020, "group-writable"
	}
	if oldMode&dangerBit == 0 {
		return RemediationResult{
			Success:     true,
			Action:      fmt.Sprintf("verified %s: no longer %s (mode %o)", path, label, oldMode),
			Description: fmt.Sprintf("File is already not %s; no change needed", label),
		}
	}

	// #nosec G302 -- Intentional: this is the remediation that sets the
	// canonical "safe web content" mode on a user file after we flagged
	// the file as having dangerous perms (e.g. 0777). 0644 is what the
	// webserver needs to serve static content as the file owner.
	if err := chmodFunc(path, 0644); err != nil {
		if errors.Is(err, syscall.EROFS) {
			return RemediationResult{Error: fmt.Sprintf(
				"cannot fix %s: the file is on a read-only mount (e.g. a backup snapshot or bind mount), not the live site. Dismiss or suppress this finding instead.",
				path)}
		}
		return RemediationResult{Error: fmt.Sprintf("chmod failed: %v", err)}
	}

	return RemediationResult{
		Success:     true,
		Action:      fmt.Sprintf("chmod 644 %s", path),
		Description: fmt.Sprintf("Changed permissions from %o to 644", oldMode),
	}
}

// fixQuarantine moves a file or directory to quarantine.
func fixQuarantine(path string) RemediationResult {
	if path == "" {
		return RemediationResult{Error: "could not extract file path from finding"}
	}

	path, info, err := resolveExistingFixPath(path, effectiveFixRoots(fixQuarantineAllowedRoots, quarantineExtraRoots...))
	if err != nil {
		return RemediationResult{Error: err.Error()}
	}
	return quarantineResolvedTarget(path, info)
}

// quarantineResolvedTarget quarantines the exact object admitted by the
// caller's boundary check. Regular-file quarantine reopens the path and
// verifies this identity before copying or unlinking it.
func quarantineResolvedTarget(path string, info os.FileInfo) RemediationResult {

	qPath := newQuarantinePath(quarantineDir, path)
	var quarantineWarning string

	meta := quarantineMetadata(path, info, "Fixed via CSM Web UI")
	if err := quarantineTarget(path, qPath, info, meta); err != nil {
		var completed bool
		quarantineWarning, completed = completedQuarantineWarning(err)
		if !completed {
			return RemediationResult{Error: err.Error()}
		}
	}

	description := fmt.Sprintf("Moved to quarantine: %s", qPath)
	if quarantineWarning != "" {
		description += ". Warning: " + quarantineWarning
	}
	return RemediationResult{
		Success:     true,
		Action:      fmt.Sprintf("quarantined %s -> %s", path, qPath),
		Description: description,
	}
}

// fixKillAndQuarantine kills any process using the file, then quarantines it.
func fixKillAndQuarantine(ctx context.Context, path, details string) RemediationResult {
	if path == "" {
		return RemediationResult{Error: "could not extract file path from finding"}
	}
	resolvedPath, target, err := resolveExistingFixPath(path, effectiveFixRoots(fixQuarantineAllowedRoots, quarantineExtraRoots...))
	if err != nil {
		return RemediationResult{Error: err.Error()}
	}
	path = resolvedPath

	// Try to extract and kill PID from details
	pid := extractPID(details)
	killed := false
	var signalErr error
	if pidInt, ok := parseProcessPID(pid); ok {
		pid = strconv.Itoa(pidInt)
		signalErr = signalProcess(ctx, pidInt, syscall.SIGKILL, func() error {
			uid := getProcessUID(pid)
			if uid == "0" || uid == "" || !processUsesFileIdentity(pidInt, target) {
				return errProcessNotEligible
			}
			return nil
		})
		recordKillAction(nil, pid, path, signalErr)
		killed = signalErr == nil
		if errors.Is(signalErr, errProcessNotEligible) || errors.Is(signalErr, os.ErrProcessDone) {
			signalErr = nil
		}
	}
	if err := ctx.Err(); err != nil && !killed {
		return RemediationResult{Error: err.Error()}
	}

	// Quarantine the same object used for the process decision. If the path was
	// replaced after validation, the pinned-identity quarantine refuses it.
	result := quarantineResolvedTarget(path, target)
	if signalErr != nil {
		result.Success = false
		if result.Error != "" {
			result.Error += "; "
		}
		result.Error += "process was not stopped: " + signalErr.Error()
	}
	if killed {
		if result.Success {
			result.Action = fmt.Sprintf("killed PID %s and %s", pid, result.Action)
			result.Description = "Process killed and file quarantined"
		} else {
			result.Action = fmt.Sprintf("killed PID %s; quarantine failed", pid)
			result.Description = "Process killed, but the file was not quarantined"
		}
	}
	return result
}

// fixHtaccess removes malicious directives from an .htaccess file while
// preserving comments and known-safe directives (e.g., Wordfence, LiteSpeed).
func fixHtaccess(path, message string) (result RemediationResult) {
	audit := newCleanAction(path)
	defer func() { audit.finish(result.Error) }()
	if path == "" {
		return RemediationResult{Error: "could not extract file path"}
	}
	if filepath.Base(path) != ".htaccess" {
		return RemediationResult{Error: "automated .htaccess remediation only applies to .htaccess files"}
	}
	path, _, err := resolveExistingFixPath(path, effectiveFixRoots(fixHtaccessAllowedRoots))
	if err != nil {
		return RemediationResult{Error: err.Error()}
	}
	// Same pinned-inode read and atomic replace as CleanHtaccessFile: the
	// directory belongs to the account, so nothing here may follow a path
	// the owner can redirect between the check and the write.
	target, err := openCleanTarget(path)
	if err != nil {
		return RemediationResult{Error: fmt.Sprintf("cannot open: %v", err)}
	}
	defer target.Close()
	audit.rec.Result = actionlog.Failed
	data, err := io.ReadAll(target.File)
	if err != nil {
		return RemediationResult{Error: fmt.Sprintf("cannot read: %v", err)}
	}

	audit.capture(target, data)
	audit.rec.Result = actionlog.Refused
	dangerous := []string{"auto_prepend_file", "auto_append_file", "eval(", "base64_decode",
		"gzinflate", "str_rot13", "addhandler", "sethandler"}
	safe := []string{
		"wordfence-waf.php", "litespeed", "advanced-headers.php", "rsssl",
		"application/x-httpd-php", "application/x-httpd-ea-php", "application/x-httpd-alt-php",
		"-execcgi", "sethandler none", "sethandler default-handler",
		"text/html", "text/css", "text/javascript", "application/javascript",
		"image/", "font/", ".woff", ".woff2", ".ttf", ".eot", ".svg",
		"wordfence",
	}

	var cleaned []string
	removed := 0
	var phpHandlerContexts []phpHandlerOverlay
	// Iterate logical directives so a malicious mapping split across an Apache
	// line continuation is removed as a unit (every physical line it spans).
	for _, logical := range joinHtaccessContinuations(strings.Split(string(data), "\n")) {
		trimmed := strings.TrimSpace(logical.text)
		lineLower := strings.ToLower(trimmed)
		if strings.HasPrefix(trimmed, "#") {
			cleaned = append(cleaned, logical.lines...)
			continue
		}
		if ctx, ok := openPHPHandlerContext(trimmed); ok {
			phpHandlerContexts = append(phpHandlerContexts, ctx)
			cleaned = append(cleaned, logical.lines...)
			continue
		}
		if closesPHPHandlerContext(trimmed) {
			if len(phpHandlerContexts) > 0 {
				phpHandlerContexts = phpHandlerContexts[:len(phpHandlerContexts)-1]
			}
			cleaned = append(cleaned, logical.lines...)
			continue
		}
		isDangerous := false
		if phpHandlerRemapsNonPHPInContext(lineLower, phpHandlerContexts) {
			isDangerous = true
		}
		for _, d := range dangerous {
			if strings.Contains(lineLower, d) {
				isSafe := false
				for _, s := range safe {
					if strings.Contains(lineLower, s) {
						isSafe = true
						break
					}
				}
				if !isSafe {
					isDangerous = true
					break
				}
			}
		}
		if isDangerous {
			removed++
		} else {
			cleaned = append(cleaned, logical.lines...)
		}
	}

	if removed == 0 {
		return RemediationResult{Error: "no malicious directives found to remove"}
	}

	backupPath := newQuarantinePath(htaccessBackupDirRoot, path)
	meta := quarantineMetadata(path, target.Info, "Pre-clean .htaccess backup")
	audit.rec.Result = actionlog.Failed
	audit.rec.Reason = meta.Reason
	if err := storeQuarantineBackup(backupPath, data, meta, 0600); err != nil {
		return RemediationResult{Error: fmt.Sprintf("cannot create durable backup: %v", err)}
	}
	if err := audit.replace(target, []byte(strings.Join(cleaned, "\n")), backupPath); err != nil {
		return RemediationResult{Error: fmt.Sprintf("write failed; backup retained at %s: %v", backupPath, err)}
	}
	return RemediationResult{
		Success:     true,
		Action:      fmt.Sprintf("removed %d malicious directive(s) from %s", removed, path),
		Description: fmt.Sprintf("Cleaned .htaccess: removed %d line(s) (backup: %s)", removed, backupPath),
	}
}

// extractFilePathFromMessage extracts a file path from a finding message.
// Handles patterns like "World-writable PHP file: /path/to/file"
// and "Webshell found: /path/to/file"
func extractFilePathFromMessage(message string) string {
	// Look for /home/ or /tmp/ paths
	for _, prefix := range accountRootPrefixes("/tmp/", "/dev/shm/", "/var/tmp/") {
		idx := strings.Index(message, prefix)
		if idx < 0 {
			continue
		}
		rest := message[idx:]
		// Path ends at space, comma, newline, or end
		endIdx := len(rest)
		for i, c := range rest {
			if c == ' ' || c == ',' || c == '\n' || c == ')' {
				endIdx = i
				break
			}
		}
		return rest[:endIdx]
	}
	return ""
}

func selectFindingPath(message string, filePath ...string) string {
	if len(filePath) > 0 {
		path := filePath[0]
		if strings.TrimSpace(path) != "" {
			return path
		}
	}
	return extractFilePathFromMessage(message)
}

func resolveExistingFixPath(path string, allowedRoots []string) (string, os.FileInfo, error) {
	cleanPath, err := sanitizeFixPath(path, allowedRoots)
	if err != nil {
		return "", nil, err
	}

	info, err := osFS.Lstat(cleanPath)
	if err != nil {
		return "", nil, fmt.Errorf("file not found: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", nil, fmt.Errorf("symlinked paths are not eligible for automated remediation: %s", cleanPath)
	}

	resolved, err := filepath.EvalSymlinks(cleanPath)
	if err != nil {
		return "", nil, fmt.Errorf("cannot resolve path: %v", err)
	}
	resolved, err = sanitizeFixPath(resolved, allowedRoots)
	if err != nil {
		return "", nil, err
	}
	if accountRoot := homeAccountRoot(cleanPath); accountRoot != "" && !isPathWithinOrEqual(resolved, accountRoot) {
		return "", nil, fmt.Errorf("resolved path escapes account boundary: %s", resolved)
	}

	resolvedInfo, err := osFS.Lstat(resolved)
	if err != nil {
		return "", nil, fmt.Errorf("file not found: %v", err)
	}
	if resolvedInfo.Mode()&os.ModeSymlink != 0 {
		return "", nil, fmt.Errorf("symlinked paths are not eligible for automated remediation: %s", resolved)
	}

	return resolved, resolvedInfo, nil
}

func sanitizeFixPath(path string, allowedRoots []string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("file path is required")
	}
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("file path must be absolute")
	}
	for _, root := range allowedRoots {
		if fixTargetDepthBelow(path, root) >= fixTargetMinDepth(root) {
			return path, nil
		}
	}
	return "", fmt.Errorf("file path is outside the allowed remediation roots: %s", path)
}

// fixTargetDepthBelow returns how many path components path lies below
// root, or 0 when path is root itself or not under it.
func fixTargetDepthBelow(path, root string) int {
	cleanRoot := filepath.Clean(root)
	if !strings.HasPrefix(path, cleanRoot+string(filepath.Separator)) {
		return 0
	}
	rel := strings.TrimPrefix(path, cleanRoot+string(filepath.Separator))
	return strings.Count(rel, string(filepath.Separator)) + 1
}

// fixTargetMinDepth is how far below a remediation root a target must lie.
// A root itself is never a target, and under /home neither is an account's
// home directory: quarantining or chmod-ing either takes a whole tree away.
func fixTargetMinDepth(root string) int {
	if isAccountRoot(root) {
		return 2
	}
	return 1
}

func isPathWithinOrEqual(path, base string) bool {
	cleanPath := filepath.Clean(path)
	cleanBase := filepath.Clean(base)
	return cleanPath == cleanBase || strings.HasPrefix(cleanPath, cleanBase+string(filepath.Separator))
}

func homeAccountRoot(path string) string {
	root, account, ok := accountRootOf(path)
	if !ok {
		return ""
	}
	return filepath.Join(root, account)
}

// extractEximMsgID extracts an Exim message ID from a finding message.
// Matches the pattern "(message: XXXXXX-XXXXXX-XX)" used by emailscan.go.
func extractEximMsgID(message string) string {
	prefix := "(message: "
	idx := strings.Index(message, prefix)
	if idx < 0 {
		return ""
	}
	rest := message[idx+len(prefix):]
	end := strings.Index(rest, ")")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:end])
}

// fixQuarantineSpoolMessage moves Exim spool files (-H header and -D body)
// for a message ID into quarantine.
func fixQuarantineSpoolMessage(message string) RemediationResult {
	msgID := extractEximMsgID(message)
	if msgID == "" {
		return RemediationResult{Error: "could not extract Exim message ID from finding"}
	}
	// Validate Exim message ID format to prevent path traversal
	if !eximMsgIDRegex.MatchString(msgID) {
		return RemediationResult{Error: fmt.Sprintf("invalid Exim message ID format: %s", msgID)}
	}

	var spoolDir string
	for _, dir := range eximSpoolDirs {
		if _, err := osFS.Stat(filepath.Join(dir, msgID+"-H")); err == nil {
			spoolDir = dir
			break
		}
	}
	if spoolDir == "" {
		return RemediationResult{Error: fmt.Sprintf("spool message %s not found (already delivered or removed)", msgID)}
	}

	base := newQuarantinePath(quarantineDir, "exim_"+msgID)
	moved := 0
	for _, suffix := range []string{"-H", "-D"} {
		src := filepath.Join(spoolDir, msgID+suffix)
		info, err := os.Lstat(src)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return RemediationResult{Error: fmt.Sprintf("cannot inspect spool file after quarantining %d files: %v", moved, err)}
		}
		meta := quarantineMetadata(src, info, "Phishing email quarantined via CSM Web UI")
		meta.MessageID, meta.SpoolDir = msgID, spoolDir
		dst := base + suffix
		if err := quarantineTarget(src, dst, info, meta); err != nil {
			return RemediationResult{Error: fmt.Sprintf("spool quarantine stopped after %d files; inspect recovery copies under %s: %v", moved, quarantineDir, err)}
		}
		moved++
	}
	if moved == 0 {
		return RemediationResult{Error: fmt.Sprintf("no spool files found for message %s", msgID)}
	}

	return RemediationResult{
		Success:     true,
		Action:      fmt.Sprintf("quarantined spool message %s (%d files)", msgID, moved),
		Description: fmt.Sprintf("Exim spool files moved to quarantine for message %s", msgID),
	}
}
