package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/processhandle"
)

// var (not const) so tests can redirect to t.TempDir().
var quarantineDir = "/opt/csm/quarantine"

// autoQuarantineChecks are the findings the scheduled auto-responder may
// quarantine on its own: the manual move set plus the kill-and-quarantine
// and handler-abuse families, and the realtime signature match, which must
// additionally pass isHighConfidenceRealtimeMatch. Membership is pinned by
// test against the check registry.
var autoQuarantineChecks = map[string]bool{
	"webshell":                 true,
	"backdoor_binary":          true,
	"new_webshell_file":        true,
	"new_executable_in_config": true,
	"obfuscated_php":           true,
	"suspicious_php_content":   true,
	"new_php_in_languages":     true,
	"new_php_in_upgrade":       true,
	"phishing_page":            true,
	"phishing_directory":       true,
	"htaccess_handler_abuse":   true,
	"signature_match_realtime": true,
}

var signalProcess = processhandle.Signal
var errProcessNotEligible = errors.New("process is no longer eligible for termination")

// AutoKillProcesses kills processes that match critical findings.
// Only targets: fake kernel threads, reverse shells, GSocket processes.
// Never kills root system services or cPanel processes.
func AutoKillProcesses(ctx context.Context, cfg *config.Config, findings []alert.Finding) []alert.Finding {
	if !cfg.AutoResponse.Enabled || !cfg.AutoResponse.KillProcesses {
		return nil
	}

	var actions []alert.Finding

	for _, f := range findings {
		// Only act on specific high-confidence critical checks
		switch f.Check {
		case "fake_kernel_thread", "suspicious_process", "php_suspicious_execution":
		default:
			continue
		}
		if f.Severity != alert.Critical {
			continue
		}

		// Use structured PID field when available, fall back to text extraction
		pid := fmt.Sprintf("%d", f.PID)
		if f.PID == 0 {
			pid = extractPID(f.Details)
			if pid == "" {
				continue
			}
		}

		pidInt, validPID := parseProcessPID(pid)
		if !validPID {
			continue
		}
		pid = strconv.Itoa(pidInt)
		var uid, exe string
		err := signalProcess(ctx, pidInt, syscall.SIGKILL, func() error {
			uid, exe = getProcessUID(pid), getProcessExe(pid)
			if uid == "0" || uid == "" || exe == "" || isSafeProcess(exe) || !processStartedBefore(pid, f.Timestamp) {
				return errProcessNotEligible
			}
			return nil
		})
		if err != nil {
			if !errors.Is(err, errProcessNotEligible) && !errors.Is(err, os.ErrProcessDone) && ctx.Err() == nil {
				csmlog.Warn("auto-kill: safe process signaling failed", "pid", pidInt, "err", err)
			}
			recordKillAction(&f, pid, exe, err)
			continue
		}
		recordKillAction(&f, pid, exe, nil)

		actions = append(actions, alert.Finding{
			Severity:  alert.Critical,
			Check:     "auto_response",
			Message:   fmt.Sprintf("AUTO-KILL: Process %s killed (was: %s)", pid, f.Check),
			Timestamp: time.Now(),
			Details:   fmt.Sprintf("Original finding: %s\nProcess: %s (UID: %s)", f.Message, exe, uid),
		})
	}

	return actions
}

// recordKillAction writes the unified action record for one termination
// attempt. A refusal is recorded as well as a kill: "the safety rules stopped
// this" is the answer to a question an operator will ask about a process that
// is still running.
func recordKillAction(f *alert.Finding, pid, exe string, err error) {
	rec := actionlog.Record{
		Op:          "respond.kill_process",
		Actor:       actionlog.DefaultActor(),
		Target:      "pid " + pid,
		ActorDetail: exe,
		Reason:      "manual process termination",
		FindingID:   "",
		Result:      actionlog.Applied,
	}
	if f != nil {
		rec.Reason = f.Check
		rec.FindingID = alert.FindingID(*f)
	}
	switch {
	case errors.Is(err, errProcessNotEligible):
		rec.Result = actionlog.Refused
		rec.Error = "process is not eligible for automatic termination"
	case errors.Is(err, os.ErrProcessDone):
		rec.Result = actionlog.Refused
		rec.Error = "process had already exited"
	case err != nil:
		rec.Result = actionlog.Failed
		rec.Error = err.Error()
	}
	actionlog.Write(rec)
}

// AutoQuarantineFiles moves malicious files to quarantine directory.
// Preserves original path and metadata in a sidecar .meta file.
// Marks evaluated input findings so alert delivery cannot repeat a response.
func AutoQuarantineFiles(cfg *config.Config, findings []alert.Finding) []alert.Finding {
	if cfg == nil || !cfg.AutoResponse.Enabled || !cfg.AutoResponse.QuarantineFiles || cfg.ObserveMode() {
		return nil
	}
	var actions []alert.Finding
	seen := make(map[string]bool)
	for i, f := range findings {
		if f.AutoFileResponseEvaluated || !autoQuarantineChecks[f.Check] || f.Severity != alert.Critical {
			continue
		}
		path := f.FilePath
		if path == "" {
			path = extractFilePath(f.Message)
		}
		if path == "" {
			continue
		}
		findings[i].AutoFileResponseEvaluated = true
		key := filepath.Clean(path)
		if seen[key] {
			continue
		}
		realtime := f.Check == "signature_match_realtime"
		if realtime && !isHighConfidenceRealtimeMatch(f, path, nil) {
			continue
		}
		info, err := osFS.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		// Multiple checks can report one file. Do not re-clean a repaired
		// target or charge repeated failures for the same batch of evidence.
		seen[key] = true
		paused := runAutoFileResponse(cfg, path, info, func() error {
			// Cleaning is one response attempt. A failed cleaner leaves the file
			// and any backup for review; it must not escalate to removing the file.
			if !realtime && ShouldCleanInsteadOfQuarantine(path) {
				result := cleanInfectedFileIdentified(path, info)
				if result.Error != "" {
					outcome := "failed"
					if result.Refused {
						outcome = "refused"
					}
					actions = append(actions, alert.Finding{Severity: alert.Warning, Check: "auto_response", Message: fmt.Sprintf("AUTO-CLEAN %s for %s; manual review required", outcome, path), Details: result.Error, Timestamp: time.Now()})
					// Safety refusals consume capacity without charging a failure.
					if result.Refused {
						return nil
					}
					return errors.New(result.Error)
				}
				if result.Cleaned {
					actions = append(actions, alert.Finding{Severity: alert.Critical, Check: "auto_response", Message: fmt.Sprintf("AUTO-CLEAN: %s surgically cleaned", path), Details: fmt.Sprintf("Backup: %s\n%s", result.BackupPath, strings.Join(result.Removals, "\n")), Timestamp: time.Now()})
				}
				return nil
			}
			qPath := newQuarantinePath(quarantineDir, path)
			meta := quarantineMetadata(path, info, f.Message)
			meta.FindingID = alert.FindingID(f)
			err := quarantineTarget(path, qPath, info, meta)
			warning := ""
			if err != nil {
				var completed bool
				warning, completed = completedQuarantineWarning(err)
				if !completed {
					return err
				}
			}
			details := fmt.Sprintf("Quarantined to: %s\nOriginal finding: %s", qPath, f.Message)
			if warning != "" {
				details += "\nWarning: " + warning
			}
			actions = append(actions, alert.Finding{Severity: alert.Critical, Check: "auto_response", Message: fmt.Sprintf("AUTO-QUARANTINE: %s moved to quarantine", path), Timestamp: time.Now(), Details: details})
			return nil
		})
		if paused != nil {
			actions = append(actions, *paused)
		}
	}
	return actions
}

// AutoFixPermissions sets world/group-writable PHP files to 0644.
// Returns the auto-response action findings and the keys of original findings
// that were successfully fixed (so the caller can dismiss them from the UI).
func AutoFixPermissions(cfg *config.Config, findings []alert.Finding) (actions []alert.Finding, fixedKeys []string) {
	if !cfg.AutoResponse.Enabled || !cfg.AutoResponse.EnforcePermissions {
		return nil, nil
	}

	for _, f := range findings {
		switch f.Check {
		case "world_writable_php", "group_writable_php":
		default:
			continue
		}

		path := extractFilePath(f.Message)
		if path == "" {
			continue
		}

		path, info, err := resolveExistingFixPath(path, effectiveFixRoots(fixPermissionsAllowedRoots))
		if err != nil || info.IsDir() {
			continue
		}

		oldMode := info.Mode().Perm()
		// #nosec G302 -- same as fixPermissions: restoring canonical web-content
		// mode on a user file flagged for dangerous (e.g. world-writable) perms.
		if err := os.Chmod(path, 0644); err != nil {
			continue
		}

		actions = append(actions, alert.Finding{
			Severity:  alert.Warning,
			Check:     "auto_response",
			Message:   fmt.Sprintf("AUTO-FIX: %s permissions set to 644 (was %o)", path, oldMode),
			Timestamp: time.Now(),
		})
		fixedKeys = append(fixedKeys, f.Check+":"+f.Message)
	}

	return actions, fixedKeys
}

// AutoFixWPCron disables WP-Cron and installs a per-user system cron for every
// perf_wp_cron finding. Returns the auto-response action findings and the keys
// of the originals so the caller can dismiss them. Gated behind an explicit
// opt-in because it edits customer wp-config.php and crontabs.
func AutoFixWPCron(cfg *config.Config, findings []alert.Finding) (actions []alert.Finding, fixedKeys []string) {
	if !cfg.AutoResponse.Enabled || !cfg.AutoResponse.FixWPCron {
		return nil, nil
	}

	opts := WPCronFixOptions{
		IntervalMinutes: cfg.Performance.WPCronFix.IntervalMinutes,
		PHPBin:          cfg.Performance.WPCronFix.PHPBin,
	}
	allowedRoots := ResolveWPCronRoots(cfg)

	for _, f := range findings {
		if f.Check != "perf_wp_cron" {
			continue
		}
		path := extractWPConfigPath(f.Details)
		if path == "" {
			continue
		}
		res := FixDisableWPCronInRoots(path, allowedRoots, opts)
		if !res.Success {
			continue
		}
		actions = append(actions, alert.Finding{
			Severity:  alert.Warning,
			Check:     "auto_response",
			Message:   fmt.Sprintf("AUTO-FIX: %s", res.Description),
			Timestamp: time.Now(),
		})
		fixedKeys = append(fixedKeys, f.Key())
	}

	return actions, fixedKeys
}

// extractWPConfigPath pulls the wp-config.php path out of a perf_wp_cron
// finding's Details, formatted as "File: <path> - add define(...)".
func extractWPConfigPath(details string) string {
	const prefix = "File: "
	idx := strings.Index(details, prefix)
	if idx < 0 {
		return ""
	}
	rest := details[idx+len(prefix):]
	if j := strings.Index(rest, " - "); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

func extractPID(details string) string {
	// Look for "PID: 12345" pattern. Stop at the first whitespace, comma,
	// or newline so a trailing word ("PID: 42 exe=/bin/ls") doesn't get
	// returned as part of the PID string.
	idx := strings.Index(details, "PID: ")
	if idx < 0 {
		return ""
	}
	rest := details[idx+5:]
	for i, c := range rest {
		if c == ' ' || c == ',' || c == '\n' || c == '\t' {
			return strings.TrimSpace(rest[:i])
		}
	}
	return strings.TrimSpace(rest)
}

func extractFilePath(message string) string {
	// Look for /home/... or /tmp/... paths in the message. Order matters:
	// longer/more-specific prefixes (/var/tmp/, /dev/shm/) must come BEFORE
	// shorter ones (/tmp/) — otherwise "/tmp/" would match inside "/var/tmp/"
	// and we'd silently misclassify the path.
	for _, prefix := range accountRootPrefixes("/var/tmp/", "/dev/shm/", "/tmp/") {
		if idx := strings.Index(message, prefix); idx >= 0 {
			rest := message[idx:]
			// Path ends at space, comma, or end of string
			endIdx := len(rest)
			for i, c := range rest {
				if c == ' ' || c == ',' || c == '\n' {
					endIdx = i
					break
				}
			}
			return rest[:endIdx]
		}
	}
	return ""
}

func getProcessUID(pid string) string {
	data, err := osFS.ReadFile(filepath.Join("/proc", pid, "status"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, found := strings.CutPrefix(line, "Uid:"); found {
			fields := strings.Fields(rest)
			if len(fields) != 4 {
				return ""
			}
			var owner uint64
			for index, field := range fields {
				uid, err := strconv.ParseUint(field, 10, 32)
				if err != nil {
					return ""
				}
				// Effective, saved, and filesystem root credentials are also
				// privileged even when the real UID still names a tenant.
				if uid == 0 {
					return "0"
				}
				if index == 0 {
					owner = uid
				}
			}
			return strconv.FormatUint(owner, 10)
		}
	}
	return ""
}

func getProcessExe(pid string) string {
	exe, err := osFS.Readlink(filepath.Join("/proc", pid, "exe"))
	if err != nil {
		return ""
	}
	return exe
}

func isSafeProcess(exe string) bool {
	safePrefixes := []string{
		"/usr/local/cpanel/",
		"/usr/sbin/",
		"/usr/bin/",
		"/usr/libexec/",
		"/opt/cpanel/",
		"/opt/cloudlinux/",
		"/opt/imunify360/",
	}
	for _, prefix := range safePrefixes {
		if strings.HasPrefix(exe, prefix) {
			return true
		}
	}
	return false
}

// isHighConfidenceRealtimeMatch validates whether a realtime signature match
// is truly malicious and safe to auto-quarantine. Prevents false positives
// on legitimate libraries (PHPMailer, zip) and theme code.
//
// The data parameter should be the file content already read by the caller
// (fanotify fd or scanner) to avoid TOCTOU re-reads. Pass nil to read from path.
//
// Criteria:
//  1. Category must be "dropper" or "webshell"
//  2. File must be >= 512 bytes (entropy unreliable below this)
//  3. Content must show obfuscation indicators:
//     Shannon entropy >= 5.5 OR hex density > 20% plus an execution signal.
//     This applies to BOTH dropper and webshell categories to avoid
//     false-positive quarantine of legitimate plugins that happen to
//     match a dropper rule (e.g. curl_exec + eval on distant lines).
func isHighConfidenceRealtimeMatch(f alert.Finding, path string, data []byte) bool {
	cat := extractCategory(f.Details)
	switch cat {
	case "dropper", "webshell":
	default:
		return false
	}

	if data == nil {
		var err error
		data, err = osFS.ReadFile(path)
		if err != nil {
			return false
		}
	}

	if len(data) < 512 {
		return false
	}

	// Both dropper and webshell categories go through the same entropy/encoding
	// checks to avoid false positives. Normal PHP with heavy class constants
	// (binary literals, many named constants) lands in the 4.5-5.3 range --
	// measured: WPML wpml_zip.php = 5.25, Breakdance google-fonts.php = 4.90.
	// The 5.5 floor leaves that headroom. Obfuscated packers land at 5.8+.
	// Files that use long hex-string payloads (LEVIATHAN signature) are
	// caught by the hex-density arm instead, which stays at 20%.
	content := string(data)

	// High Shannon entropy is a strong standalone signal: packed/encrypted
	// payloads land at 5.8+, while ordinary library code (even with a handful
	// of binary constants) stays below 5.5 -- measured WPML wpml_zip.php =
	// 5.25, Breakdance google-fonts.php = 4.90.
	if shannonEntropy(content) >= 5.5 {
		return true
	}

	// High hex density alone is NOT enough: a ZIP/PDF library's magic-byte
	// constant tables ("\x50\x4b\x03\x04" ...) saturate that metric while being
	// inert data. Require a structural obfuscated-execution signal too. This
	// replaces a hardcoded library-path allowlist (vendor/, node_modules/,
	// named plugin slugs) that an attacker could defeat by planting a webshell
	// under any "trusted" directory -- the file is now judged by content, so a
	// hex-encoded packer still quarantines wherever it hides and a benign
	// data-heavy library file is spared on any path.
	if hexEncodingDensity(content) > 0.20 {
		return hasObfuscatedExecutionSignal(content)
	}
	return false
}

var (
	reVariableFunctionCall   = regexp.MustCompile(`\$[A-Za-z_]\w*\s*\(`)
	reHexEscapedStringConcat = regexp.MustCompile(`(?i)"(?:\\x[0-9a-f]{2})+"\s*\.\s*"(?:\\x[0-9a-f]{2})+"`)
)

// hasObfuscatedExecutionSignal reports whether content carries a structural
// sign of obfuscated code execution, distinguishing a packed webshell from
// inert binary data such as a ZIP library's magic-byte constants. Any signal
// is sufficient:
//   - LEVIATHAN-style control-flow obfuscation (goto spaghetti).
//   - Function names built from concatenated hex escapes ("\x65"."\x76"... to
//     dodge literal-name detection).
//   - A variable bound to a decoder/exec primitive and later invoked.
//   - A decoder (base64/gz/rot13/openssl/hex2bin) paired with an executor
//     (eval/assert/create_function, a literal dangerous callback, or a
//     request-scoped variable-function call).
func hasObfuscatedExecutionSignal(content string) bool {
	code := stripPHPCommentsFromCode(content)
	codeNoStrings := strings.ToLower(stripPHPStringsFromCode(code))
	if countOccurrences(codeNoStrings, "goto ") > 10 {
		return true
	}
	// Function-name obfuscation: many double-quoted hex string literals joined
	// by the concatenation operator. Standalone hex constant tables (no concat)
	// are inert data and do not match.
	if countHexEscapedStringConcats(code) > 10 {
		return true
	}
	if detectVarFuncDangerousAssignment(code) {
		return true
	}
	if !containsDirectPHPFunctionCall(codeNoStrings, []string{
		"base64_decode", "gzinflate", "gzuncompress", "gzdecode",
		"str_rot13", "openssl_decrypt", "hex2bin", "convert_uudecode",
	}) {
		return false
	}
	if containsDirectPHPFunctionCall(codeNoStrings, []string{
		"eval", "assert", "create_function",
	}) {
		return true
	}
	if hasLiteralCallbackExecutor(code) {
		return true
	}
	return hasRequestScopedVariableFunctionCall(codeNoStrings)
}

func countHexEscapedStringConcats(code string) int {
	return len(reHexEscapedStringConcat.FindAllStringIndex(code, -1))
}

func containsDirectPHPFunctionCall(codeNoStrings string, names []string) bool {
	for _, name := range names {
		if containsStandaloneFunc(codeNoStrings, name+"(") {
			return true
		}
	}
	return false
}

func hasRequestScopedVariableFunctionCall(codeNoStrings string) bool {
	for _, line := range strings.Split(codeNoStrings, "\n") {
		if containsRequestSuperglobal(line) && reVariableFunctionCall.MatchString(line) {
			return true
		}
	}
	return false
}

func hasLiteralCallbackExecutor(code string) bool {
	for i := 0; i < len(code); i++ {
		if isPHPQuote(code[i]) {
			i = skipPHPString(code, i)
			continue
		}

		nameStart := i
		if code[i] == '\\' {
			if i+1 >= len(code) || !isPHPIdentifierStart(code[i+1]) || !canStartGlobalPHPFunction(code, i) {
				continue
			}
			nameStart = i + 1
		} else if !isPHPIdentifierStart(code[i]) || !canStartPHPFunctionName(code, i) {
			continue
		}

		nameEnd := nameStart + 1
		for nameEnd < len(code) && isPHPIdentifierPart(code[nameEnd]) {
			nameEnd++
		}
		name := strings.ToLower(code[nameStart:nameEnd])
		if _, ok := callbackFirstArgFuncs[name]; !ok {
			i = nameEnd - 1
			continue
		}

		openParen := skipPHPWhitespace(code, nameEnd)
		if openParen >= len(code) || code[openParen] != '(' {
			i = nameEnd - 1
			continue
		}
		firstArg := skipPHPWhitespace(code, openParen+1)
		if firstArg >= len(code) || !isPHPQuote(code[firstArg]) {
			i = nameEnd - 1
			continue
		}
		callbackName, _, ok := readPHPFunctionString(code, firstArg)
		if !ok {
			i = nameEnd - 1
			continue
		}
		if _, dangerous := callbackExecNames[callbackName]; dangerous {
			return true
		}
		i = nameEnd - 1
	}
	return false
}

// hexEncodingDensity returns the fraction of a string's bytes that are part
// of PHP hex escape sequences (\xNN). LEVIATHAN AES-encrypted webshells
// encode their payload as long hex strings - the \x prefix repeats so
// frequently that Shannon entropy drops to ~3.5 (below normal PHP), but
// the hex density reaches 40-60%.
func hexEncodingDensity(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	hexBytes := 0
	for i := 0; i < len(s)-3; i++ {
		if s[i] == '\\' && s[i+1] == 'x' &&
			isHexDigit(s[i+2]) && isHexDigit(s[i+3]) {
			hexBytes += 4
			i += 3 // skip past this sequence
		}
	}
	return float64(hexBytes) / float64(len(s))
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// InlineQuarantineGated applies the operator's quarantine policy before
// InlineQuarantine moves anything. The realtime fanotify path detects malware
// continuously, but moving a file is a customer-impacting auto-response
// action: it must honor the same master switch and quarantine opt-in as the
// batch AutoQuarantineFiles dispatcher, never act on detection alone. An
// operator in monitor mode (auto-response off, or quarantine_files off) gets
// the alert without having files moved out from under them.
func InlineQuarantineGated(cfg *config.Config, f alert.Finding, path string, data []byte) (string, bool) {
	path, ok, _ := InlineQuarantineGatedIdentified(cfg, &f, path, data, nil)
	return path, ok
}

// InlineQuarantineGatedIdentified applies the auto-response policy gate and
// then quarantines the exact file the caller scanned. See
// InlineQuarantineIdentified for why the identity matters.
// Marks the finding evaluated only once it reaches the shared budget gate.
func InlineQuarantineGatedIdentified(cfg *config.Config, f *alert.Finding, path string, data []byte, scanned os.FileInfo) (string, bool, *alert.Finding) {
	if f == nil || cfg == nil || !cfg.AutoResponse.Enabled || !cfg.AutoResponse.QuarantineFiles || cfg.ObserveMode() {
		return "", false, nil
	}
	info, ok := inlineQuarantineInfo(*f, path, data, scanned)
	if !ok {
		return "", false, nil
	}
	var qPath string
	f.AutoFileResponseEvaluated = true
	paused := runAutoFileResponse(cfg, path, info, func() error {
		var err error
		qPath, err = quarantineInlineTarget(*f, path, info)
		return err
	})
	return qPath, qPath != "", paused
}

// InlineQuarantine moves a file to quarantine immediately if it passes the
// high-confidence validation gates. Called from fanotify's analyzeFile to
// quarantine malware without waiting for the 5-second batch dispatcher.
// The data parameter is the file content already read by the caller (avoids
// TOCTOU re-read). Pass nil to read from path.
// Returns the quarantine path and true if the file was quarantined.
func InlineQuarantine(f alert.Finding, path string, data []byte) (string, bool) {
	return InlineQuarantineIdentified(f, path, data, nil)
}

// InlineQuarantineIdentified is InlineQuarantine with the identity of the file
// the caller actually scanned. The realtime scanner reads content from the
// fanotify event descriptor, so passing that descriptor's stat pins the move to
// the object that was examined: a file replaced between detection and
// quarantine fails the identity check instead of being moved in place of the
// malware. A nil identity keeps the older path-based behaviour for callers that
// began from a path in the first place, such as the batch dispatcher.
func InlineQuarantineIdentified(f alert.Finding, path string, data []byte, scanned os.FileInfo) (string, bool) {
	info, ok := inlineQuarantineInfo(f, path, data, scanned)
	if !ok {
		return "", false
	}
	qPath, err := quarantineInlineTarget(f, path, info)
	if err != nil {
		csmlog.Warn("inline quarantine refused", "path", path, "err", err)
	}
	return qPath, err == nil
}

func inlineQuarantineInfo(f alert.Finding, path string, data []byte, scanned os.FileInfo) (os.FileInfo, bool) {
	if !isHighConfidenceRealtimeMatch(f, path, data) {
		return nil, false
	}
	info, err := osFS.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return nil, false
	}
	if scanned != nil && (!sameFileIdentity(info, scanned) || !sameContentShape(info, scanned)) {
		return nil, false
	}
	return info, true
}

func quarantineInlineTarget(f alert.Finding, path string, info os.FileInfo) (string, error) {
	qPath := newQuarantinePath(quarantineDir, path)
	meta := quarantineMetadata(path, info, "Inline quarantine: high-confidence realtime signature match")
	meta.FindingID = alert.FindingID(f)
	if err := quarantineTarget(path, qPath, info, meta); err != nil {
		if warning, completed := completedQuarantineWarning(err); completed {
			csmlog.Warn("inline quarantine completed with warning", "warning", warning)
		} else {
			return "", err
		}
	}
	return qPath, nil
}

// extractCategory parses "Category: <value>" from a finding's Details field.
func extractCategory(details string) string {
	for _, line := range strings.Split(details, "\n") {
		if strings.HasPrefix(line, "Category: ") {
			return strings.TrimPrefix(line, "Category: ")
		}
	}
	return ""
}

// AutoCleanHtaccess runs the hardened .htaccess cleaner against
// every finding emitted by the new detector registry, gated by
// AutoResponse.CleanHtaccess. Skipped when the daemon's auto-response
// pipeline is disabled overall.
//
// Unlike AutoQuarantineFiles, this routes around the
// quarantine/clean fork (.htaccess files are infrastructure -- moving
// them to /opt/csm/quarantine breaks the site). Each invocation
// backs up the original to /opt/csm/quarantine/pre_clean/<ts>_*
// inside CleanHtaccessFile before atomic-replacing.
// Marks evaluated input findings so alert delivery cannot repeat a response.
func AutoCleanHtaccess(cfg *config.Config, findings []alert.Finding) []alert.Finding {
	if cfg == nil || !cfg.AutoResponse.Enabled || !cfg.AutoResponse.CleanHtaccess || cfg.ObserveMode() {
		return nil
	}

	var actions []alert.Finding
	seen := make(map[string]struct{})
	for i, f := range findings {
		if f.AutoFileResponseEvaluated || !isHtaccessHardenedFinding(f.Check) {
			continue
		}
		path := f.FilePath
		if path == "" {
			path = extractFilePath(f.Message)
		}
		if path == "" {
			continue
		}
		findings[i].AutoFileResponseEvaluated = true
		// One Clean per file per autoresponse pass: multiple
		// detector findings on the same file converge on a single
		// cleaning call (CleanHtaccessFile re-runs every detector).
		key := filepath.Clean(path)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		info, err := osFS.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		paused := runAutoFileResponse(cfg, path, info, func() error {
			result := cleanHtaccessFileIdentified(path, info)
			if result.Success {
				actions = append(actions, alert.Finding{
					Severity:  alert.Critical,
					Check:     "auto_response",
					Message:   fmt.Sprintf("AUTO-CLEAN: %s hardened directives removed", path),
					Details:   result.Description,
					Timestamp: time.Now(),
				})
			} else if result.Error != "" && !result.Refused {
				actions = append(actions, alert.Finding{
					Severity:  alert.Warning,
					Check:     "auto_response",
					Message:   fmt.Sprintf("AUTO-CLEAN failed: %s", path),
					Details:   result.Error,
					Timestamp: time.Now(),
				})
			}
			if result.Error != "" && !result.Refused {
				return errors.New(result.Error)
			}
			return nil
		})
		if paused != nil {
			actions = append(actions, *paused)
		}
	}
	return actions
}

func isHtaccessHardenedFinding(check string) bool {
	for _, detector := range htaccessDetectors {
		if check == detector.Name {
			return true
		}
	}
	return false
}
