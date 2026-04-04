package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

const phpContentReadSize = 32768 // Read first 32KB for analysis

// CheckPHPContent scans new/suspicious PHP files for obfuscation patterns,
// remote payload fetching, and eval chains. This is designed to catch droppers
// like the LEVIATHAN attack's file.php and files.php that use goto spaghetti,
// hex-encoded strings, and call_user_func with string-built function names.
//
// This check scans PHP files in directories that shouldn't normally contain
// user-authored PHP: wp-content/languages, wp-content/upgrade, wp-content/mu-plugins,
// and also checks any PHP files flagged by the file index as new.
func CheckPHPContent(cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	homeDirs, err := GetScanHomeDirs()
	if err != nil {
		return nil
	}

	for _, homeEntry := range homeDirs {
		if !homeEntry.IsDir() {
			continue
		}
		homeDir := filepath.Join("/home", homeEntry.Name())

		// Get all potential document roots
		docRoots := []string{filepath.Join(homeDir, "public_html")}
		subDirs, _ := os.ReadDir(homeDir)
		for _, sd := range subDirs {
			if sd.IsDir() && sd.Name() != "public_html" && sd.Name() != "mail" &&
				!strings.HasPrefix(sd.Name(), ".") && sd.Name() != "etc" &&
				sd.Name() != "logs" && sd.Name() != "ssl" && sd.Name() != "tmp" {
				docRoots = append(docRoots, filepath.Join(homeDir, sd.Name()))
			}
		}

		for _, docRoot := range docRoots {
			// Scan directories that shouldn't contain user PHP
			suspiciousDirs := []string{
				filepath.Join(docRoot, "wp-content", "languages"),
				filepath.Join(docRoot, "wp-content", "upgrade"),
				filepath.Join(docRoot, "wp-content", "mu-plugins"),
				filepath.Join(docRoot, "wp-content", "plugins"),
				filepath.Join(docRoot, "wp-content", "themes"),
			}

			for _, dir := range suspiciousDirs {
				scanDirForObfuscatedPHP(dir, 4, cfg, &findings)
			}
		}
	}

	return findings
}

// scanDirForObfuscatedPHP recursively scans directories for PHP files with
// malicious content patterns.
func scanDirForObfuscatedPHP(dir string, maxDepth int, cfg *config.Config, findings *[]alert.Finding) {
	if maxDepth <= 0 {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		name := entry.Name()
		fullPath := filepath.Join(dir, name)

		// Check suppressed paths
		suppressed := false
		for _, ignore := range cfg.Suppressions.IgnorePaths {
			if matchGlob(fullPath, ignore) {
				suppressed = true
				break
			}
		}
		if suppressed {
			continue
		}

		if entry.IsDir() {
			scanDirForObfuscatedPHP(fullPath, maxDepth-1, cfg, findings)
			continue
		}

		nameLower := strings.ToLower(name)
		if !strings.HasSuffix(nameLower, ".php") {
			continue
		}

		// Skip known safe files
		if isSafePHPInWPDir(fullPath, name) {
			continue
		}

		// Read and analyze content
		result := analyzePHPContent(fullPath)
		if result.severity >= 0 {
			info, _ := os.Stat(fullPath)
			details := result.details
			if info != nil {
				details += fmt.Sprintf("\nSize: %d, Mtime: %s", info.Size(), info.ModTime().Format("2006-01-02 15:04:05"))
			}
			*findings = append(*findings, alert.Finding{
				Severity: result.severity,
				Check:    result.check,
				Message:  fmt.Sprintf("%s: %s", result.message, fullPath),
				Details:  details,
				FilePath: fullPath,
			})
		}
	}
}

type phpAnalysisResult struct {
	severity alert.Severity
	check    string
	message  string
	details  string
}

// analyzePHPContent reads the first 8KB of a PHP file and checks for
// obfuscation and malicious patterns.
func analyzePHPContent(path string) phpAnalysisResult {
	f, err := os.Open(path)
	if err != nil {
		return phpAnalysisResult{severity: -1}
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, phpContentReadSize)
	n, _ := f.Read(buf)
	if n == 0 {
		return phpAnalysisResult{severity: -1}
	}
	content := string(buf[:n])
	contentLower := strings.ToLower(content)

	var indicators []string

	// --- Critical: Remote payload fetching ---
	payloadHosts := []string{
		"gist.githubusercontent.com",
		"raw.githubusercontent.com",
		"pastebin.com/raw",
		"paste.ee/r/",
		"ghostbin.co/paste/",
		"hastebin.com/raw/",
	}
	for _, host := range payloadHosts {
		if strings.Contains(contentLower, host) {
			indicators = append(indicators, fmt.Sprintf("remote payload URL: %s", host))
		}
	}

	// --- Critical: eval() chains with decoding ---
	evalPatterns := []struct {
		pattern string
		desc    string
	}{
		{"eval(", "eval() call"},
		{"assert(", "assert() call (code execution)"},
	}
	decoders := []string{
		"base64_decode", "gzinflate", "gzuncompress", "str_rot13",
		"rawurldecode", "gzdecode", "bzdecompress",
	}
	hasEval := false
	hasDecoder := false
	for _, ep := range evalPatterns {
		if containsStandaloneFunc(contentLower, ep.pattern) {
			hasEval = true
		}
	}
	for _, d := range decoders {
		if strings.Contains(contentLower, d) {
			hasDecoder = true
		}
	}
	if hasEval && hasDecoder {
		indicators = append(indicators, "eval() combined with encoding/compression function")
	}

	// --- Critical: call_user_func with string-built function names ---
	// This is the exact technique used in the LEVIATHAN droppers
	if strings.Contains(contentLower, "call_user_func") {
		// Check if function names are built from string concatenation
		if countOccurrences(content, `"\x`) > 5 || countOccurrences(content, "\" . \"") > 10 {
			indicators = append(indicators, "call_user_func with obfuscated function names")
		}
	}

	// --- High: Goto obfuscation (LEVIATHAN signature) ---
	gotoCount := countOccurrences(contentLower, "goto ")
	if gotoCount > 10 {
		indicators = append(indicators, fmt.Sprintf("excessive goto statements (%d found — obfuscation pattern)", gotoCount))
	}

	// --- High: Hex-encoded string construction ---
	// Only flag hex strings when accompanied by concatenation — real obfuscation
	// builds function names like "\x63" . "\x75" . "\x72" . "\x6c" (= "curl").
	// Standalone hex arrays (Wordfence IPv6 subnet masks, binary data) are benign.
	hexStringCount := countOccurrences(content, `"\x`)
	dotConcatCount := countOccurrences(content, `" . "`)
	if hexStringCount > 20 && dotConcatCount > 10 {
		indicators = append(indicators, fmt.Sprintf("heavy hex-encoded strings with concatenation (%d hex, %d concat — obfuscation pattern)", hexStringCount, dotConcatCount))
	} else if dotConcatCount > 30 {
		indicators = append(indicators, fmt.Sprintf("excessive string concatenation (%d — function name obfuscation)", dotConcatCount))
	}

	// --- High: Variable function calls with obfuscated names ---
	// call_user_func + decoder alone is too broad — Elementor, WooCommerce, and
	// dozens of plugins use call_user_func_array with base64_decode legitimately.
	// Only flag when combined with actual obfuscation (hex strings, heavy concat).
	if strings.Contains(contentLower, "call_user_func") && hasDecoder {
		if hexStringCount > 5 || dotConcatCount > 5 {
			indicators = append(indicators, "variable function call with decoder and obfuscation")
		}
	}

	// --- High: Shell execution functions combined with request input ---
	// Uses containsStandaloneFunc to avoid substring false positives
	// (e.g. "WP_Filesystem(" matching "exec(", "preg_match(" matching "exec(")
	shellFuncs := []string{"system(", "passthru(", "exec(", "shell_exec(", "popen(", "proc_open(", "pcntl_exec("}
	requestVars := []string{"$_request", "$_post", "$_get", "$_cookie", "$_server"}
	hasShell := false
	hasInput := false
	for _, sf := range shellFuncs {
		if containsStandaloneFunc(contentLower, sf) {
			hasShell = true
		}
	}
	for _, rv := range requestVars {
		if strings.Contains(contentLower, rv) {
			hasInput = true
		}
	}
	if hasShell && hasInput {
		indicators = append(indicators, "shell execution function with request input (webshell pattern)")
	}

	// --- High: base64 encoding/decoding of commands (CGI shell pattern) ---
	if strings.Contains(contentLower, "base64_decode") && strings.Contains(contentLower, "base64_encode") {
		if hasShell || containsStandaloneFunc(contentLower, "eval(") {
			indicators = append(indicators, "base64 encode+decode with execution (command relay pattern)")
		}
	}

	// --- Determine severity based on indicators ---
	if len(indicators) == 0 {
		return phpAnalysisResult{severity: -1}
	}

	// Multiple indicators or remote payloads = critical
	if len(indicators) >= 2 || containsAny(indicators, "remote payload", "call_user_func with obfuscated") {
		return phpAnalysisResult{
			severity: alert.Critical,
			check:    "obfuscated_php",
			message:  "Obfuscated/malicious PHP detected",
			details:  fmt.Sprintf("Indicators found:\n- %s", strings.Join(indicators, "\n- ")),
		}
	}

	return phpAnalysisResult{
		severity: alert.High,
		check:    "suspicious_php_content",
		message:  "Suspicious PHP content detected",
		details:  fmt.Sprintf("Indicators found:\n- %s", strings.Join(indicators, "\n- ")),
	}
}

// isSafePHPInWPDir returns true for known legitimate PHP files in WP directories
// like languages (translation files) and upgrade (empty index.php).
func isSafePHPInWPDir(path, name string) bool {
	nameLower := strings.ToLower(name)

	// WordPress translation files: *.l10n.php, *.mo, admin-*.php patterns
	if strings.HasSuffix(nameLower, ".l10n.php") {
		return true
	}
	if nameLower == "index.php" {
		return true
	}

	// Known safe patterns in wp-content/languages/
	if strings.Contains(path, "/wp-content/languages/") {
		// Legitimate translation files have standard naming
		if strings.HasPrefix(nameLower, "admin-") ||
			strings.HasPrefix(nameLower, "continents-") ||
			strings.Contains(path, "/languages/plugins/") ||
			strings.Contains(path, "/languages/themes/") {
			return true
		}
		// WP 6.5+ PHP translation files: xx_XX.php format (2-5 letter locale codes)
		noExt := strings.TrimSuffix(nameLower, ".php")
		if strings.Contains(noExt, "_") && len(noExt) <= 10 && !strings.ContainsAny(noExt, " /.\\") {
			return true
		}
	}

	// Known safe in mu-plugins — common hosting provider mu-plugins
	if strings.Contains(path, "/mu-plugins/") {
		safeMuPlugins := []string{
			"endurance", "starter", "imunify", "wp-toolkit",
			"starter-plugin", "starter_plugin",
			"jetpack", "object-cache", "redis-cache",
			"cloudlinux", "alt-php",
		}
		for _, safe := range safeMuPlugins {
			if strings.Contains(nameLower, safe) {
				return true
			}
		}
	}

	// Files in vendor/ or node_modules/ subdirectories within plugins/themes
	// are third-party dependencies and should not be flagged.
	if strings.Contains(path, "/wp-content/plugins/") || strings.Contains(path, "/wp-content/themes/") {
		if strings.Contains(path, "/vendor/") || strings.Contains(path, "/node_modules/") {
			return true
		}
		// Standard WordPress plugin/theme files with known safe names
		// (e.g. uninstall.php, functions.php, class-*.php, etc.)
		// The indicator-based scoring already prevents false positives
		// for normal PHP, but we skip files with a standard WP plugin header
		// to avoid unnecessary content reads.
	}

	return false
}

func countOccurrences(s, substr string) int {
	count := 0
	offset := 0
	for {
		idx := strings.Index(s[offset:], substr)
		if idx < 0 {
			break
		}
		count++
		offset += idx + len(substr)
	}
	return count
}

// containsStandaloneFunc checks if content contains a function call like "eval("
// without it being part of a longer function name (e.g. "doubleval(").
// Requires the character before the match to be non-alphanumeric or start-of-string.
func containsStandaloneFunc(content, funcCall string) bool {
	idx := 0
	for {
		pos := strings.Index(content[idx:], funcCall)
		if pos < 0 {
			return false
		}
		absPos := idx + pos
		if absPos == 0 {
			return true // at start of content
		}
		prev := content[absPos-1]
		// Must not be preceded by a letter, digit, or underscore
		isAlnum := (prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') ||
			(prev >= '0' && prev <= '9') || prev == '_'
		if !isAlnum {
			return true
		}
		idx = absPos + len(funcCall)
		if idx >= len(content) {
			return false
		}
	}
}

func containsAny(strs []string, substrs ...string) bool {
	for _, s := range strs {
		for _, sub := range substrs {
			if strings.Contains(s, sub) {
				return true
			}
		}
	}
	return false
}
