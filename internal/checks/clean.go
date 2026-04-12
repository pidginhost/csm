package checks

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// CleanResult describes the outcome of a cleaning attempt.
type CleanResult struct {
	Path       string
	Cleaned    bool
	BackupPath string
	Removals   []string // descriptions of what was removed
	Error      string
}

// CleanInfectedFile attempts to surgically remove malicious code from a PHP file
// while preserving the legitimate content. Always creates a backup first.
//
// Cleaning strategies (tried in order):
// 1. @include injection - remove @include lines pointing to /tmp, eval, base64, or via variables
// 2. Prepend injection - remove malicious code blocks at start of file (entropy-validated)
// 3. Append injection - remove malicious code after closing ?> or end of PSR-12 file
// 4. Inline eval injection - remove eval(base64_decode(...)) single-line injections
func CleanInfectedFile(path string) CleanResult {
	result := CleanResult{Path: path}

	// Read original file
	data, err := osFS.ReadFile(path)
	if err != nil {
		result.Error = fmt.Sprintf("cannot read file: %v", err)
		return result
	}

	// Create backup before any modification
	backupDir := filepath.Join(quarantineDir, "pre_clean")
	_ = os.MkdirAll(backupDir, 0700)
	ts := time.Now().Format("20060102-150405")
	safeName := strings.ReplaceAll(path, "/", "_")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("%s_%s", ts, safeName))
	if err := os.WriteFile(backupPath, data, 0600); err != nil {
		result.Error = fmt.Sprintf("cannot create backup: %v", err)
		return result
	}
	result.BackupPath = backupPath

	// Write metadata sidecar so the WebUI quarantine page can list pre-clean backups
	info, _ := osFS.Stat(path)
	var fileSize int64
	var fileMode string
	var uid, gid int
	if info != nil {
		fileSize = info.Size()
		fileMode = info.Mode().String()
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			uid = int(stat.Uid)
			gid = int(stat.Gid)
		}
	}
	meta := map[string]interface{}{
		"original_path":  path,
		"owner_uid":      uid,
		"group_gid":      gid,
		"mode":           fileMode,
		"size":           fileSize,
		"quarantined_at": time.Now(),
		"reason":         "Pre-clean backup (surgical cleaning)",
	}
	metaData, _ := json.MarshalIndent(meta, "", "  ")
	_ = os.WriteFile(backupPath+".meta", metaData, 0600)

	content := string(data)
	originalLen := len(content)
	var removals []string

	// Strategy 1: Remove @include injections (including variable-based)
	content, removed := removeIncludeInjections(content)
	removals = append(removals, removed...)

	// Strategy 2: Remove prepend injections (with entropy validation)
	content, removed = removePrependInjection(content)
	removals = append(removals, removed...)

	// Strategy 3: Remove append injections (handles files with and without closing ?>)
	content, removed = removeAppendInjection(content)
	removals = append(removals, removed...)

	// Strategy 4: Remove inline eval(base64_decode(...)) injections
	content, removed = removeInlineEvalInjections(content)
	removals = append(removals, removed...)

	// Strategy 5: Remove multi-layer base64 decode chains
	content, removed = removeMultiLayerBase64(content)
	removals = append(removals, removed...)

	// Strategy 6: Remove chr()/pack() constructed code
	content, removed = removeChrPackInjections(content)
	removals = append(removals, removed...)

	// Strategy 7: Remove hex-encoded variable injections
	content, removed = removeHexVarInjections(content)
	removals = append(removals, removed...)

	// If nothing was removed, file couldn't be cleaned
	if len(removals) == 0 || len(content) == originalLen {
		result.Error = "no known injection patterns found - file may need manual review"
		return result
	}

	// Write cleaned file
	info, _ = osFS.Stat(path)
	mode := os.FileMode(0644)
	if info != nil {
		mode = info.Mode()
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		result.Error = fmt.Sprintf("cannot write cleaned file: %v", err)
		return result
	}

	result.Cleaned = true
	result.Removals = removals
	return result
}

// ShouldCleanInsteadOfQuarantine returns true if the file should be cleaned
// (surgical removal) instead of quarantined (full removal).
// WP core files and plugin files are better cleaned - removing them breaks the site.
// Unknown standalone files (droppers, webshells) should be quarantined.
func ShouldCleanInsteadOfQuarantine(path string) bool {
	// WP core files - always clean, never quarantine
	if strings.Contains(path, "/wp-includes/") || strings.Contains(path, "/wp-admin/") {
		return true
	}
	// Plugin/theme main files - clean to preserve functionality
	if strings.Contains(path, "/wp-content/plugins/") || strings.Contains(path, "/wp-content/themes/") {
		// But not if the file itself is the malware (h4x0r.php inside a theme)
		name := strings.ToLower(filepath.Base(path))
		if isWebshellName(name) {
			return false // quarantine this - it's a standalone webshell
		}
		return true
	}
	// Everything else - quarantine
	return false
}

// removeIncludeInjections removes @include lines that load malicious files.
// Catches:
// - @include("/tmp/...") - literal paths to temp dirs
// - @include(base64_decode("...")) - encoded includes
// - @include($var) where $var is built from obfuscated strings nearby
func removeIncludeInjections(content string) (string, []string) {
	var removals []string
	lines := strings.Split(content, "\n")
	var clean []string

	// Pattern 1: @include with literal malicious paths or encoding functions
	maliciousInclude := regexp.MustCompile(
		`(?i)^\s*@include\s*\(\s*(?:` +
			`['"](?:/tmp/|/dev/shm/|/var/tmp/)` + // include from temp dirs
			`|base64_decode\s*\(` + // include with base64
			`|str_rot13\s*\(` + // include with rot13
			`|gzinflate\s*\(` + // include with gzip
			`)`)

	// Pattern 2: @include($variable) - suspicious variable-based include
	// Only flag if the variable is defined nearby with concatenation/obfuscation
	varInclude := regexp.MustCompile(`(?i)^\s*@include\s*\(\s*\$[a-zA-Z_]+\s*\)`)

	for i, line := range lines {
		if maliciousInclude.MatchString(line) {
			removals = append(removals, fmt.Sprintf("removed @include injection: %s", strings.TrimSpace(line)))
			continue
		}

		// Variable-based @include - check surrounding context for obfuscation
		if varInclude.MatchString(line) {
			context := getLineContext(lines, i, 3)
			contextLower := strings.ToLower(context)
			isObfuscated := strings.Contains(contextLower, "base64_decode") ||
				strings.Contains(contextLower, "str_rot13") ||
				strings.Contains(contextLower, "chr(") ||
				strings.Contains(contextLower, `"\x`) ||
				strings.Count(contextLower, ". ") > 5 // heavy string concatenation
			if isObfuscated {
				removals = append(removals, fmt.Sprintf("removed obfuscated @include: %s", strings.TrimSpace(line)))
				continue
			}
		}

		clean = append(clean, line)
	}

	return strings.Join(clean, "\n"), removals
}

// removePrependInjection removes malicious PHP code injected before the
// legitimate file content. Uses entropy analysis to verify the prefix
// is actually obfuscated (not legitimate minified code).
func removePrependInjection(content string) (string, []string) {
	var removals []string

	trimmed := strings.TrimSpace(content)
	if !strings.HasPrefix(trimmed, "<?php") {
		return content, nil
	}

	// Find if there's a malicious block at the start followed by ?><?php
	closeOpen := regexp.MustCompile(`\?>\s*<\?php`)
	loc := closeOpen.FindStringIndex(content)
	if loc == nil {
		return content, nil
	}

	prefix := content[:loc[0]]
	prefixLower := strings.ToLower(prefix)

	// Check if the prefix contains malicious patterns
	hasMaliciousPatterns := strings.Contains(prefixLower, "eval(") ||
		strings.Contains(prefixLower, "base64_decode") ||
		strings.Contains(prefixLower, "gzinflate") ||
		strings.Contains(prefixLower, "str_rot13") ||
		strings.Contains(prefixLower, "@include")

	if !hasMaliciousPatterns {
		return content, nil
	}

	// Additional safety: verify the prefix has high entropy (obfuscated code)
	// or contains long encoded strings. This prevents false positives on
	// legitimate minified PHP that happens to use ?><?php patterns.
	entropy := shannonEntropy(prefix)
	hasLongStrings := containsLongEncodedString(prefix, 100)

	if entropy < 4.5 && !hasLongStrings {
		// Low entropy and no long encoded strings - likely legitimate code
		return content, nil
	}

	// Remove everything before the second <?php
	cleaned := "<?php" + content[loc[1]:]
	removals = append(removals, fmt.Sprintf("removed %d-byte prepend injection (entropy: %.2f)", loc[1], entropy))

	return cleaned, removals
}

// removeAppendInjection removes malicious code appended after the end of
// legitimate PHP content. Handles both files with closing ?> and files
// without (PSR-12 style).
func removeAppendInjection(content string) (string, []string) {
	var removals []string

	// Case 1: File has closing ?> with malicious code after it
	lastClose := strings.LastIndex(content, "?>")
	if lastClose >= 0 {
		after := content[lastClose+2:]
		afterTrimmed := strings.TrimSpace(after)
		if afterTrimmed != "" {
			afterLower := strings.ToLower(afterTrimmed)
			isMalicious := strings.Contains(afterLower, "eval(") ||
				strings.Contains(afterLower, "base64_decode") ||
				strings.Contains(afterLower, "gzinflate") ||
				strings.Contains(afterLower, "system(") ||
				strings.Contains(afterLower, "exec(") ||
				strings.Contains(afterLower, "@include") ||
				strings.Contains(afterLower, "<?php") // second PHP block appended

			if isMalicious {
				cleaned := content[:lastClose+2] + "\n"
				removals = append(removals, fmt.Sprintf("removed %d-byte append injection (after ?>)", len(after)))
				return cleaned, removals
			}
		}
	}

	// Case 2: PSR-12 style file (no closing ?>) - check if there's a malicious
	// block appended at the very end, separated by multiple newlines
	lines := strings.Split(content, "\n")
	if len(lines) < 5 {
		return content, nil
	}

	// Check last 10 lines for injected code block
	startCheck := len(lines) - 10
	if startCheck < 0 {
		startCheck = 0
	}

	blankLineIdx := -1
	for i := startCheck; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" && blankLineIdx < 0 {
			blankLineIdx = i
		}
	}

	if blankLineIdx >= 0 {
		tailBlock := strings.Join(lines[blankLineIdx:], "\n")
		tailLower := strings.ToLower(tailBlock)
		if strings.Contains(tailLower, "eval(") && strings.Contains(tailLower, "base64_decode") {
			cleaned := strings.Join(lines[:blankLineIdx], "\n") + "\n"
			removals = append(removals, fmt.Sprintf("removed %d-byte PSR-12 append injection", len(tailBlock)))
			return cleaned, removals
		}
	}

	return content, nil
}

// removeInlineEvalInjections removes single-line eval(base64_decode("..."));
// injections that are inserted as standalone lines in PHP files.
func removeInlineEvalInjections(content string) (string, []string) {
	var removals []string
	lines := strings.Split(content, "\n")
	var clean []string

	// Matches standalone eval(base64_decode("...")) or eval(gzinflate(base64_decode("...")))
	evalInject := regexp.MustCompile(
		`(?i)^\s*(?:@?)eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(`)

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if evalInject.MatchString(trimmedLine) {
			// Verify it's a standalone injection (not part of legitimate code)
			// Standalone injections are long (encoded payload) - short eval() is likely legitimate
			if len(trimmedLine) > 50 {
				removals = append(removals, fmt.Sprintf("removed inline eval injection (%d chars)", len(trimmedLine)))
				continue
			}
		}
		clean = append(clean, line)
	}

	return strings.Join(clean, "\n"), removals
}

// --- Helper functions ---

// shannonEntropy calculates the Shannon entropy of a string.
// Obfuscated/encoded code typically has entropy > 5.0.
// Normal PHP code typically has entropy 4.0-4.5.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[byte]float64)
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}

	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// containsLongEncodedString checks if the text contains a long base64-like
// string (alphanumeric + /+ without spaces).
func containsLongEncodedString(s string, minLength int) bool {
	encoded := regexp.MustCompile(`[A-Za-z0-9+/=]{` + fmt.Sprintf("%d", minLength) + `,}`)
	return encoded.MatchString(s)
}

// getLineContext returns N lines before and after the given line index.
func getLineContext(lines []string, idx, window int) string {
	start := idx - window
	if start < 0 {
		start = 0
	}
	end := idx + window + 1
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

// FormatCleanResult returns a human-readable summary of a clean operation.
func FormatCleanResult(r CleanResult) string {
	if r.Error != "" {
		return fmt.Sprintf("FAILED to clean %s: %s", r.Path, r.Error)
	}
	if !r.Cleaned {
		return fmt.Sprintf("No changes made to %s", r.Path)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "CLEANED %s\n", r.Path)
	fmt.Fprintf(&b, "  Backup: %s\n", r.BackupPath)
	for _, removal := range r.Removals {
		fmt.Fprintf(&b, "  - %s\n", removal)
	}
	return b.String()
}

// --- Strategy 5: Multi-layer base64 decode chains ---
// Catches: eval(base64_decode(base64_decode("...")))
// Catches: $x=base64_decode("...");$y=base64_decode($x);eval($y);
func removeMultiLayerBase64(content string) (string, []string) {
	var removals []string
	lines := strings.Split(content, "\n")
	var clean []string

	// Multi-layer base64: 2+ nested base64_decode calls on one line
	multiB64 := regexp.MustCompile(`(?i)(?:base64_decode\s*\(\s*){2,}`)
	// Chained base64 across variables: $x = base64_decode(...); eval($x);
	chainedB64 := regexp.MustCompile(`(?i)\$\w+\s*=\s*base64_decode\s*\(\s*base64_decode`)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) < 80 {
			clean = append(clean, line)
			continue
		}
		if multiB64.MatchString(trimmed) || chainedB64.MatchString(trimmed) {
			removals = append(removals, fmt.Sprintf("removed multi-layer base64 chain (%d chars)", len(trimmed)))
			continue
		}
		clean = append(clean, line)
	}

	return strings.Join(clean, "\n"), removals
}

// --- Strategy 6: chr()/pack() constructed code ---
// Catches: eval(chr(115).chr(121).chr(115)...);
// Catches: $f = pack("H*", "73797374656d"); $f($_POST['cmd']);
func removeChrPackInjections(content string) (string, []string) {
	var removals []string
	lines := strings.Split(content, "\n")
	var clean []string

	// 5+ chr() calls concatenated - building function names from char codes
	chrChain := regexp.MustCompile(`(?i)(?:chr\s*\(\s*\d+\s*\)\s*\.?\s*){5,}`)
	// pack("H*", ...) - hex string to function name construction
	packHex := regexp.MustCompile(`(?i)pack\s*\(\s*["']H\*["']\s*,`)

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if chrChain.MatchString(trimmed) {
			removals = append(removals, fmt.Sprintf("removed chr() chain injection (line %d, %d chars)", i+1, len(trimmed)))
			continue
		}

		if packHex.MatchString(trimmed) {
			lower := strings.ToLower(trimmed)
			// Only remove if combined with execution
			if strings.Contains(lower, "eval") || strings.Contains(lower, "$_") ||
				strings.Contains(lower, "system") || strings.Contains(lower, "exec") {
				removals = append(removals, fmt.Sprintf("removed pack() code construction (line %d)", i+1))
				continue
			}
		}

		clean = append(clean, line)
	}

	return strings.Join(clean, "\n"), removals
}

// --- Strategy 7: Hex-encoded variable injections ---
// Catches: $GLOBALS["\x61\x64\x6d\x69\x6e"] = eval(...)
// Catches: ${"\x47\x4c\x4f\x42\x41\x4c\x53"}[...] = ...
func removeHexVarInjections(content string) (string, []string) {
	var removals []string
	lines := strings.Split(content, "\n")
	var clean []string

	// Variable names built from hex: $GLOBALS["\x41\x42\x43"]
	hexVar := regexp.MustCompile(`(?:"\x5c\x78[0-9a-fA-F]{2}){3,}|(?:\\x[0-9a-fA-F]{2}){3,}`)

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) < 30 {
			clean = append(clean, line)
			continue
		}

		if hexVar.MatchString(trimmed) {
			lower := strings.ToLower(trimmed)
			// Only remove if combined with dangerous operations
			if strings.Contains(lower, "eval") || strings.Contains(lower, "system(") ||
				strings.Contains(lower, "exec(") || strings.Contains(lower, "base64_decode") ||
				strings.Contains(lower, "assert(") || strings.Contains(lower, "$_post") ||
				strings.Contains(lower, "$_request") || strings.Contains(lower, "$_get") {
				removals = append(removals, fmt.Sprintf("removed hex-encoded variable injection (line %d, %d chars)", i+1, len(trimmed)))
				continue
			}
		}

		clean = append(clean, line)
	}

	return strings.Join(clean, "\n"), removals
}
