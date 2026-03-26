package checks

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// CleanResult describes the outcome of a cleaning attempt.
type CleanResult struct {
	Path        string
	Cleaned     bool
	BackupPath  string
	Removals    []string // descriptions of what was removed
	Error       string
}

// CleanInfectedFile attempts to surgically remove malicious code from a PHP file
// while preserving the legitimate content. Always creates a backup first.
//
// Cleaning strategies (tried in order):
// 1. WP core file — restore from wp core download if checksum mismatch
// 2. @include injection — remove @include lines pointing to /tmp, eval, base64
// 3. Prepend/append injection — remove malicious code blocks at start/end of file
// 4. Inline eval injection — remove eval(base64_decode(...)) single-line injections
func CleanInfectedFile(path string) CleanResult {
	result := CleanResult{Path: path}

	// Read original file
	data, err := os.ReadFile(path)
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

	content := string(data)
	originalLen := len(content)
	var removals []string

	// Strategy 1: Remove @include injections
	content, removed := removeIncludeInjections(content)
	removals = append(removals, removed...)

	// Strategy 2: Remove prepend injections (malicious code before <?php)
	content, removed = removePrependInjection(content)
	removals = append(removals, removed...)

	// Strategy 3: Remove append injections (malicious code after closing ?>)
	content, removed = removeAppendInjection(content)
	removals = append(removals, removed...)

	// Strategy 4: Remove inline eval(base64_decode(...)) injections
	content, removed = removeInlineEvalInjections(content)
	removals = append(removals, removed...)

	// If nothing was removed, file couldn't be cleaned
	if len(removals) == 0 || len(content) == originalLen {
		result.Error = "no known injection patterns found — file may need manual review"
		return result
	}

	// Write cleaned file
	info, _ := os.Stat(path)
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

// removeIncludeInjections removes @include lines that load malicious files.
// Pattern: @include("/tmp/...") or @include(base64_decode("..."))
func removeIncludeInjections(content string) (string, []string) {
	var removals []string
	lines := strings.Split(content, "\n")
	var clean []string

	// Patterns for malicious @include
	maliciousInclude := regexp.MustCompile(
		`(?i)^\s*@include\s*\(\s*(?:` +
			`['"](?:/tmp/|/dev/shm/|/var/tmp/)` + // include from temp dirs
			`|base64_decode\s*\(` + // include with base64
			`|str_rot13\s*\(` + // include with rot13
			`|gzinflate\s*\(` + // include with gzip
			`)`)

	for _, line := range lines {
		if maliciousInclude.MatchString(line) {
			removals = append(removals, fmt.Sprintf("removed @include injection: %s", strings.TrimSpace(line)))
		} else {
			clean = append(clean, line)
		}
	}

	return strings.Join(clean, "\n"), removals
}

// removePrependInjection removes malicious PHP code injected before the
// legitimate file content. Common pattern: eval(base64_decode("...")) or
// long obfuscated block before the first legitimate <?php tag.
func removePrependInjection(content string) (string, []string) {
	var removals []string

	// Pattern: file starts with <?php followed by eval/base64 on the same or next line,
	// then has a second <?php that starts the real content
	if !strings.HasPrefix(strings.TrimSpace(content), "<?php") {
		return content, nil
	}

	// Find if there's a malicious block at the start followed by a closing ?> and new <?php
	// Common: <?php eval(base64_decode("...")); ?><?php (real content)
	closeOpen := regexp.MustCompile(`\?>\s*<\?php`)
	loc := closeOpen.FindStringIndex(content)
	if loc == nil {
		return content, nil
	}

	prefix := strings.ToLower(content[:loc[0]])
	// Check if the prefix contains malicious patterns
	isMalicious := strings.Contains(prefix, "eval(") ||
		strings.Contains(prefix, "base64_decode") ||
		strings.Contains(prefix, "gzinflate") ||
		strings.Contains(prefix, "str_rot13") ||
		strings.Contains(prefix, "@include")

	if !isMalicious {
		return content, nil
	}

	// Remove everything before the second <?php
	cleaned := "<?php" + content[loc[1]:]
	removals = append(removals, fmt.Sprintf("removed %d-byte prepend injection", loc[1]))

	return cleaned, removals
}

// removeAppendInjection removes malicious code appended after a closing ?> tag.
func removeAppendInjection(content string) (string, []string) {
	var removals []string

	// Find the last ?> followed by <?php with malicious content
	lastClose := strings.LastIndex(content, "?>")
	if lastClose < 0 {
		return content, nil
	}

	after := content[lastClose+2:]
	afterTrimmed := strings.TrimSpace(after)
	if afterTrimmed == "" {
		return content, nil // nothing after ?>, normal
	}

	afterLower := strings.ToLower(afterTrimmed)
	isMalicious := strings.Contains(afterLower, "eval(") ||
		strings.Contains(afterLower, "base64_decode") ||
		strings.Contains(afterLower, "gzinflate") ||
		strings.Contains(afterLower, "system(") ||
		strings.Contains(afterLower, "exec(") ||
		strings.Contains(afterLower, "@include")

	if !isMalicious {
		return content, nil
	}

	cleaned := content[:lastClose+2] + "\n"
	removals = append(removals, fmt.Sprintf("removed %d-byte append injection", len(after)))

	return cleaned, removals
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
		trimmed := strings.TrimSpace(line)
		if evalInject.MatchString(trimmed) {
			// Verify it's a standalone injection (not part of legitimate code)
			// Standalone = the line is mostly just the eval call
			if len(trimmed) > 50 { // short eval() is likely legitimate, long = encoded payload
				removals = append(removals, fmt.Sprintf("removed inline eval injection (%d chars)", len(trimmed)))
				continue
			}
		}
		clean = append(clean, line)
	}

	return strings.Join(clean, "\n"), removals
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
	for _, r := range r.Removals {
		fmt.Fprintf(&b, "  - %s\n", r)
	}
	return b.String()
}
