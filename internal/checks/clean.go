package checks

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// CleanResult describes the outcome of a cleaning attempt.
type CleanResult struct {
	Path       string
	Cleaned    bool
	BackupPath string
	Removals   []string // descriptions of what was removed
	Error      string
}

var (
	// Leading class is [\s\x00\x0b] rather than \s: an injection can pad
	// the line start with NUL or vertical-tab bytes that Go's \s does not
	// cover. Detection still flags the file (analyzePHPContent is not
	// anchored); widening the class here lets the surgical cleaner strip
	// the injection instead of falling back to whole-file quarantine.
	cleanRegexpMaliciousInclude = regexp.MustCompile(
		`(?i)^[\s\x00\x0b]*@include\s*\(\s*(?:` +
			`['"](?:/tmp/|/dev/shm/|/var/tmp/)` +
			`|base64_decode\s*\(` +
			`|str_rot13\s*\(` +
			`|gzinflate\s*\(` +
			`)`)
	cleanRegexpVarInclude = regexp.MustCompile(`(?i)^[\s\x00\x0b]*@include\s*\(\s*\$[a-zA-Z_]+\s*\)`)
	cleanRegexpCloseOpen  = regexp.MustCompile(`\?>\s*<\?php`)
	cleanRegexpInlineEval = regexp.MustCompile(
		`(?i)^[\s\x00\x0b]*(?:@?)eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(`)
	cleanRegexpMultiB64   = regexp.MustCompile(`(?i)(?:base64_decode\s*\(\s*){2,}`)
	cleanRegexpChainedB64 = regexp.MustCompile(`(?i)\$\w+\s*=\s*base64_decode\s*\(\s*base64_decode`)
	cleanRegexpChrChain   = regexp.MustCompile(`(?i)\bchr\s*\(\s*\d+\s*\)(?:\s*\.?\s*\bchr\s*\(\s*\d+\s*\)){4,}`)
	cleanRegexpPackHex    = regexp.MustCompile(`(?i)pack\s*\(\s*["']H\*["']\s*,`)
	cleanRegexpHexVar     = regexp.MustCompile(`(?:"\x5c\x78[0-9a-fA-F]{2}){3,}|(?:\\x[0-9a-fA-F]{2}){3,}`)
)

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

	target, err := openCleanTarget(path)
	if err != nil {
		result.Error = fmt.Sprintf("cannot read file: %v", err)
		return result
	}
	defer target.Close()

	data, err := io.ReadAll(target.File)
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

	// Metadata sidecar derived from the same fd we read, so a directory
	// race after open cannot change the metadata we record.
	meta := map[string]interface{}{
		"original_path":  path,
		"owner_uid":      target.UID,
		"group_gid":      target.GID,
		"mode":           target.Info.Mode().String(),
		"size":           target.Info.Size(),
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

	if err := writeCleanedFileAtomic(target, []byte(content)); err != nil {
		result.Error = fmt.Sprintf("cannot write cleaned file: %v", err)
		return result
	}

	result.Cleaned = true
	result.Removals = removals
	return result
}

type cleanTarget struct {
	Path       string
	DirFD      int
	Name       string
	File       *os.File
	Info       os.FileInfo
	UID        int
	GID        int
	OwnerKnown bool
}

func (t *cleanTarget) Close() {
	if t.File != nil {
		_ = t.File.Close()
	}
	if t.DirFD >= 0 {
		_ = unix.Close(t.DirFD)
	}
}

func openCleanTarget(path string) (*cleanTarget, error) {
	dir, name := filepath.Split(path)
	if name == "" || name == "." || name == ".." {
		return nil, fmt.Errorf("invalid target path %q", path)
	}
	if dir == "" {
		dir = "."
	}
	dir = filepath.Clean(dir)
	parentInfo, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat parent directory: %w", err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing symlinked parent directory")
	}

	// Pin the immediate parent. A swap of that directory to a symlink
	// after detection must not redirect either the read or the writeback.
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open parent directory: %w", err)
	}
	closeDir := true
	defer func() {
		if closeDir {
			_ = unix.Close(dirFD)
		}
	}()
	if pinErr := verifyCleanParentStillPinned(dirFD, parentInfo); pinErr != nil {
		return nil, pinErr
	}

	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	// #nosec G115 -- unix.Openat returned a non-negative fd because err is nil.
	file := os.NewFile(uintptr(fd), path)
	closeFile := true
	defer func() {
		if closeFile {
			_ = file.Close()
		}
	}()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing non-regular file (mode=%v)", info.Mode())
	}

	target := &cleanTarget{
		Path:  path,
		DirFD: dirFD,
		Name:  name,
		File:  file,
		Info:  info,
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		target.UID = int(stat.Uid)
		target.GID = int(stat.Gid)
		target.OwnerKnown = true
	}

	closeDir = false
	closeFile = false
	return target, nil
}

func verifyCleanParentStillPinned(dirFD int, want os.FileInfo) error {
	var got unix.Stat_t
	if err := unix.Fstat(dirFD, &got); err != nil {
		return fmt.Errorf("stat opened parent directory: %w", err)
	}
	if !sameUnixStatIdentity(want, got) {
		return fmt.Errorf("parent directory changed during cleaning")
	}
	return nil
}

func sameUnixStatIdentity(info os.FileInfo, stat unix.Stat_t) bool {
	if info == nil {
		return false
	}
	want, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return uint64(want.Dev) == uint64(stat.Dev) && uint64(want.Ino) == uint64(stat.Ino)
}

// writeCleanedFileAtomic stages cleaned content through a hidden sibling
// name under the pinned parent directory and renames it over the original
// only after the path still resolves to the inode we read.
func writeCleanedFileAtomic(target *cleanTarget, content []byte) error {
	tmp, tmpName, err := createCleanTempFile(target.DirFD)
	if err != nil {
		return err
	}
	removeTmp := true
	defer func() {
		if removeTmp {
			_ = unix.Unlinkat(target.DirFD, tmpName, 0)
		}
		_ = tmp.Close()
	}()

	if _, err := tmp.Write(content); err != nil {
		return err
	}
	if target.OwnerKnown {
		if err := tmp.Chown(target.UID, target.GID); err != nil {
			return err
		}
	}
	if err := tmp.Chmod(cleanReplacementMode(target.Info.Mode())); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}

	if err := verifyCleanTargetUnchanged(target); err != nil {
		return err
	}

	if err := unix.Renameat(target.DirFD, tmpName, target.DirFD, target.Name); err != nil {
		return err
	}
	removeTmp = false
	return nil
}

func createCleanTempFile(dirFD int) (*os.File, string, error) {
	for i := 0; i < 100; i++ {
		var raw [8]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return nil, "", fmt.Errorf("random temp name: %w", err)
		}
		name := ".csm-clean-" + hex.EncodeToString(raw[:])
		fd, err := unix.Openat(dirFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err == unix.EEXIST {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		// #nosec G115 -- unix.Openat returned a non-negative fd because err is nil.
		return os.NewFile(uintptr(fd), name), name, nil
	}
	return nil, "", fmt.Errorf("could not allocate temp file name")
}

func verifyCleanTargetUnchanged(target *cleanTarget) error {
	fd, err := unix.Openat(target.DirFD, target.Name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open target before rename: %w", err)
	}
	// #nosec G115 -- unix.Openat returned a non-negative fd because err is nil.
	file := os.NewFile(uintptr(fd), target.Path)
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat target before rename: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing non-regular target before rename (mode=%v)", info.Mode())
	}
	if !sameFileIdentity(info, target.Info) || !sameCleanContentShape(info, target.Info) {
		return fmt.Errorf("file changed during cleaning")
	}
	return nil
}

func sameCleanContentShape(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func cleanReplacementMode(mode os.FileMode) os.FileMode {
	return mode & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
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

	for i, line := range lines {
		if cleanRegexpMaliciousInclude.MatchString(line) {
			removals = append(removals, fmt.Sprintf("removed @include injection: %s", strings.TrimSpace(line)))
			continue
		}

		// Variable-based @include - check surrounding context for obfuscation
		if cleanRegexpVarInclude.MatchString(line) {
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
	loc := cleanRegexpCloseOpen.FindStringIndex(content)
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

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		// Strip /* ... */ block comments and trailing // / # comments
		// before matching. Attackers wedge comments between the keyword
		// and the open paren ("@eval/*x*/(base64_decode(...))") to slip
		// past a strict regex; the cleaner has to see the line the way
		// the PHP tokenizer does, not byte-for-byte.
		normalized := stripPHPComments(trimmedLine)
		if cleanRegexpInlineEval.MatchString(normalized) {
			// Length gate stays on the ORIGINAL line so a short legitimate
			// eval() does not get sucked into the removal path.
			if len(trimmedLine) > 50 {
				removals = append(removals, fmt.Sprintf("removed inline eval injection (%d chars)", len(trimmedLine)))
				continue
			}
		}
		clean = append(clean, line)
	}

	return strings.Join(clean, "\n"), removals
}

// stripPHPComments removes PHP comments while leaving quoted strings
// intact, so comment-looking payload data does not change the code the
// cleaner evaluates.
func stripPHPComments(line string) string {
	return strings.TrimSpace(stripPHPCommentsFromCode(line))
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
	if minLength <= 0 {
		return true
	}

	run := 0
	for i := 0; i < len(s); i++ {
		if isEncodedStringByte(s[i]) {
			run++
			if run >= minLength {
				return true
			}
			continue
		}
		run = 0
	}
	return false
}

func isEncodedStringByte(b byte) bool {
	return b >= 'A' && b <= 'Z' ||
		b >= 'a' && b <= 'z' ||
		b >= '0' && b <= '9' ||
		b == '+' || b == '/' || b == '='
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

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) < 80 {
			clean = append(clean, line)
			continue
		}
		if cleanRegexpMultiB64.MatchString(trimmed) || cleanRegexpChainedB64.MatchString(trimmed) {
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

	// Find chr-chain spans across the full content first so multi-line
	// chains (chr(115)\n.chr(121)\n...) are recognized as one chain
	// instead of slipping past the per-line 5+ count.
	dropLine := make(map[int]bool)
	offsets := make([]int, len(lines))
	off := 0
	for i, line := range lines {
		offsets[i] = off
		off += len(line) + 1 // +1 for the newline strings.Split consumed
	}
	for _, span := range cleanRegexpChrChain.FindAllStringIndex(content, -1) {
		startLine, endLine := chrChainStatementLineRange(lines, offsets, span)
		for i := startLine; i <= endLine; i++ {
			dropLine[i] = true
		}
	}

	var clean []string
	for i, line := range lines {
		if dropLine[i] {
			removals = append(removals, fmt.Sprintf("removed chr() chain injection (line %d, %d chars)", i+1, len(strings.TrimSpace(line))))
			continue
		}
		trimmed := strings.TrimSpace(line)

		if cleanRegexpPackHex.MatchString(trimmed) {
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

func chrChainStatementLineRange(lines []string, offsets []int, span []int) (int, int) {
	startLine := lineIndexForOffset(offsets, span[0])
	endLine := lineIndexForOffset(offsets, span[1]-1)

	for startLine > 0 && chrChainPrefixContinues(lines[startLine-1]) {
		startLine--
	}
	for endLine+1 < len(lines) && !strings.Contains(lines[endLine], ";") && chrChainSuffixContinues(lines[endLine+1]) {
		endLine++
		if strings.Contains(lines[endLine], ";") {
			break
		}
	}
	return startLine, endLine
}

func chrChainPrefixContinues(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || trimmed == "<?php" {
		return false
	}
	return strings.HasSuffix(trimmed, "=") ||
		strings.HasSuffix(trimmed, ".") ||
		strings.HasSuffix(trimmed, "(") ||
		strings.HasSuffix(trimmed, ",") ||
		strings.HasSuffix(trimmed, "[")
}

func chrChainSuffixContinues(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return true
	}
	return strings.HasPrefix(trimmed, ".") ||
		strings.HasPrefix(trimmed, ")") ||
		strings.HasPrefix(trimmed, ",") ||
		strings.HasPrefix(trimmed, ";")
}

// lineIndexForOffset returns the index of the line containing the byte
// at offset within the original content.
func lineIndexForOffset(offsets []int, byteOffset int) int {
	if len(offsets) == 0 || byteOffset < 0 {
		return 0
	}
	idx := sort.Search(len(offsets), func(i int) bool {
		return offsets[i] > byteOffset
	}) - 1
	if idx < 0 {
		return 0
	}
	if idx >= len(offsets) {
		return len(offsets) - 1
	}
	return idx
}

// --- Strategy 7: Hex-encoded variable injections ---
// Catches: $GLOBALS["\x61\x64\x6d\x69\x6e"] = eval(...)
// Catches: ${"\x47\x4c\x4f\x42\x41\x4c\x53"}[...] = ...
func removeHexVarInjections(content string) (string, []string) {
	var removals []string
	lines := strings.Split(content, "\n")
	var clean []string

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) < 30 {
			clean = append(clean, line)
			continue
		}

		if cleanRegexpHexVar.MatchString(trimmed) {
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
