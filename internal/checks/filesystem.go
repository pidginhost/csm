package checks

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// CheckFilesystem uses globs and targeted ReadDir to check for backdoors,
// hidden files, and SUID binaries. No `find` command needed.
func CheckFilesystem(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if ctx == nil {
		ctx = context.Background()
	}
	var findings []alert.Finding

	// GSocket / backdoor binaries in .config dirs - glob (instant).
	// Rank by mtime desc so recently-touched accounts process first
	// when the check timeout cuts iteration short.
	backdoorNames := map[string]bool{
		"defunct": true, "defunct.dat": true, "gs-netcat": true,
		"gs-sftp": true, "gs-mount": true, "gsocket": true,
	}
	configGlobs := [][]string{
		{".config", "htop", "*"},
		{".config", "*", "*"},
	}
	// The htop glob is a subset of the wider .config glob. Deduplicate
	// before ranking so the per-account cap applies to this scanner once.
	configCandidates := make([]string, 0)
	seenConfigCandidate := make(map[string]struct{})
	for _, pattern := range configGlobs {
		if ctx.Err() != nil {
			return findings
		}
		matches, err := homeGlob(ctx, pattern...)
		markScanReadError(ctx, "filesystem", err)
		for _, path := range matches {
			if ctx.Err() != nil {
				return findings
			}
			if backdoorNames[filepath.Base(path)] {
				if _, seen := seenConfigCandidate[path]; seen {
					continue
				}
				seenConfigCandidate[path] = struct{}{}
				configCandidates = append(configCandidates, path)
			}
		}
	}
	rankedConfigCandidates := rankPathsByMtimeDesc(ctx, configCandidates, accountScanMaxFiles(ctx, cfg))
	if len(rankedConfigCandidates) < len(configCandidates) {
		markCheckIncomplete(ctx, "filesystem")
	}
	if ctx.Err() != nil {
		return findings
	}
	for _, path := range rankedConfigCandidates {
		if ctx.Err() != nil {
			return findings
		}
		info, _ := osFS.Stat(path)
		var details string
		if info != nil {
			details = fmt.Sprintf("Size: %d bytes, Mtime: %s", info.Size(), info.ModTime().Format("2006-01-02 15:04:05"))
		}
		findings = append(findings, alert.Finding{
			Severity: alert.Critical,
			Check:    "backdoor_binary",
			Message:  fmt.Sprintf("Backdoor binary found: %s", path),
			Details:  details,
			FilePath: path,
		})
	}

	if AccountFromContext(ctx) == "" {
		// Hidden files in /tmp, /dev/shm, /var/tmp - glob (instant)
		safeHiddenPrefixes := []string{
			".s.PGSQL", ".font-unix", ".ICE-unix", ".X11-unix",
			".XIM-unix", ".crontab.", ".Test-unix",
		}
		// One candidate set across all three roots: on CloudLinux /var/tmp is
		// the same filesystem as /tmp, so the same physical file is reachable
		// through two of these patterns and was reported once per pattern.
		var candidates []string
		for _, pattern := range []string{"/tmp/.*", "/dev/shm/.*", "/var/tmp/.*"} {
			if ctx.Err() != nil {
				return findings
			}
			matches, err := osFS.Glob(pattern)
			markScanReadError(ctx, "filesystem", err)
			for _, match := range matches {
				if ctx.Err() != nil {
					return findings
				}
				base := filepath.Base(match)
				safe := false
				for _, prefix := range safeHiddenPrefixes {
					if strings.HasPrefix(base, prefix) {
						safe = true
						break
					}
				}
				if safe {
					continue
				}
				candidates = append(candidates, match)
			}
		}
		// These are global temp locations, not account paths; do not let
		// account_scan_max_files hide older suspicious files here.
		ranked := rankPathsByMtimeDesc(ctx, candidates, 0)
		if ctx.Err() != nil {
			return findings
		}
		var reported []os.FileInfo
		for _, match := range ranked {
			if ctx.Err() != nil {
				return findings
			}
			info, err := osFS.Stat(match)
			markScanReadError(ctx, "filesystem", err)
			if err != nil || info.IsDir() {
				continue
			}
			// A leading dot is not by itself a signal: these directories are
			// full of root-owned infrastructure state. What matters is whether
			// the file could execute.
			if !hiddenTempFileCanExecute(match) {
				continue
			}
			seen := false
			for _, prev := range reported {
				if os.SameFile(prev, info) {
					seen = true
					break
				}
			}
			if seen {
				continue
			}
			reported = append(reported, info)
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "suspicious_file",
				Message:  fmt.Sprintf("Suspicious hidden file: %s", match),
				Details:  fmt.Sprintf("Size: %d, Mtime: %s", info.Size(), info.ModTime()),
				FilePath: match,
			})
		}

		// SUID binaries in tmp dirs - ReadDir + stat (small dirs, fast)
		for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
			if ctx.Err() != nil {
				return findings
			}
			scanForSUID(ctx, dir, 3, &findings)
		}
	}

	// SUID in /home - shallow scan only
	if ctx.Err() != nil {
		return findings
	}
	homeDirs := scanHomeDirsWithCoverage(ctx, "filesystem")
	for _, entry := range homeDirs {
		if ctx.Err() != nil {
			return findings
		}
		if !entry.IsDir() {
			continue
		}
		scanForSUID(ctx, scanHomeDirPath(entry), 3, &findings)
	}

	return findings
}

// hiddenTempFileCanExecute reports whether a hidden file in a world-writable
// temp directory could run: an executable bit or ELF magic, or a script marker
// that an interpreter would honour. Inert data written there by system
// components is not a finding.
func hiddenTempFileCanExecute(path string) bool {
	// Opening a FIFO blocks until a writer appears, and these directories are
	// world-writable, so the mode is checked before anything is opened.
	info, err := osFS.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	if looksExecutableOrLibrary(path) {
		return true
	}
	f, err := osFS.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	var head [8]byte
	n, _ := io.ReadFull(f, head[:])
	prefix := strings.ToLower(string(head[:n]))
	return strings.HasPrefix(prefix, "#!") ||
		strings.HasPrefix(prefix, "<?php") ||
		strings.HasPrefix(prefix, "<?=")
}

// scanForSUID checks for SUID binaries using ReadDir.
func scanForSUID(ctx context.Context, dir string, maxDepth int, findings *[]alert.Finding) {
	if ctx.Err() != nil {
		return
	}
	if maxDepth <= 0 {
		return
	}
	entries, err := osFS.ReadDir(dir)
	if err != nil {
		markScanReadError(ctx, "filesystem", err)
		return
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		fullPath := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			// Skip virtfs and known large dirs
			if entry.Name() == "virtfs" || entry.Name() == "mail" || entry.Name() == "public_html" {
				continue
			}
			scanForSUID(ctx, fullPath, maxDepth-1, findings)
			continue
		}
		info, err := entry.Info()
		if err != nil {
			markScanReadError(ctx, "filesystem", err)
			continue
		}
		if info.Mode()&os.ModeSetuid != 0 {
			*findings = append(*findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "suid_binary",
				Message:  fmt.Sprintf("SUID binary in unusual location: %s", fullPath),
				Details:  fmt.Sprintf("Mode: %s, Size: %d", info.Mode(), info.Size()),
				FilePath: fullPath,
			})
		}
	}
}

// CheckWebshells uses pure Go ReadDir to scan for known webshell files
// and directories. No `find` command needed.
func CheckWebshells(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	webshellNames := map[string]bool{
		"h4x0r.php": true, "c99.php": true, "r57.php": true,
		"wso.php": true, "alfa.php": true, "b374k.php": true,
		"mini.php": true, "adminer.php": true,
	}
	webshellDirs := map[string]bool{
		"LEVIATHAN": true, "haxorcgiapi": true,
	}

	// Scan each user's public_html and addon domains
	homeDirs := scanHomeDirsWithCoverage(ctx, "webshells")
	for _, homeEntry := range homeDirs {
		if ctx.Err() != nil {
			return findings
		}
		if !homeEntry.IsDir() {
			continue
		}
		homeDir := scanHomeDirPath(homeEntry)

		// Get all potential document roots
		docRoots := []string{filepath.Join(homeDir, "public_html")}
		subDirs, err := osFS.ReadDir(homeDir)
		markScanReadError(ctx, "webshells", err)
		for _, sd := range subDirs {
			if sd.IsDir() && sd.Name() != "public_html" && sd.Name() != "mail" &&
				!strings.HasPrefix(sd.Name(), ".") && sd.Name() != "etc" &&
				sd.Name() != "logs" && sd.Name() != "ssl" && sd.Name() != "tmp" {
				docRoots = append(docRoots, filepath.Join(homeDir, sd.Name()))
			}
		}

		for _, docRoot := range docRoots {
			scanForWebshells(ctx, docRoot, 8, webshellNames, webshellDirs, cfg, &findings)
			if ctx.Err() != nil {
				return findings
			}
		}
	}

	return findings
}

// scanForWebshells recursively reads directories looking for known webshell
// files and directories. Uses ReadDir (getdents) - no stat unless matched.
func scanForWebshells(ctx context.Context, dir string, maxDepth int, names map[string]bool, dirs map[string]bool, cfg *config.Config, findings *[]alert.Finding) {
	if ctx.Err() != nil {
		return
	}
	if maxDepth <= 0 {
		return
	}
	entries, err := osFS.ReadDir(dir)
	if err != nil {
		markScanReadError(ctx, "webshells", err)
		return
	}

	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		name := entry.Name()
		fullPath := filepath.Join(dir, name)

		// Check suppressed paths (bypassed for explicit full-scan / audit requests).
		suppressed := false
		if scanRespectsIgnores(ctx, cfg) {
			for _, ignore := range cfg.Suppressions.IgnorePaths {
				if matchGlob(fullPath, ignore) {
					suppressed = true
					break
				}
			}
		}
		if suppressed {
			continue
		}

		if entry.IsDir() {
			if dirs[name] {
				*findings = append(*findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "webshell",
					Message:  fmt.Sprintf("Webshell directory found: %s", fullPath),
					FilePath: fullPath,
				})
			}
			scanForWebshells(ctx, fullPath, maxDepth-1, names, dirs, cfg, findings)
			continue
		}

		nameLower := strings.ToLower(name)
		if names[nameLower] {
			info, _ := osFS.Stat(fullPath)
			var details string
			if info != nil {
				details = fmt.Sprintf("Size: %d, Mtime: %s", info.Size(), info.ModTime())
			}
			*findings = append(*findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "webshell",
				Message:  fmt.Sprintf("Known webshell found: %s", fullPath),
				Details:  details,
				FilePath: fullPath,
			})
		}

		// .haxor extension
		if strings.HasSuffix(nameLower, ".haxor") || strings.HasSuffix(nameLower, ".cgix") {
			*findings = append(*findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "webshell",
				Message:  fmt.Sprintf("Suspicious CGI file: %s", fullPath),
				FilePath: fullPath,
			})
		}

		// File permission anomalies - only check PHP-executable files to keep it fast
		if isExecutablePHPName(nameLower) {
			info, err := entry.Info()
			markScanReadError(ctx, "webshells", err)
			if err == nil {
				mode := info.Mode()
				// World-writable PHP
				if mode&0002 != 0 {
					*findings = append(*findings, alert.Finding{
						Severity: alert.High,
						Check:    "world_writable_php",
						Message:  fmt.Sprintf("World-writable PHP file: %s", fullPath),
						Details:  fmt.Sprintf("Mode: %s", mode),
						FilePath: fullPath,
					})
				}
				// Note: executable PHP check removed - most PHP files on cPanel
				// have +x due to suPHP/lsapi, making this too noisy.
			}
		}
	}
}

// matchGlob reports whether path is covered by an operator suppression pattern.
//
// Matching is tried in order:
//  1. filepath.Match against the basename ("*.php", "*.log") and the full path.
//  2. For a leading-any-depth glob pattern, a substring match of the
//     wildcard-stripped residue -- but ONLY when that residue still contains a
//     path separator with literal content (e.g. "*/node_modules/*" ->
//     "/node_modules/"). This preserves the "directory anywhere in the path, at
//     any depth" intent without broadening anchored full-path globs like
//     "/tmp/safe/*" into recursive subtree suppressions.
//  3. For a pattern with no wildcards, a literal substring match, so an operator
//     can suppress a directory ("/uploads/") or a filename ("adminer.php").
//
// The separator requirement in step 2 is the fix for an over-suppression
// footgun: the previous code stripped every "*" and substring-matched the
// remainder, so "*.php" became the bare token ".php" and silenced every file
// whose path merely contained ".php" -- turning a narrow pattern into a
// whole-subtree allowlist an attacker could hide a webshell in.
// PathMatchesIgnore reports whether path is covered by any of the operator's
// suppressions.ignore_paths patterns, using the same glob semantics the
// content checks apply. Exported so the real-time watchers honour the same
// suppression list instead of maintaining a second interpretation of it.
func PathMatchesIgnore(path string, ignores []string) bool {
	for _, ignore := range ignores {
		if matchGlob(path, ignore) {
			return true
		}
	}
	return false
}

func matchGlob(path, pattern string) bool {
	if pattern == "" {
		return false
	}
	if strings.ContainsAny(pattern, "*?[") {
		if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
		if strings.ContainsAny(pattern, "?[") || !hasLeadingAnyDepthGlob(pattern) {
			return false
		}
		residue := strings.ReplaceAll(pattern, "*", "")
		if strings.Contains(residue, "/") && strings.Trim(residue, "/") != "" {
			return strings.Contains(path, residue)
		}
		return false
	}
	return strings.Contains(path, pattern)
}

func hasLeadingAnyDepthGlob(pattern string) bool {
	firstSlash := strings.Index(pattern, "/")
	if firstSlash <= 0 {
		return false
	}
	return strings.Trim(pattern[:firstSlash], "*") == ""
}
