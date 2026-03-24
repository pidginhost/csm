package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

// CheckFilesystem uses globs and targeted ReadDir to check for backdoors,
// hidden files, and SUID binaries. No `find` command needed.
func CheckFilesystem(_ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	// GSocket / backdoor binaries in .config dirs — glob (instant)
	backdoorNames := map[string]bool{
		"defunct": true, "defunct.dat": true, "gs-netcat": true,
		"gs-sftp": true, "gs-mount": true, "gsocket": true,
	}
	configGlobs := []string{
		"/home/*/.config/htop/*",
		"/home/*/.config/*/*",
	}
	for _, pattern := range configGlobs {
		matches, _ := filepath.Glob(pattern)
		for _, path := range matches {
			if backdoorNames[filepath.Base(path)] {
				info, _ := os.Stat(path)
				var details string
				if info != nil {
					details = fmt.Sprintf("Size: %d bytes, Mtime: %s", info.Size(), info.ModTime().Format("2006-01-02 15:04:05"))
				}
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "backdoor_binary",
					Message:  fmt.Sprintf("Backdoor binary found: %s", path),
					Details:  details,
				})
			}
		}
	}

	// Hidden files in /tmp, /dev/shm, /var/tmp — glob (instant)
	safeHiddenPrefixes := []string{
		".s.PGSQL", ".font-unix", ".ICE-unix", ".X11-unix",
		".XIM-unix", ".crontab.", ".Test-unix",
	}
	for _, pattern := range []string{"/tmp/.*", "/dev/shm/.*", "/var/tmp/.*"} {
		matches, _ := filepath.Glob(pattern)
		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil || info.IsDir() {
				continue
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
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "suspicious_file",
				Message:  fmt.Sprintf("Suspicious hidden file: %s", match),
				Details:  fmt.Sprintf("Size: %d, Mtime: %s", info.Size(), info.ModTime()),
			})
		}
	}

	// SUID binaries in tmp dirs — ReadDir + stat (small dirs, fast)
	for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		scanForSUID(dir, 3, &findings)
	}

	// SUID in /home — shallow scan only
	homeDirs, _ := os.ReadDir("/home")
	for _, entry := range homeDirs {
		if !entry.IsDir() {
			continue
		}
		scanForSUID(filepath.Join("/home", entry.Name()), 3, &findings)
	}

	return findings
}

// scanForSUID checks for SUID binaries using ReadDir.
func scanForSUID(dir string, maxDepth int, findings *[]alert.Finding) {
	if maxDepth <= 0 {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		fullPath := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			// Skip virtfs and known large dirs
			if entry.Name() == "virtfs" || entry.Name() == "mail" || entry.Name() == "public_html" {
				continue
			}
			scanForSUID(fullPath, maxDepth-1, findings)
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSetuid != 0 {
			*findings = append(*findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "suid_binary",
				Message:  fmt.Sprintf("SUID binary in unusual location: %s", fullPath),
				Details:  fmt.Sprintf("Mode: %s, Size: %d", info.Mode(), info.Size()),
			})
		}
	}
}

// CheckWebshells uses pure Go ReadDir to scan for known webshell files
// and directories. No `find` command needed.
func CheckWebshells(cfg *config.Config, _ *state.Store) []alert.Finding {
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
	homeDirs, _ := os.ReadDir("/home")
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
			scanForWebshells(docRoot, 5, webshellNames, webshellDirs, cfg, &findings)
		}
	}

	return findings
}

// scanForWebshells recursively reads directories looking for known webshell
// files and directories. Uses ReadDir (getdents) — no stat unless matched.
func scanForWebshells(dir string, maxDepth int, names map[string]bool, dirs map[string]bool, cfg *config.Config, findings *[]alert.Finding) {
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
			if dirs[name] {
				*findings = append(*findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "webshell",
					Message:  fmt.Sprintf("Webshell directory found: %s", fullPath),
				})
			}
			scanForWebshells(fullPath, maxDepth-1, names, dirs, cfg, findings)
			continue
		}

		nameLower := strings.ToLower(name)
		if names[nameLower] {
			info, _ := os.Stat(fullPath)
			var details string
			if info != nil {
				details = fmt.Sprintf("Size: %d, Mtime: %s", info.Size(), info.ModTime())
			}
			*findings = append(*findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "webshell",
				Message:  fmt.Sprintf("Known webshell found: %s", fullPath),
				Details:  details,
			})
		}

		// .haxor extension
		if strings.HasSuffix(nameLower, ".haxor") || strings.HasSuffix(nameLower, ".cgix") {
			*findings = append(*findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "webshell",
				Message:  fmt.Sprintf("Suspicious CGI file: %s", fullPath),
			})
		}
	}
}

func matchGlob(path, pattern string) bool {
	matched, _ := filepath.Match(pattern, filepath.Base(path))
	if matched {
		return true
	}
	pattern = strings.ReplaceAll(pattern, "*", "")
	return strings.Contains(path, pattern)
}
