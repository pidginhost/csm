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

func CheckFilesystem(_ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	// GSocket / backdoor binaries in .config dirs — targeted glob, not walk
	backdoorNames := []string{"defunct", "defunct.dat", "gs-netcat", "gs-sftp", "gs-mount", "gsocket"}

	configGlobs := []string{
		"/home/*/.config/htop/*",
		"/home/*/.config/*/*",
	}
	for _, pattern := range configGlobs {
		matches, _ := filepath.Glob(pattern)
		for _, path := range matches {
			name := filepath.Base(path)
			for _, bad := range backdoorNames {
				if name == bad {
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
	}

	// Hidden files in /tmp and /dev/shm — targeted glob, not walk
	tmpGlobs := []string{"/tmp/.*", "/dev/shm/.*", "/var/tmp/.*"}
	for _, pattern := range tmpGlobs {
		matches, _ := filepath.Glob(pattern)
		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil || info.IsDir() {
				continue
			}
			base := filepath.Base(match)
			// Skip known safe files
			if strings.HasPrefix(base, ".s.PGSQL") ||
				strings.HasPrefix(base, ".font-unix") ||
				strings.HasPrefix(base, ".ICE-unix") ||
				strings.HasPrefix(base, ".X11-unix") ||
				strings.HasPrefix(base, ".XIM-unix") ||
				strings.HasPrefix(base, ".crontab.") {
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

	// SUID binaries in unusual locations — use find command with maxdepth
	// instead of filepath.Walk which traverses millions of files
	suidDirs := []string{"/tmp", "/var/tmp", "/dev/shm"}
	for _, dir := range suidDirs {
		out, err := runCmd("find", dir, "-maxdepth", "3", "-perm", "-4000", "-type", "f")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line == "" {
				continue
			}
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "suid_binary",
				Message:  fmt.Sprintf("SUID binary in unusual location: %s", line),
			})
		}
	}

	// SUID in /home — only check shallow depths, not entire trees
	out, err := runCmd("find", "/home", "-maxdepth", "4", "-perm", "-4000", "-type", "f",
		"-not", "-path", "*/virtfs/*")
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line == "" {
				continue
			}
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "suid_binary",
				Message:  fmt.Sprintf("SUID binary in home directory: %s", line),
			})
		}
	}

	return findings
}

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

	knownSafeUploadPaths := []string{
		"/cache/", "/imunify", "/redux/", "/mailchimp-for-wp/",
		"/sucuri/", "/smush/", "/goldish/", "/wpallexport/",
		"/wpallimport/", "/wph/", "/stm_fonts/", "/smile_fonts/",
		"/bws-custom-code/", "/wp-import-export-lite/",
		"/mc4wp-debug-log.php", "/zn_fonts/", "/companies_documents/",
	}

	// Use find command to search for webshell filenames — much faster than Walk
	// Search only top-level and common webshell drop locations
	findArgs := []string{"/home", "-maxdepth", "6", "("}
	first := true
	for name := range webshellNames {
		if !first {
			findArgs = append(findArgs, "-o")
		}
		findArgs = append(findArgs, "-name", name)
		first = false
	}
	// Also search for webshell directories
	for name := range webshellDirs {
		findArgs = append(findArgs, "-o", "-name", name, "-type", "d")
	}
	// Also search for .haxor files
	findArgs = append(findArgs, "-o", "-name", "*.haxor")
	findArgs = append(findArgs, ")")

	out, err := runCmd("find", findArgs...)
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line == "" {
				continue
			}
			// Skip suppressed paths
			suppressed := false
			for _, ignore := range cfg.Suppressions.IgnorePaths {
				if matchGlob(line, ignore) {
					suppressed = true
					break
				}
			}
			if suppressed {
				continue
			}

			info, _ := os.Stat(line)
			if info != nil && info.IsDir() {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "webshell",
					Message:  fmt.Sprintf("Webshell directory found: %s", line),
				})
			} else {
				var details string
				if info != nil {
					details = fmt.Sprintf("Size: %d, Mtime: %s", info.Size(), info.ModTime())
				}
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "webshell",
					Message:  fmt.Sprintf("Known webshell found: %s", line),
					Details:  details,
				})
			}
		}
	}

	// PHP files in uploads dirs — targeted find instead of walking everything
	out, err = runCmd("find", "/home", "-maxdepth", "8",
		"-path", "*/wp-content/uploads/*.php",
		"-not", "-name", "index.php",
		"-type", "f")
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line == "" {
				continue
			}

			// Skip known safe paths
			safe := false
			for _, sp := range knownSafeUploadPaths {
				if strings.Contains(line, sp) {
					safe = true
					break
				}
			}
			if safe {
				continue
			}

			info, _ := os.Stat(line)
			var details string
			if info != nil {
				details = fmt.Sprintf("Size: %d, Mtime: %s", info.Size(), info.ModTime())
			}
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "php_in_uploads",
				Message:  fmt.Sprintf("PHP file in uploads directory: %s", line),
				Details:  details,
			})
		}
	}

	return findings
}

func matchGlob(path, pattern string) bool {
	matched, _ := filepath.Match(pattern, filepath.Base(path))
	if matched {
		return true
	}
	pattern = strings.ReplaceAll(pattern, "*", "")
	return strings.Contains(path, pattern)
}
