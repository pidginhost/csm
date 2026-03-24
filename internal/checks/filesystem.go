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

	// GSocket / backdoor binaries in .config dirs
	backdoorNames := []string{"defunct", "defunct.dat", "gs-netcat", "gs-sftp", "gs-mount", "gsocket"}
	homes, _ := filepath.Glob("/home/*/.config/htop/*")
	for _, path := range homes {
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

	// Also check broader patterns
	patterns := []string{
		"/home/*/.config/*/defunct",
		"/home/*/.config/*/defunct.dat",
		"/tmp/.*",
		"/dev/shm/.*",
	}
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil || info.IsDir() {
				continue
			}
			// Skip known safe files
			if strings.Contains(match, "/tmp/lshttpd/") || strings.Contains(match, "/tmp/.s.PGSQL") {
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

	// SUID binaries in unusual locations
	suidDirs := []string{"/home", "/tmp", "/var/tmp", "/dev/shm"}
	for _, dir := range suidDirs {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error { //nolint:errcheck
			if err != nil {
				return filepath.SkipDir
			}
			if info == nil || info.IsDir() {
				return nil
			}
			if info.Mode()&os.ModeSetuid != 0 {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "suid_binary",
					Message:  fmt.Sprintf("SUID binary in unusual location: %s", path),
					Details:  fmt.Sprintf("Mode: %s, Size: %d", info.Mode(), info.Size()),
				})
			}
			return nil
		})
	}

	return findings
}

func CheckWebshells(cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Known webshell filenames
	webshellNames := []string{
		"h4x0r.php", "c99.php", "r57.php", "wso.php", "alfa.php",
		"b374k.php", "mini.php", "adminer.php",
	}
	webshellDirs := []string{"LEVIATHAN", "haxorcgiapi"}

	homes, _ := filepath.Glob("/home/*/public_html")
	for _, home := range homes {
		filepath.Walk(home, func(path string, info os.FileInfo, err error) error { //nolint:errcheck
			if err != nil {
				return filepath.SkipDir
			}
			if info == nil {
				return nil
			}

			name := info.Name()

			// Skip suppressed paths
			for _, ignore := range cfg.Suppressions.IgnorePaths {
				if matchGlob(path, ignore) {
					return nil
				}
			}

			if info.IsDir() {
				for _, d := range webshellDirs {
					if name == d {
						findings = append(findings, alert.Finding{
							Severity: alert.Critical,
							Check:    "webshell",
							Message:  fmt.Sprintf("Webshell directory found: %s", path),
						})
					}
				}
				return nil
			}

			// Check filenames
			for _, ws := range webshellNames {
				if strings.EqualFold(name, ws) {
					findings = append(findings, alert.Finding{
						Severity: alert.Critical,
						Check:    "webshell",
						Message:  fmt.Sprintf("Known webshell found: %s", path),
						Details:  fmt.Sprintf("Size: %d, Mtime: %s", info.Size(), info.ModTime()),
					})
				}
			}

			// Check for .php files in uploads dirs
			if strings.Contains(path, "/wp-content/uploads/") && strings.HasSuffix(name, ".php") {
				// Skip known safe files
				if name == "index.php" || strings.Contains(path, "/cache/") || strings.Contains(path, "/imunify") {
					return nil
				}
				findings = append(findings, alert.Finding{
					Severity: alert.High,
					Check:    "php_in_uploads",
					Message:  fmt.Sprintf("PHP file in uploads directory: %s", path),
					Details:  fmt.Sprintf("Size: %d, Mtime: %s", info.Size(), info.ModTime()),
				})
			}

			// Check for CGI files with suspicious extensions
			if strings.HasSuffix(name, ".haxor") || strings.HasSuffix(name, ".cgix") {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "webshell",
					Message:  fmt.Sprintf("Suspicious CGI file: %s", path),
				})
			}

			return nil
		})
	}

	return findings
}

func matchGlob(path, pattern string) bool {
	matched, _ := filepath.Match(pattern, filepath.Base(path))
	if matched {
		return true
	}
	// Simple contains match for patterns like "*/cache/*"
	pattern = strings.ReplaceAll(pattern, "*", "")
	return strings.Contains(path, pattern)
}
