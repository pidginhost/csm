package checks

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

func CheckHtaccess(cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	suspiciousPatterns := []string{
		"auto_prepend_file",
		"auto_append_file",
		"eval(",
		"base64_decode",
		"gzinflate",
		"str_rot13",
		"php_value disable_functions",
	}

	// Known safe patterns to whitelist
	safePatterns := []string{
		"wordfence-waf.php",
		"litespeed",
	}

	homes, _ := filepath.Glob("/home/*/public_html")
	for _, home := range homes {
		_ = filepath.Walk(home, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return filepath.SkipDir
			}
			if info == nil || info.IsDir() {
				return nil
			}
			if info.Name() != ".htaccess" {
				return nil
			}

			// Skip suppressed paths
			for _, ignore := range cfg.Suppressions.IgnorePaths {
				if matchGlob(path, ignore) {
					return nil
				}
			}

			f, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer func() { _ = f.Close() }()

			scanner := bufio.NewScanner(f)
			lineNum := 0
			for scanner.Scan() {
				lineNum++
				line := scanner.Text()
				lineLower := strings.ToLower(line)

				for _, pattern := range suspiciousPatterns {
					if strings.Contains(lineLower, strings.ToLower(pattern)) {
						// Check if it matches a safe pattern
						safe := false
						for _, sp := range safePatterns {
							if strings.Contains(lineLower, strings.ToLower(sp)) {
								safe = true
								break
							}
						}
						if safe {
							continue
						}

						findings = append(findings, alert.Finding{
							Severity: alert.High,
							Check:    "htaccess_injection",
							Message:  fmt.Sprintf("Suspicious .htaccess directive: %s", pattern),
							Details:  fmt.Sprintf("File: %s (line %d)\nContent: %s", path, lineNum, strings.TrimSpace(line)),
						})
					}
				}
			}
			return nil
		})
	}

	return findings
}

func CheckWPCore(_ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Find all WordPress installations
	wpConfigs, _ := filepath.Glob("/home/*/public_html/wp-config.php")

	for _, wpConfig := range wpConfigs {
		wpPath := filepath.Dir(wpConfig)
		user := extractUser(wpPath)

		out, err := exec.Command("wp", "core", "verify-checksums",
			"--path="+wpPath, "--allow-root").CombinedOutput()
		if err != nil {
			outStr := string(out)
			// Filter out error_log warnings
			lines := strings.Split(outStr, "\n")
			for _, line := range lines {
				if strings.Contains(line, "should not exist") && !strings.Contains(line, "error_log") {
					findings = append(findings, alert.Finding{
						Severity: alert.High,
						Check:    "wp_core_integrity",
						Message:  fmt.Sprintf("WordPress core integrity failure for %s", user),
						Details:  fmt.Sprintf("Path: %s\n%s", wpPath, line),
					})
				}
			}
		}
	}

	return findings
}

func extractUser(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if p == "home" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return "unknown"
}
