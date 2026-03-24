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

	safePatterns := []string{
		"wordfence-waf.php",
		"litespeed",
		"advanced-headers.php",
		"rsssl",
	}

	// Use find to locate .htaccess files instead of walking entire trees
	out, err := exec.Command("find", "/home", "-maxdepth", "6",
		"-name", ".htaccess", "-type", "f").Output()
	if err != nil {
		return findings
	}

	for _, path := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if path == "" {
			continue
		}

		// Skip suppressed paths
		suppressed := false
		for _, ignore := range cfg.Suppressions.IgnorePaths {
			if matchGlob(path, ignore) {
				suppressed = true
				break
			}
		}
		if suppressed {
			continue
		}

		f, err := os.Open(path)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			lineLower := strings.ToLower(line)

			for _, pattern := range suspiciousPatterns {
				if strings.Contains(lineLower, strings.ToLower(pattern)) {
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
		_ = f.Close()
	}

	return findings
}

func CheckWPCore(_ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	wpConfigs, _ := filepath.Glob("/home/*/public_html/wp-config.php")

	for _, wpConfig := range wpConfigs {
		wpPath := filepath.Dir(wpConfig)
		user := extractUser(wpPath)

		out, err := exec.Command("wp", "core", "verify-checksums",
			"--path="+wpPath, "--allow-root").CombinedOutput()
		if err != nil {
			outStr := string(out)
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
