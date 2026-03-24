package checks

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

// CheckHtaccess scans for malicious .htaccess directives using pure Go ReadDir.
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

	// Scan each user's document roots
	homeDirs, _ := os.ReadDir("/home")
	for _, homeEntry := range homeDirs {
		if !homeEntry.IsDir() {
			continue
		}
		homeDir := filepath.Join("/home", homeEntry.Name())
		docRoot := filepath.Join(homeDir, "public_html")
		scanHtaccess(docRoot, 5, suspiciousPatterns, safePatterns, cfg, &findings)

		// Also check addon domains
		subDirs, _ := os.ReadDir(homeDir)
		for _, sd := range subDirs {
			if sd.IsDir() && sd.Name() != "public_html" && sd.Name() != "mail" &&
				!strings.HasPrefix(sd.Name(), ".") && sd.Name() != "etc" &&
				sd.Name() != "logs" && sd.Name() != "ssl" && sd.Name() != "tmp" {
				scanHtaccess(filepath.Join(homeDir, sd.Name()), 5, suspiciousPatterns, safePatterns, cfg, &findings)
			}
		}
	}

	return findings
}

func scanHtaccess(dir string, maxDepth int, suspicious, safe []string, cfg *config.Config, findings *[]alert.Finding) {
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

		if entry.IsDir() {
			scanHtaccess(fullPath, maxDepth-1, suspicious, safe, cfg, findings)
			continue
		}

		if name != ".htaccess" {
			continue
		}

		// Skip suppressed paths
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

		checkHtaccessFile(fullPath, suspicious, safe, findings)
	}
}

func checkHtaccessFile(path string, suspicious, safe []string, findings *[]alert.Finding) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		lineLower := strings.ToLower(line)

		for _, pattern := range suspicious {
			if !strings.Contains(lineLower, strings.ToLower(pattern)) {
				continue
			}
			isSafe := false
			for _, sp := range safe {
				if strings.Contains(lineLower, strings.ToLower(sp)) {
					isSafe = true
					break
				}
			}
			if isSafe {
				continue
			}

			*findings = append(*findings, alert.Finding{
				Severity: alert.High,
				Check:    "htaccess_injection",
				Message:  fmt.Sprintf("Suspicious .htaccess directive: %s", pattern),
				Details:  fmt.Sprintf("File: %s (line %d)\nContent: %s", path, lineNum, strings.TrimSpace(line)),
			})
		}
	}
}

// CheckWPCore runs wp core verify-checksums for each WordPress installation.
// This is the only check that still uses an external command (wp-cli).
func CheckWPCore(_ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	wpConfigs, _ := filepath.Glob("/home/*/public_html/wp-config.php")

	for _, wpConfig := range wpConfigs {
		wpPath := filepath.Dir(wpConfig)
		user := extractUser(wpPath)

		out, err := runCmdCombined("wp", "core", "verify-checksums",
			"--path="+wpPath, "--allow-root")
		if err != nil && out != nil {
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
