package checks

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

const wpChecksumWorkers = 5 // concurrent wp core verify-checksums

// CheckHtaccess scans for malicious .htaccess directives using pure Go ReadDir.
func CheckHtaccess(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	suspiciousPatterns := []string{
		"auto_prepend_file",
		"auto_append_file",
		"eval(",
		"base64_decode",
		"gzinflate",
		"str_rot13",
		"php_value disable_functions",
		"addhandler",
		"addtype",
		"sethandler",
	}

	safePatterns := []string{
		"wordfence-waf.php",
		"litespeed",
		"advanced-headers.php",
		"rsssl",
		// Standard handler directives for PHP/static files are safe
		"application/x-httpd-php",
		"application/x-httpd-php5",
		"application/x-httpd-ea-php",
		"application/x-httpd-alt-php",
		"text/html",
		"text/css",
		"text/javascript",
		"application/javascript",
		"image/",
		"font/",
		"proxy:unix",
		// Security plugins that use handler directives to BLOCK execution
		"-execcgi",                   // Options -ExecCGI disables CGI (Wordfence pattern)
		"sethandler none",            // Disables all handlers (security measure)
		"sethandler default-handler", // Resets to default (security measure)
		// Legitimate MIME type additions
		"application/font",
		"application/vnd",
		".woff",
		".woff2",
		".ttf",
		".eot",
		".svg",
		// Wordfence code execution protection
		"wordfence",
	}

	// Scan each user's document roots
	homeDirs, _ := GetScanHomeDirs()
	for _, homeEntry := range homeDirs {
		if ctx.Err() != nil {
			return findings
		}
		if !homeEntry.IsDir() {
			continue
		}
		homeDir := filepath.Join("/home", homeEntry.Name())
		docRoot := filepath.Join(homeDir, "public_html")
		scanHtaccess(ctx, docRoot, 5, suspiciousPatterns, safePatterns, cfg, &findings)

		// Also check addon domains
		subDirs, _ := os.ReadDir(homeDir)
		for _, sd := range subDirs {
			if sd.IsDir() && sd.Name() != "public_html" && sd.Name() != "mail" &&
				!strings.HasPrefix(sd.Name(), ".") && sd.Name() != "etc" &&
				sd.Name() != "logs" && sd.Name() != "ssl" && sd.Name() != "tmp" {
				scanHtaccess(ctx, filepath.Join(homeDir, sd.Name()), 5, suspiciousPatterns, safePatterns, cfg, &findings)
			}
		}
	}

	return findings
}

func scanHtaccess(ctx context.Context, dir string, maxDepth int, suspicious, safe []string, cfg *config.Config, findings *[]alert.Finding) {
	if ctx.Err() != nil {
		return
	}
	if maxDepth <= 0 {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		name := entry.Name()
		fullPath := filepath.Join(dir, name)

		if entry.IsDir() {
			scanHtaccess(ctx, fullPath, maxDepth-1, suspicious, safe, cfg, findings)
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

	// Read entire file to check cross-line context (e.g., AddHandler + Options -ExecCGI)
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	// Build full file content for context checks
	fullContentLower := strings.ToLower(strings.Join(lines, "\n"))

	// If file contains handler directives paired with -ExecCGI, the whole
	// block is a security measure (e.g., Wordfence execution protection)
	hasExecCGIBlock := strings.Contains(fullContentLower, "-execcgi")

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		lineLower := strings.ToLower(trimmed)

		// Skip comments entirely - commented-out directives are not active
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		for _, pattern := range suspicious {
			if !strings.Contains(lineLower, strings.ToLower(pattern)) {
				continue
			}

			// Check per-line safe patterns
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

			patternLower := strings.ToLower(pattern)

			// For handler directives, apply context-aware checks
			if patternLower == "addhandler" || patternLower == "sethandler" {
				// Skip if paired with -ExecCGI (Wordfence protection)
				if hasExecCGIBlock {
					continue
				}
				// Skip Drupal security handlers
				if strings.Contains(lineLower, "drupal_security") {
					continue
				}
				// Skip SetHandler none/default (disabling handlers = security measure)
				if strings.Contains(lineLower, "sethandler none") ||
					strings.Contains(lineLower, "sethandler default") {
					continue
				}
				// Skip AddHandler for standard CGI extensions only (.cgi, .pl)
				if strings.Contains(lineLower, "addhandler") {
					// Only flag if mapping non-standard extensions
					standardCGI := true
					hasNonStandard := false
					// Check each extension on the line
					for _, ext := range []string{".haxor", ".cgix", ".phtml", ".php3",
						".php5", ".suspected", ".bak.php", ".shtml", ".sh"} {
						if strings.Contains(lineLower, ext) {
							hasNonStandard = true
							break
						}
					}
					// If line only has .cgi and/or .pl, it's standard
					if !hasNonStandard && standardCGI {
						onlyStandard := true
						parts := strings.Fields(lineLower)
						for _, p := range parts {
							if strings.HasPrefix(p, ".") && p != ".cgi" && p != ".pl" && p != ".py" &&
								p != ".php" && p != ".jsp" && p != ".asp" {
								// Has non-standard extension
								onlyStandard = false
								break
							}
						}
						if onlyStandard {
							continue
						}
					}
				}
			}

			// Skip AddType for any MIME type (application/*, text/*, x-mapp-*, etc.)
			if patternLower == "addtype" {
				// AddType is only dangerous if it maps to a PHP/CGI handler
				// Standard MIME type declarations are safe
				if strings.Contains(lineLower, "application/") ||
					strings.Contains(lineLower, "text/") ||
					strings.Contains(lineLower, "image/") ||
					strings.Contains(lineLower, "font/") ||
					strings.Contains(lineLower, "x-mapp-") ||
					strings.Contains(lineLower, "audio/") ||
					strings.Contains(lineLower, "video/") {
					continue
				}
			}

			*findings = append(*findings, alert.Finding{
				Severity: alert.High,
				Check:    "htaccess_injection",
				Message:  fmt.Sprintf("Suspicious .htaccess directive: %s", pattern),
				Details:  fmt.Sprintf("File: %s (line %d)\nContent: %s", path, lineNum+1, trimmed),
				FilePath: path,
			})
		}
	}

	// Special check: AddHandler mapping non-standard extensions WITHOUT -ExecCGI
	// (actual attack pattern - e.g., AddHandler cgi-script .haxor)
	if !hasExecCGIBlock && strings.Contains(fullContentLower, "addhandler") {
		for lineNum, line := range lines {
			lineLower := strings.ToLower(line)
			if !strings.Contains(lineLower, "addhandler") {
				continue
			}
			// Flag if it maps unusual extensions like .haxor, .cgix, etc.
			dangerousExts := []string{".haxor", ".cgix", ".suspected", ".bak.php"}
			for _, ext := range dangerousExts {
				if strings.Contains(lineLower, ext) {
					*findings = append(*findings, alert.Finding{
						Severity: alert.Critical,
						Check:    "htaccess_handler_abuse",
						Message:  fmt.Sprintf("Malicious handler mapping for %s extension", ext),
						Details:  fmt.Sprintf("File: %s (line %d)\nContent: %s", path, lineNum+1, strings.TrimSpace(line)),
						FilePath: path,
					})
				}
			}
		}
	}
}

// CheckWPCore runs wp core verify-checksums for each WordPress installation
// using a bounded worker pool for concurrency.
// Installations that pass verification have their core files cached in
// GlobalCMSCache so the real-time scanner can skip signature matches
// on known-clean CMS files.
func CheckWPCore(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
	wpConfigs, _ := filepath.Glob("/home/*/public_html/wp-config.php")
	if len(wpConfigs) == 0 {
		return nil
	}

	cache := GlobalCMSCache()

	var mu sync.Mutex
	var findings []alert.Finding
	var wg sync.WaitGroup

	// Bounded worker pool
	jobs := make(chan string, len(wpConfigs))
	for i := 0; i < wpChecksumWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for wpConfig := range jobs {
				if ctx.Err() != nil {
					return
				}
				wpPath := filepath.Dir(wpConfig)
				user := extractUser(wpPath)

				out, err := runCmdCombinedContext(ctx, "wp", "core", "verify-checksums",
					"--path="+wpPath, "--allow-root")
				if ctx.Err() != nil {
					return
				}

				if err == nil {
					// Verification passed - cache all core files
					cacheWPCoreFiles(cache, wpPath)
					continue
				}

				if out == nil {
					continue
				}

				outStr := string(out)
				for _, line := range strings.Split(outStr, "\n") {
					if strings.Contains(line, "should not exist") && !strings.Contains(line, "error_log") {
						mu.Lock()
						findings = append(findings, alert.Finding{
							Severity: alert.High,
							Check:    "wp_core_integrity",
							Message:  fmt.Sprintf("WordPress core integrity failure for %s", user),
							Details:  fmt.Sprintf("Path: %s\n%s", wpPath, line),
						})
						mu.Unlock()
					}
				}
			}
		}()
	}

	for _, wpConfig := range wpConfigs {
		if ctx.Err() != nil {
			break
		}
		jobs <- wpConfig
	}
	close(jobs)
	wg.Wait()

	fmt.Fprintf(os.Stderr, "CMS hash cache: %d verified core files cached\n", cache.Size())

	return findings
}

// cacheWPCoreFiles hashes all PHP files in wp-includes/ and wp-admin/
// for a verified-clean WordPress installation and adds them to the cache.
func cacheWPCoreFiles(cache *CMSHashCache, wpPath string) {
	coreDirs := []string{
		filepath.Join(wpPath, "wp-includes"),
		filepath.Join(wpPath, "wp-admin"),
	}
	// Also cache root-level WP core files
	rootFiles := []string{
		"wp-config.php", "wp-cron.php", "wp-login.php", "wp-settings.php",
		"wp-load.php", "wp-blog-header.php", "wp-links-opml.php",
		"wp-mail.php", "wp-signup.php", "wp-activate.php",
		"wp-comments-post.php", "wp-trackback.php", "xmlrpc.php",
		"index.php",
	}
	for _, name := range rootFiles {
		path := filepath.Join(wpPath, name)
		if hash := HashFile(path); hash != "" {
			cache.Add(hash)
		}
	}

	for _, dir := range coreDirs {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			name := strings.ToLower(info.Name())
			if strings.HasSuffix(name, ".php") || strings.HasSuffix(name, ".js") {
				if hash := HashFile(path); hash != "" {
					cache.Add(hash)
				}
			}
			return nil
		})
	}
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
