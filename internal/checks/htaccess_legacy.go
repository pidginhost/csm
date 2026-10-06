package checks

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

// Rewrite flags end at a comma or closing bracket. Those delimiters belong
// to Apache, not the PHP target; SetEnv values can contain either character.
var reRewritePreludeTarget = regexp.MustCompile(`(?i)auto_(?:prepend|append)_file(?:[\t ]*=[\t ]*|[\t ]+)("[^"\r\n]*"|'[^'\r\n]*'|[^\s,\]]+)`)

var htaccessSuspiciousPatterns = []string{
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

var htaccessSafePatterns = []string{
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

// auditHtaccessLegacyContent keeps generic findings and their removal spans together.
// Manual fixes, automatic cleaning and verification must judge the same bytes.
func auditHtaccessLegacyContent(path string, content []byte, suspicious, safe []string) ([]alert.Finding, []htaccessMatch) {
	var findings []alert.Finding
	var matches []htaccessMatch
	// Build full file content for context checks
	fullContentLower := strings.ToLower(string(content))

	// If file contains handler directives paired with -ExecCGI, the whole
	// block is a security measure (e.g., Wordfence execution protection)
	hasExecCGIBlock := strings.Contains(fullContentLower, "-execcgi")
	var phpHandlerContexts []phpHandlerOverlay

	nextLine := 0
	logicalLines := htaccessLogicalByteLines(content)
	for lineIndex, logical := range logicalLines {
		lineNum := nextLine
		end := logical.span.End
		if end < len(content) {
			end++
		}
		nextLine += strings.Count(string(content[logical.span.Start:end]), "\n")
		trimmed := strings.TrimSpace(logical.text)
		lineLower := strings.ToLower(trimmed)

		// Skip comments entirely - commented-out directives are not active
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if ctx, ok := openPHPHandlerContext(trimmed); ok {
			phpHandlerContexts = append(phpHandlerContexts, ctx)
			continue
		}
		if closesPHPHandlerContext(trimmed) {
			if len(phpHandlerContexts) > 0 {
				phpHandlerContexts = phpHandlerContexts[:len(phpHandlerContexts)-1]
			}
			continue
		}

		// A PHP execution handler mapped onto a non-PHP extension is the
		// handler-remap webshell technique: an uploaded .jpg then runs as
		// PHP. The safe-pattern and AddType skips below would otherwise
		// suppress it because the handler name itself is a normal PHP
		// handler, so this override fires first and unconditionally.
		remapsNonPHP := phpHandlerRemapsNonPHP(lineLower)
		if !remapsNonPHP && len(phpHandlerContexts) > 0 {
			remapsNonPHP = phpHandlerRemapsNonPHPInContext(lineLower, phpHandlerContexts)
		}
		if remapsNonPHP {
			matches = append(matches, htaccessMatch{Range: logical.span})
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "htaccess_injection",
				Message:  "PHP handler mapped to non-PHP extension (handler remap)",
				Details:  fmt.Sprintf("File: %s (line %d)\nContent: %s", path, lineNum+1, trimmed),
				FilePath: path,
			})
			continue
		}
		// The prelude is judged wherever the line carries one: PHP-FPM also
		// takes it from a PHP_VALUE environment variable, which SetEnv or a
		// RewriteRule E= flag can set.
		fields := apacheDirectiveFields(trimmed)
		preludeText := trimmed
		preludePattern := reAutoPrependTarget
		if len(fields) > 0 {
			if strings.EqualFold(fields[0], "SetEnv") || strings.EqualFold(fields[0], "RewriteRule") {
				// PHP parses the value after Apache removes its outer quotes
				// and escapes, including escaped quotes around a PHP path.
				if decoded, ok := parseApacheDirectiveFields(trimmed); ok {
					preludeText = strings.Join(decoded, " ")
				}
			}
			if strings.EqualFold(fields[0], "RewriteRule") {
				preludePattern = reRewritePreludeTarget
			}
		}
		preludes := preludePattern.FindAllStringSubmatchIndex(preludeText, -1)
		var suspiciousPrelude, pluginPrelude bool
		for _, m := range preludes {
			target := preludeText[m[2]:m[3]]
			if !autoPrependTargetSuspicious(target, path) {
				continue
			}
			suspiciousPrelude = true
			// Really Simple Security writes its prelude only as a php_value
			// prepend, so only that form is kept out of cleaning.
			prefix := strings.ToLower(strings.TrimSpace(preludeText[:m[0]]))
			pluginPrelude = (prefix == "" || prefix == "php_value" || prefix == "php_admin_value") &&
				strings.HasPrefix(strings.ToLower(preludeText[m[0]:]), "auto_prepend_file") &&
				preludeBase(strings.Trim(target, `"'`)) == rssslPreludeName
			// The retained php_value form has one executable target. Later
			// text must not turn that plugin directive into a removable hit.
			break
		}
		if len(preludes) > 0 && !suspiciousPrelude {
			continue
		}
		// Other tokens inside a rewrite condition or rule are regex patterns
		// in an attack-query blocklist, not code.
		if len(preludes) == 0 && len(fields) > 0 &&
			(strings.EqualFold(fields[0], "RewriteCond") || strings.EqualFold(fields[0], "RewriteRule")) {
			continue
		}

		for _, pattern := range suspicious {
			patternLower := strings.ToLower(pattern)
			if !strings.Contains(lineLower, patternLower) {
				continue
			}

			if strings.Contains(patternLower, "auto_") && len(preludes) == 0 {
				continue
			}

			// A prelude directive is judged by its target file alone. The
			// line-wide safe list below would let a target such as
			// ".../uploads/fonts/x.ttf" or ".../litespeed/x.php" exempt itself
			// with a word the attacker chose.
			if len(preludes) == 0 && (patternLower == "addhandler" || patternLower == "sethandler" || patternLower == "addtype") {
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
			}

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

			span := logical.span
			if len(fields) > 0 && strings.EqualFold(fields[0], "RewriteRule") {
				// Orphaned conditions would apply to the next surviving rule,
				// changing unrelated site routing after the malicious rule goes.
				for previous := lineIndex - 1; previous >= 0; previous-- {
					line := strings.TrimSpace(logicalLines[previous].text)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					if htaccessDirectiveName(line) != "rewritecond" {
						break
					}
					span.Start = logicalLines[previous].span.Start
				}
			}
			matches = append(matches, htaccessMatch{Range: span, Retain: pluginPrelude})
			findings = append(findings, alert.Finding{
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
		nextLine := 0
		for _, logical := range htaccessLogicalByteLines(content) {
			lineNum := nextLine
			end := logical.span.End
			if end < len(content) {
				end++
			}
			nextLine += strings.Count(string(content[logical.span.Start:end]), "\n")
			line := logical.text
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			lineLower := strings.ToLower(line)
			fields := apacheDirectiveFields(line)
			if len(fields) == 0 || !strings.EqualFold(fields[0], "AddHandler") {
				continue
			}
			// Flag if it maps unusual extensions like .haxor, .cgix, etc.
			dangerousExts := []string{".haxor", ".cgix", ".suspected", ".bak.php"}
			for _, ext := range dangerousExts {
				if strings.Contains(lineLower, ext) {
					matches = append(matches, htaccessMatch{Range: logical.span})
					findings = append(findings, alert.Finding{
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
	return findings, matches
}
