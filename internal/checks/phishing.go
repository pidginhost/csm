package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

const phishingReadSize = 16384 // Read first 16KB - phishing pages are self-contained

// ---------------------------------------------------------------------------
// Brand impersonation patterns
// ---------------------------------------------------------------------------

var phishingBrands = []struct {
	name          string
	titlePatterns []string
	bodyPatterns  []string
}{
	{
		name:          "Microsoft/SharePoint",
		titlePatterns: []string{"sharepoint", "onedrive", "microsoft 365", "outlook web", "office 365", "ms online"},
		bodyPatterns:  []string{"sharepoint", "onedrive", "secured by microsoft", "microsoft corporation"},
	},
	{
		name:          "Google",
		titlePatterns: []string{"google drive", "google docs", "google sign", "gmail", "google workspace"},
		bodyPatterns:  []string{"google drive", "google docs", "accounts.google", "secured by google"},
	},
	{
		name:          "Dropbox",
		titlePatterns: []string{"dropbox", "shared file", "shared folder"},
		bodyPatterns:  []string{"dropbox", "dropbox.com", "secured by dropbox"},
	},
	{
		name:          "DocuSign",
		titlePatterns: []string{"docusign", "document signing", "e-signature"},
		bodyPatterns:  []string{"docusign", "please review and sign", "e-signature"},
	},
	{
		name:          "Adobe",
		titlePatterns: []string{"adobe sign", "adobe document", "adobe acrobat"},
		bodyPatterns:  []string{"adobe sign", "adobe document cloud", "secured by adobe"},
	},
	{
		name:          "WeTransfer",
		titlePatterns: []string{"wetransfer", "file transfer"},
		bodyPatterns:  []string{"wetransfer", "download your files"},
	},
	{
		name:          "Apple/iCloud",
		titlePatterns: []string{"icloud", "apple id", "find my"},
		bodyPatterns:  []string{"icloud.com", "apple id", "secured by apple"},
	},
	{
		name:          "PayPal",
		titlePatterns: []string{"paypal", "pay pal"},
		bodyPatterns:  []string{"paypal.com", "secured by paypal"},
	},
	{
		name:          "Webmail/Roundcube",
		titlePatterns: []string{"roundcube", "horde", "webmail login", "webmail ::", "squirrelmail", "zimbra"},
		bodyPatterns:  []string{"roundcube webmail", "horde login", "zimbra web client", "webmail login"},
		// Note: bare "squirrelmail"/"roundcube" removed from body - sites legitimately
		// link to their server's webmail (e.g. href="squirrelmail/index.php").
	},
	{
		name:          "cPanel/WHM",
		titlePatterns: []string{"cpanel", "whm login", "webhost manager"},
		bodyPatterns:  []string{"cpanel login", "whm login", "webhost manager"},
	},
	{
		name:          "Banking/Financial",
		titlePatterns: []string{"online banking", "bank login", "secure banking", "account login"},
		bodyPatterns:  []string{"online banking", "bank account", "transaction verification"},
	},
	{
		name:          "Generic Login",
		titlePatterns: []string{"secure access", "verify your", "confirm your identity", "account verification", "email verification", "sign in"},
		bodyPatterns:  []string{"verify your identity", "confirm your account", "unusual activity"},
	},
}

// ---------------------------------------------------------------------------
// Content-based indicators
// ---------------------------------------------------------------------------

// Credential harvesting patterns in page body.
var harvestIndicators = []string{
	"window.location.href",
	"window.location.replace",
	"window.location =",
	"document.location.href",
	"form.submit()",
	".workers.dev",
	"confirm access",
	"verify your email",
	"confirm your email",
	"verify identity",
	"continue to document",
	"access confirmed, redirecting",
	"secured by microsoft",
	"secured by google",
	"secured by apple",
	"256-bit encrypted",
	"256‑bit encrypted",
	// fetch/XHR exfiltration - silent credential POST without redirect
	"fetch(",
	"xmlhttprequest",
	"$.ajax(",
	"$.post(",
	"navigator.sendbeacon(",
}

// Redirect/exfiltration URL patterns.
var exfilPatterns = []string{
	".workers.dev",
	"//t.co/",
	"/redir?",
	"/redirect?",
	"effi.redir",
	"link?url=",
	"goto_url=",
	"//bit.ly/",
	"//tinyurl.com/",
	"//rb.gy/",
	"//is.gd/",
	"/servlet/effi.redir",
}

// Fake trust badge patterns - security claims in pages not on the brand's domain.
var trustBadgePatterns = []string{
	"secured by microsoft",
	"secured by google",
	"secured by apple",
	"secured by dropbox",
	"secured by adobe",
	"verified by microsoft",
	"protected by microsoft",
	"256-bit encrypted",
	"256‑bit encrypted",
	"ssl secured",
	"bank-level encryption",
	"enterprise security",
}

// Urgency language used to pressure victims.
var urgencyPatterns = []string{
	"expires in",
	"temporary hold",
	"limited time",
	"unusual activity detected",
	"suspicious activity",
	"your account will be",
	"verify within",
	"action required",
	"immediate action",
	"account suspended",
	"access will be revoked",
}

// Embedded asset indicators - phishing kits embed logos to avoid external loading.
var embeddedAssetPatterns = []string{
	"data:image/png;base64,",
	"data:image/svg+xml;base64,",
	"data:image/jpeg;base64,",
}

// ---------------------------------------------------------------------------
// Main check entry point
// ---------------------------------------------------------------------------

// CheckPhishing scans HTML files in user document roots for phishing pages.
// Uses three detection layers:
//  1. Content analysis - brand impersonation + credential harvesting patterns
//  2. Structural analysis - self-contained HTML with embedded assets
//  3. Directory anomaly - lone HTML files in otherwise empty directories
func CheckPhishing(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	homeDirs, err := GetScanHomeDirs()
	if err != nil {
		return nil
	}

	for _, homeEntry := range homeDirs {
		if ctx.Err() != nil {
			return findings
		}
		if !homeEntry.IsDir() {
			continue
		}
		user := homeEntry.Name()
		if strings.HasPrefix(user, ".") || user == "virtfs" {
			continue
		}

		homeDir := filepath.Join("/home", user)
		docRoots := []string{filepath.Join(homeDir, "public_html")}
		subDirs, _ := osFS.ReadDir(homeDir)
		for _, sd := range subDirs {
			if sd.IsDir() && sd.Name() != "public_html" && sd.Name() != "mail" &&
				!strings.HasPrefix(sd.Name(), ".") && sd.Name() != "etc" &&
				sd.Name() != "logs" && sd.Name() != "ssl" && sd.Name() != "tmp" {
				docRoots = append(docRoots, filepath.Join(homeDir, sd.Name()))
			}
		}

		for _, docRoot := range docRoots {
			scanForPhishing(ctx, docRoot, 3, user, cfg, &findings)
			if ctx.Err() != nil {
				return findings
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Directory scanner
// ---------------------------------------------------------------------------

func scanForPhishing(ctx context.Context, dir string, maxDepth int, user string, cfg *config.Config, findings *[]alert.Finding) {
	if ctx.Err() != nil {
		return
	}
	if maxDepth <= 0 {
		return
	}
	entries, err := osFS.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		name := entry.Name()
		fullPath := filepath.Join(dir, name)

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
			if isKnownSafeDir(name) {
				continue
			}

			// --- Directory anomaly detection ---
			dirResult := analyzeDirectoryStructure(fullPath, user)
			if dirResult != nil {
				*findings = append(*findings, *dirResult)
			}

			scanForPhishing(ctx, fullPath, maxDepth-1, user, cfg, findings)
			continue
		}

		nameLower := strings.ToLower(name)
		info, err := entry.Info()
		if err != nil {
			continue
		}
		size := info.Size()

		// --- HTML/HTM phishing pages ---
		if strings.HasSuffix(nameLower, ".html") || strings.HasSuffix(nameLower, ".htm") {
			// Standard phishing page check (3KB-100KB)
			if size >= 3000 && size <= 100000 {
				result := analyzeHTMLForPhishing(fullPath)
				if result != nil {
					*findings = append(*findings, alert.Finding{
						Severity: alert.Critical,
						Check:    "phishing_page",
						Message:  fmt.Sprintf("Phishing page detected (%s impersonation): %s", result.brand, fullPath),
						Details: fmt.Sprintf("Account: %s\nBrand: %s\nScore: %d/10\nIndicators:\n- %s\nSize: %d bytes",
							user, result.brand, result.score, strings.Join(result.indicators, "\n- "), size),
						FilePath: fullPath,
					})
				}
			}

			// --- iframe phishing (tiny HTML files that embed external phishing) ---
			if size > 0 && size < 3000 {
				if result := checkIframePhishing(fullPath); result != "" {
					*findings = append(*findings, alert.Finding{
						Severity: alert.Critical,
						Check:    "phishing_iframe",
						Message:  fmt.Sprintf("Iframe phishing page detected: %s", fullPath),
						Details:  fmt.Sprintf("Account: %s\n%s", user, result),
						FilePath: fullPath,
					})
				}
			}
			continue
		}

		// --- PHP phishing pages and open redirectors ---
		if strings.HasSuffix(nameLower, ".php") {
			// Skip known CMS files
			if isKnownCMSFile(nameLower) {
				continue
			}
			// PHP phishing (3KB-100KB) - same brand/content analysis as HTML
			if size >= 3000 && size <= 100000 {
				result := analyzePHPForPhishing(fullPath)
				if result != nil {
					*findings = append(*findings, alert.Finding{
						Severity: alert.Critical,
						Check:    "phishing_php",
						Message:  fmt.Sprintf("PHP phishing page detected (%s): %s", result.brand, fullPath),
						Details: fmt.Sprintf("Account: %s\nBrand: %s\nScore: %d/10\nIndicators:\n- %s\nSize: %d bytes",
							user, result.brand, result.score, strings.Join(result.indicators, "\n- "), size),
						FilePath: fullPath,
					})
				}
			}
			// PHP open redirector (tiny PHP files under 1KB)
			if size > 0 && size < 1024 {
				if result := checkPHPRedirector(fullPath); result != "" {
					*findings = append(*findings, alert.Finding{
						Severity: alert.High,
						Check:    "phishing_redirector",
						Message:  fmt.Sprintf("PHP open redirector detected: %s", fullPath),
						Details:  fmt.Sprintf("Account: %s\n%s", user, result),
						FilePath: fullPath,
					})
				}
			}
			continue
		}

		// --- Credential log files ---
		if isCredentialLogName(nameLower) && size > 0 && size < 10*1024*1024 {
			if result := checkCredentialLog(fullPath); result != "" {
				*findings = append(*findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "phishing_credential_log",
					Message:  fmt.Sprintf("Harvested credential log file detected: %s", fullPath),
					Details:  fmt.Sprintf("Account: %s\n%s", user, result),
					FilePath: fullPath,
				})
			}
			continue
		}

		// --- Phishing kit ZIP archives ---
		if strings.HasSuffix(nameLower, ".zip") && size > 1000 && size < 50*1024*1024 {
			if isPhishingKitZip(nameLower) {
				*findings = append(*findings, alert.Finding{
					Severity: alert.High,
					Check:    "phishing_kit_archive",
					Message:  fmt.Sprintf("Suspected phishing kit archive: %s", fullPath),
					Details: fmt.Sprintf("Account: %s\nFilename: %s\nSize: %d bytes",
						user, name, size),
					FilePath: fullPath,
				})
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Layer 1: Content analysis
// ---------------------------------------------------------------------------

type phishingResult struct {
	brand      string
	score      int
	indicators []string
}

func analyzeHTMLForPhishing(path string) *phishingResult {
	f, err := osFS.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, phishingReadSize)
	n, _ := f.Read(buf)
	if n == 0 {
		return nil
	}
	content := string(buf[:n])
	contentLower := strings.ToLower(content)

	// Must contain a form or input
	hasForm := strings.Contains(contentLower, "<form") ||
		strings.Contains(contentLower, "<input")
	if !hasForm {
		return nil
	}

	// Must contain email/password input
	hasCredentialInput := strings.Contains(contentLower, "type=\"email\"") ||
		strings.Contains(contentLower, "type=\"password\"") ||
		strings.Contains(contentLower, "type='email'") ||
		strings.Contains(contentLower, "type='password'") ||
		strings.Contains(contentLower, "name=\"email\"") ||
		strings.Contains(contentLower, "name=\"pass\"") ||
		strings.Contains(contentLower, "name=\"password\"") ||
		strings.Contains(contentLower, "name=\"login\"") ||
		strings.Contains(contentLower, "placeholder=\"email") ||
		strings.Contains(contentLower, "placeholder=\"you@") ||
		strings.Contains(contentLower, "placeholder=\"your email") ||
		strings.Contains(contentLower, "work or school email") ||
		strings.Contains(contentLower, "corporate email")
	if !hasCredentialInput {
		return nil
	}

	var indicators []string
	score := 0

	// --- Brand impersonation ---
	brandMatch := ""
	titleContent := extractTitle(contentLower)

	for _, brand := range phishingBrands {
		titleHit := false
		bodyHit := false

		for _, tp := range brand.titlePatterns {
			if strings.Contains(titleContent, tp) {
				titleHit = true
				indicators = append(indicators, fmt.Sprintf("title impersonates '%s'", tp))
				score += 3
				break
			}
		}

		for _, bp := range brand.bodyPatterns {
			if strings.Contains(contentLower, bp) {
				bodyHit = true
				if !titleHit {
					indicators = append(indicators, fmt.Sprintf("body impersonates '%s'", bp))
					score += 2
				}
				break
			}
		}

		if titleHit || bodyHit {
			brandMatch = brand.name
			break
		}
	}

	// --- Credential harvesting / redirect indicators ---
	for _, pattern := range harvestIndicators {
		if strings.Contains(contentLower, pattern) {
			score++
			indicators = append(indicators, fmt.Sprintf("harvest: '%s'", pattern))
		}
	}

	// --- Exfiltration URL patterns ---
	for _, pattern := range exfilPatterns {
		if strings.Contains(contentLower, pattern) {
			score += 2
			indicators = append(indicators, fmt.Sprintf("exfiltration: '%s'", pattern))
		}
	}

	// --- Fake trust badges ---
	for _, pattern := range trustBadgePatterns {
		if strings.Contains(contentLower, pattern) {
			score++
			indicators = append(indicators, fmt.Sprintf("fake trust badge: '%s'", pattern))
		}
	}

	// --- Urgency language ---
	urgencyCount := 0
	for _, pattern := range urgencyPatterns {
		if strings.Contains(contentLower, pattern) {
			urgencyCount++
		}
	}
	if urgencyCount > 0 {
		score++
		indicators = append(indicators, fmt.Sprintf("urgency language (%d patterns)", urgencyCount))
	}

	// --- Embedded Base64 assets (logos embedded to avoid external loading) ---
	embeddedCount := 0
	for _, pattern := range embeddedAssetPatterns {
		embeddedCount += countOccurrences(contentLower, pattern)
	}
	if embeddedCount > 0 {
		score++
		indicators = append(indicators, fmt.Sprintf("embedded base64 assets (%d)", embeddedCount))
	}

	// --- Form action pointing to external domain ---
	if hasExternalFormAction(content) {
		score += 2
		indicators = append(indicators, "form action points to external domain")
	}

	// --- Self-contained page (all CSS inline, no external stylesheets except CDN) ---
	if isSelfContainedHTML(contentLower) {
		score++
		indicators = append(indicators, "self-contained HTML (all styles inline)")
	}

	// --- Person name as filename ---
	baseName := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(path), ".html"), ".htm")
	if looksLikePersonName(baseName) {
		score += 2
		indicators = append(indicators, fmt.Sprintf("filename looks like person name: '%s'", baseName))
	}

	// --- Decision ---
	// With brand match: need score >= 4 (brand gives 2-3 + at least 1 other signal)
	// Without brand match: need score >= 6 (multiple strong signals)
	if brandMatch != "" && score >= 4 {
		return &phishingResult{brand: brandMatch, score: score, indicators: indicators}
	}
	if brandMatch == "" && score >= 6 {
		return &phishingResult{brand: "Unknown", score: score, indicators: indicators}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Layer 2: Structural analysis helpers
// ---------------------------------------------------------------------------

// extractTitle pulls the <title> content from HTML.
func extractTitle(contentLower string) string {
	start := strings.Index(contentLower, "<title>")
	end := strings.Index(contentLower, "</title>")
	if start >= 0 && end > start+7 {
		return contentLower[start+7 : end]
	}
	return ""
}

// hasExternalFormAction checks if a <form> action points to a different domain.
func hasExternalFormAction(content string) bool {
	lower := strings.ToLower(content)
	// Find form action="..." or action='...'
	idx := strings.Index(lower, "action=")
	if idx < 0 {
		return false
	}
	rest := content[idx+7:]
	if len(rest) == 0 {
		return false
	}

	// Extract the URL value
	quote := rest[0]
	if quote != '"' && quote != '\'' {
		return false
	}
	endIdx := strings.IndexByte(rest[1:], quote)
	if endIdx < 0 {
		return false
	}
	url := strings.ToLower(rest[1 : endIdx+1])

	// External if it starts with http:// or https:// (not relative)
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}

// isSelfContainedHTML checks if a page has all its CSS inline (embedded <style> tags)
// with no or minimal external stylesheet references - typical of phishing kits.
func isSelfContainedHTML(contentLower string) bool {
	hasInlineStyle := strings.Contains(contentLower, "<style")
	externalCSS := countOccurrences(contentLower, "rel=\"stylesheet\"") +
		countOccurrences(contentLower, "rel='stylesheet'")
	// Allow 1 external CSS (e.g., Font Awesome CDN) - phishing kits often use one
	return hasInlineStyle && externalCSS <= 1
}

// looksLikePersonName checks if a filename looks like a person name (CamelCase
// with 2+ capitalized words, e.g., "PalmerHamilton", "MarilynEsguerra").
func looksLikePersonName(name string) bool {
	if len(name) < 6 {
		return false
	}

	// Count uppercase transitions (start of words in CamelCase)
	upperCount := 0
	for i, c := range name {
		if unicode.IsUpper(c) {
			if i == 0 || unicode.IsLower(rune(name[i-1])) {
				upperCount++
			}
		}
	}

	// 2+ capitalized words, all letters, no common web words
	if upperCount < 2 {
		return false
	}

	allLetters := true
	for _, c := range name {
		if !unicode.IsLetter(c) {
			allLetters = false
			break
		}
	}
	if !allLetters {
		return false
	}

	// Exclude common web filenames
	nameLower := strings.ToLower(name)
	webNames := []string{"index", "default", "portal", "login", "home", "main",
		"readme", "changelog", "license", "manifest", "service"}
	for _, w := range webNames {
		if nameLower == w {
			return false
		}
	}

	return true
}

// ---------------------------------------------------------------------------
// Layer 3: Directory anomaly detection
// ---------------------------------------------------------------------------

// analyzeDirectoryStructure checks if a directory looks like a phishing drop:
// - Contains only 1-3 HTML files and nothing else significant
// - Directory name looks like a business/organization name
// - No CMS markers (wp-config, index.php, etc.)
func analyzeDirectoryStructure(dir string, user string) *alert.Finding {
	entries, err := osFS.ReadDir(dir)
	if err != nil {
		return nil
	}

	var htmlFiles []string
	otherFiles := 0
	totalFiles := 0

	for _, entry := range entries {
		if entry.IsDir() {
			return nil // Has subdirectories - likely not a simple phishing drop
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue // Skip dotfiles (.htaccess etc.)
		}
		totalFiles++
		nameLower := strings.ToLower(name)
		if strings.HasSuffix(nameLower, ".html") || strings.HasSuffix(nameLower, ".htm") {
			htmlFiles = append(htmlFiles, name)
		} else {
			otherFiles++
		}
	}

	// Must have exactly 1-3 HTML files and at most 1 other file
	if len(htmlFiles) == 0 || len(htmlFiles) > 3 || otherFiles > 1 {
		return nil
	}

	// Directory name should look like a business/organization (CamelCase or multi-word)
	dirName := filepath.Base(dir)
	if !looksLikeBusinessName(dirName) {
		return nil
	}

	// Verify at least one HTML file has credential inputs (quick check)
	hasPhishingContent := false
	for _, htmlFile := range htmlFiles {
		fullPath := filepath.Join(dir, htmlFile)
		if quickPhishingCheck(fullPath) {
			hasPhishingContent = true
			break
		}
	}
	if !hasPhishingContent {
		return nil
	}

	// Build indicators
	indicators := []string{
		fmt.Sprintf("directory '%s' contains only %d HTML file(s)", dirName, len(htmlFiles)),
		fmt.Sprintf("directory name resembles business/organization: '%s'", dirName),
	}
	for _, h := range htmlFiles {
		baseName := strings.TrimSuffix(strings.TrimSuffix(h, ".html"), ".htm")
		if looksLikePersonName(baseName) {
			indicators = append(indicators, fmt.Sprintf("HTML filename looks like person name: '%s'", baseName))
		}
	}

	return &alert.Finding{
		Severity: alert.High,
		Check:    "phishing_directory",
		Message:  fmt.Sprintf("Suspected phishing directory (lone HTML in business-named folder): %s", dir),
		Details: fmt.Sprintf("Account: %s\nDirectory: %s\nHTML files: %s\nIndicators:\n- %s",
			user, dirName, strings.Join(htmlFiles, ", "), strings.Join(indicators, "\n- ")),
		FilePath: dir,
	}
}

// looksLikeBusinessName checks if a directory name looks like a business or
// organization name rather than a standard web directory.
func looksLikeBusinessName(name string) bool {
	if len(name) < 5 {
		return false
	}

	nameLower := strings.ToLower(name)

	// Skip names that start with tech/dev terms - these are tutorial
	// or test directories, not business names (e.g. "php-email-form",
	// "PHP-Login", "JavaScript Login")
	techPrefixes := []string{
		"php", "javascript", "js-", "css", "html", "python",
		"java", "node", "react", "vue", "angular", "jquery",
		"bootstrap", "wordpress", "wp-", "laravel",
	}
	for _, prefix := range techPrefixes {
		if strings.HasPrefix(nameLower, prefix) {
			return false
		}
	}

	// Skip standard web directories
	standardDirs := []string{
		"images", "img", "css", "js", "fonts", "assets", "static",
		"media", "uploads", "downloads", "files", "docs", "data",
		"api", "admin", "config", "templates", "scripts", "lib",
		"src", "dist", "build", "public", "private", "backup",
		"old", "new", "test", "dev", "staging", "demo",
	}
	for _, sd := range standardDirs {
		if nameLower == sd {
			return false
		}
	}

	// CamelCase detection (e.g., WashingtonGolf, XRFScientificAmericasInc)
	upperTransitions := 0
	for i, c := range name {
		if unicode.IsUpper(c) && i > 0 && unicode.IsLower(rune(name[i-1])) {
			upperTransitions++
		}
	}
	if upperTransitions >= 1 && unicode.IsUpper(rune(name[0])) {
		return true
	}

	// Multi-word with separators (e.g., federated-lighting, northwest_crawlspace)
	if strings.ContainsAny(name, "-_") {
		parts := strings.FieldsFunc(name, func(r rune) bool { return r == '-' || r == '_' })
		if len(parts) >= 2 {
			return true
		}
	}

	// Long lowercase name that doesn't match standard dirs (e.g., "healthcornerpediattrics")
	allLower := true
	for _, c := range name {
		if !unicode.IsLetter(c) {
			allLower = false
			break
		}
	}
	if allLower && len(name) >= 12 {
		return true
	}

	return false
}

// quickPhishingCheck does a fast read of an HTML file to check for credential
// input fields without full analysis - used for directory structure checks.
func quickPhishingCheck(path string) bool {
	f, err := osFS.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, 4096) // Only need first 4KB for quick check
	n, _ := f.Read(buf)
	if n == 0 {
		return false
	}
	content := strings.ToLower(string(buf[:n]))

	return (strings.Contains(content, "<form") || strings.Contains(content, "<input")) &&
		(strings.Contains(content, "email") || strings.Contains(content, "password"))
}

// ---------------------------------------------------------------------------
// Layer 4: PHP phishing pages
// ---------------------------------------------------------------------------

// analyzePHPForPhishing reads a PHP file and checks for embedded HTML with
// brand impersonation. PHP phishing kits often have PHP code at the top
// (credential handling, emailing) and HTML output below.
func analyzePHPForPhishing(path string) *phishingResult {
	f, err := osFS.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, phishingReadSize)
	n, _ := f.Read(buf)
	if n == 0 {
		return nil
	}
	content := string(buf[:n])
	contentLower := strings.ToLower(content)

	// PHP phishing indicators: credential handling code.
	// Only truly specific patterns belong here - generic functions like
	// mail() and fwrite() are handled separately with context checks below.
	phpPhishingPatterns := []string{
		"$_post['email']",
		"$_post['password']",
		"$_post['pass']",
		"$_post[\"email\"]",
		"$_post[\"password\"]",
		"$_post[\"pass\"]",
		"$_request['email']",
		"$_request['password']",
	}

	var indicators []string
	score := 0

	// Check for PHP credential handling
	phpCredHandling := false
	for _, pattern := range phpPhishingPatterns {
		if strings.Contains(contentLower, pattern) {
			phpCredHandling = true
			indicators = append(indicators, fmt.Sprintf("PHP credential handling: '%s'", pattern))
			score += 2
			break
		}
	}

	// Must have either PHP credential handling OR HTML form output
	hasForm := strings.Contains(contentLower, "<form") || strings.Contains(contentLower, "<input")
	hasCredentialInput := strings.Contains(contentLower, "type=\"email\"") ||
		strings.Contains(contentLower, "type=\"password\"") ||
		strings.Contains(contentLower, "type='email'") ||
		strings.Contains(contentLower, "type='password'") ||
		strings.Contains(contentLower, "name=\"email\"") ||
		strings.Contains(contentLower, "name=\"password\"") ||
		strings.Contains(contentLower, "name=\"pass\"")

	if !phpCredHandling && (!hasForm || !hasCredentialInput) {
		return nil
	}

	// Check brand impersonation (same as HTML check)
	brandMatch := ""
	titleContent := extractTitle(contentLower)

	for _, brand := range phishingBrands {
		for _, tp := range brand.titlePatterns {
			if strings.Contains(titleContent, tp) {
				brandMatch = brand.name
				indicators = append(indicators, fmt.Sprintf("title impersonates '%s'", tp))
				score += 3
				break
			}
		}
		if brandMatch != "" {
			break
		}
		for _, bp := range brand.bodyPatterns {
			if strings.Contains(contentLower, bp) {
				brandMatch = brand.name
				indicators = append(indicators, fmt.Sprintf("body impersonates '%s'", bp))
				score += 2
				break
			}
		}
		if brandMatch != "" {
			break
		}
	}

	// Check harvest/exfil patterns
	for _, pattern := range harvestIndicators {
		if strings.Contains(contentLower, pattern) {
			score++
			indicators = append(indicators, fmt.Sprintf("harvest: '%s'", pattern))
		}
	}
	for _, pattern := range exfilPatterns {
		if strings.Contains(contentLower, pattern) {
			score += 2
			indicators = append(indicators, fmt.Sprintf("exfiltration: '%s'", pattern))
		}
	}

	// PHP-specific exfil: emailing or writing harvested credentials.
	// These only fire when the file also reads from $_POST/$_REQUEST,
	// because a phishing kit must capture form data before exfiltrating it.
	// Without this gate, any PHP file using fwrite()+config keywords triggers.
	hasPostData := strings.Contains(contentLower, "$_post") || strings.Contains(contentLower, "$_request")

	if hasPostData && strings.Contains(contentLower, "mail(") &&
		(strings.Contains(contentLower, "password") || strings.Contains(contentLower, "email")) {
		score += 2
		indicators = append(indicators, "PHP mail() with credential data")
	}

	if hasPostData &&
		(strings.Contains(contentLower, "fwrite(") || strings.Contains(contentLower, "file_put_contents(")) {
		if strings.Contains(contentLower, "password") || strings.Contains(contentLower, "email") ||
			strings.Contains(contentLower, "result") || strings.Contains(contentLower, "log") {
			score += 2
			indicators = append(indicators, "PHP writes credential data to file")
		}
	}

	// Require brand impersonation to flag as phishing.
	// PHP files with $_POST['email'] + mail() are normal (contact forms, CMS user
	// admin, gallery software). Without brand impersonation, these are almost
	// always legitimate applications.
	if brandMatch == "" {
		return nil
	}
	if score >= 4 {
		return &phishingResult{brand: brandMatch, score: score, indicators: indicators}
	}

	return nil
}

// isKnownCMSFile returns true for PHP files that are standard CMS files
// and should not be scanned for phishing (too many false positives).
func isKnownCMSFile(nameLower string) bool {
	cmsFiles := map[string]bool{
		"index.php": true, "wp-config.php": true, "wp-login.php": true,
		"wp-cron.php": true, "wp-settings.php": true, "wp-load.php": true,
		"wp-blog-header.php": true, "wp-links-opml.php": true,
		"xmlrpc.php": true, "wp-signup.php": true, "wp-activate.php": true,
		"wp-trackback.php": true, "wp-comments-post.php": true,
		"wp-mail.php": true, "configuration.php": true,
		"config.php": true, "settings.php": true,
	}
	return cmsFiles[nameLower]
}

// ---------------------------------------------------------------------------
// Layer 5: PHP open redirectors
// ---------------------------------------------------------------------------

// checkPHPRedirector reads a small PHP file and checks if it's an open
// redirector - a file that redirects the visitor to a URL from a parameter.
func checkPHPRedirector(path string) string {
	f, err := osFS.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, 1024)
	n, _ := f.Read(buf)
	if n == 0 {
		return ""
	}
	content := strings.ToLower(string(buf[:n]))

	hasHeader := strings.Contains(content, "header(") &&
		(strings.Contains(content, "location:") || strings.Contains(content, "location :"))

	if !hasHeader {
		return ""
	}

	// Pattern 1: user-controlled redirect target - the URL in header() must
	// come from user input. Just having $_GET anywhere + header() is too broad;
	// normal form handlers use $_POST for data then header() for redirect.
	// Only flag when the redirect URL itself is parameterized.
	userControlledRedirect := false
	redirectPatterns := []string{
		"$_get['url']", "$_get[\"url\"]",
		"$_get['redirect']", "$_get[\"redirect\"]",
		"$_get['r']", "$_get[\"r\"]",
		"$_get['return']", "$_get[\"return\"]",
		"$_get['next']", "$_get[\"next\"]",
		"$_get['goto']", "$_get[\"goto\"]",
		"$_get['link']", "$_get[\"link\"]",
		"$_request['url']", "$_request[\"url\"]",
		"$_request['redirect']", "$_request[\"redirect\"]",
		"header(\"location: \".$_get", "header(\"location: \".$_request",
		"header('location: '.$_get", "header('location: '.$_request",
		"header(\"location:\".$_get", "header('location:'.$_get",
	}
	for _, p := range redirectPatterns {
		if strings.Contains(content, p) {
			userControlledRedirect = true
			break
		}
	}
	if userControlledRedirect {
		return "PHP open redirector: header(Location) with user-supplied URL"
	}

	// Pattern 2: Hardcoded redirect to suspicious domain
	for _, pattern := range exfilPatterns {
		if strings.Contains(content, pattern) {
			return fmt.Sprintf("PHP redirect to suspicious destination matching '%s'", pattern)
		}
	}

	return ""
}

// ---------------------------------------------------------------------------
// Layer 6: Credential log files
// ---------------------------------------------------------------------------

// isCredentialLogName checks if a filename matches patterns used by phishing
// kits to store harvested credentials.
func isCredentialLogName(nameLower string) bool {
	// Exact names commonly used by phishing kits
	exactNames := map[string]bool{
		"results.txt": true, "result.txt": true, "log.txt": true,
		"logs.txt": true, "emails.txt": true, "data.txt": true,
		"passwords.txt": true, "creds.txt": true, "credentials.txt": true,
		"victims.txt": true, "output.txt": true, "harvested.txt": true,
		"results.log": true, "emails.log": true, "data.log": true,
		"results.csv": true, "emails.csv": true, "data.csv": true,
		"results.html": true,
	}
	if exactNames[nameLower] {
		return true
	}

	// Pattern: contains "result", "victim", "harvested", "credential" in name
	suspiciousWords := []string{"result", "victim", "harvest", "credential", "creds", "stolen"}
	for _, word := range suspiciousWords {
		if strings.Contains(nameLower, word) {
			return true
		}
	}

	return false
}

// checkCredentialLog reads a text file and checks if it contains harvested
// credentials (email:password pairs, one per line).
func checkCredentialLog(path string) string {
	f, err := osFS.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	// Read first 4KB
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	if n == 0 {
		return ""
	}
	content := string(buf[:n])

	lines := strings.Split(content, "\n")
	credentialLines := 0
	emailCount := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Pattern: email:password or email|password or email,password
		if strings.Contains(line, "@") {
			emailCount++
			// Check for delimiter after email
			for _, delim := range []string{":", "|", "\t", ","} {
				parts := strings.SplitN(line, delim, 3)
				if len(parts) >= 2 {
					part0 := strings.TrimSpace(parts[0])
					part1 := strings.TrimSpace(parts[1])
					if strings.Contains(part0, "@") && len(part1) > 0 && !strings.Contains(part1, " ") {
						credentialLines++
						break
					}
				}
			}
		}
	}

	// 3+ lines that look like email:password pairs = credential log
	if credentialLines >= 3 {
		return fmt.Sprintf("File contains %d credential-like lines (email:password format) out of %d email lines",
			credentialLines, emailCount)
	}

	// High density of emails alone (10+) in a non-.csv file is suspicious
	if emailCount >= 10 && !strings.HasSuffix(strings.ToLower(path), ".csv") {
		return fmt.Sprintf("File contains %d email addresses - possible harvested email list", emailCount)
	}

	return ""
}

// ---------------------------------------------------------------------------
// Layer 7: Iframe phishing
// ---------------------------------------------------------------------------

// checkIframePhishing checks small HTML files for iframe-based phishing -
// a minimal HTML page that just loads an external phishing page in a full-screen iframe.
func checkIframePhishing(path string) string {
	f, err := osFS.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, 3000)
	n, _ := f.Read(buf)
	if n == 0 {
		return ""
	}
	contentLower := strings.ToLower(string(buf[:n]))

	// Must contain an iframe
	if !strings.Contains(contentLower, "<iframe") {
		return ""
	}

	// Check if iframe src points to an external URL
	idx := strings.Index(contentLower, "<iframe")
	if idx < 0 {
		return ""
	}
	rest := contentLower[idx:]
	endTag := strings.Index(rest, ">")
	if endTag < 0 {
		return ""
	}
	iframeTag := rest[:endTag+1]

	// Extract src
	srcIdx := strings.Index(iframeTag, "src=")
	if srcIdx < 0 {
		return ""
	}
	srcRest := iframeTag[srcIdx+4:]
	if len(srcRest) == 0 {
		return ""
	}
	quote := srcRest[0]
	if quote != '"' && quote != '\'' {
		return ""
	}
	srcEnd := strings.IndexByte(srcRest[1:], quote)
	if srcEnd < 0 {
		return ""
	}
	src := srcRest[1 : srcEnd+1]

	// Must be external (http:// or https://)
	if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") {
		return ""
	}

	// Check if iframe is fullscreen (width/height 100% or style covers viewport)
	isFullscreen := strings.Contains(iframeTag, "100%") ||
		strings.Contains(contentLower, "width:100%") ||
		strings.Contains(contentLower, "width: 100%") ||
		strings.Contains(contentLower, "position:fixed") ||
		strings.Contains(contentLower, "position: fixed")

	if isFullscreen {
		return fmt.Sprintf("Full-screen iframe loading external URL: %s", src)
	}

	// Even non-fullscreen, check if URL matches known phishing/exfil patterns
	for _, pattern := range exfilPatterns {
		if strings.Contains(src, pattern) {
			return fmt.Sprintf("Iframe loading suspicious external URL matching '%s': %s", pattern, src)
		}
	}

	return ""
}

// ---------------------------------------------------------------------------
// Layer 8: Phishing kit ZIP archives
// ---------------------------------------------------------------------------

// isPhishingKitZip checks if a ZIP filename matches common phishing kit names.
// Requires 2+ keyword matches to reduce false positives (e.g. "CssCheckboxKit"
// matched "kit" alone, but legitimate UI kits, CSS kits, etc. are common).
func isPhishingKitZip(nameLower string) bool {
	// High-confidence single-match keywords (brand impersonation in filename)
	singleMatch := []string{
		"office365", "office 365", "sharepoint", "onedrive",
		"microsoft", "outlook", "gmail",
		"dropbox", "docusign", "wetransfer",
		"paypal", "icloud", "netflix",
		"facebook", "instagram", "linkedin",
		"roundcube", "cpanel",
		"phish", "scam",
	}
	for _, kw := range singleMatch {
		if strings.Contains(nameLower, kw) {
			return true
		}
	}

	// Lower-confidence keywords - require 2+ matches to flag.
	// Words like "login", "verify", "secure", "google", "apple", "bank"
	// appear in legitimate archives too.
	multiMatch := []string{
		"login", "verify", "secure", "bank",
		"google", "apple", "adobe", "webmail",
	}
	matches := 0
	for _, kw := range multiMatch {
		if strings.Contains(nameLower, kw) {
			matches++
		}
	}
	return matches >= 2
}

// ---------------------------------------------------------------------------
// Safe directory list
// ---------------------------------------------------------------------------

func isKnownSafeDir(name string) bool {
	safeDirs := map[string]bool{
		"wp-admin": true, "wp-includes": true, "wp-content": true,
		"node_modules": true, "vendor": true, ".git": true,
		"cgi-bin": true, ".well-known": true, "mail": true,
		"cache": true, "tmp": true, "logs": true,
	}
	return safeDirs[name]
}
