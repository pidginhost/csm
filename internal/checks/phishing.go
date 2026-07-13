package checks

import (
	"archive/zip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf16"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"golang.org/x/net/html"
)

const phishingReadSize = 16384 // Read first 16KB - phishing pages are self-contained

// phishingScanMaxDepth bounds how deep CheckPhishing recurses below each doc
// root. Real kits land in date-nested WordPress upload folders
// (wp-content/uploads/YYYY/MM/<kit>/), six directory levels below the root, so
// the budget must clear that. Heavy/transient dirs (node_modules, vendor, WP
// core, caches) are pruned by isKnownSafeDir before recursion, keeping the
// deeper walk affordable.
const phishingScanMaxDepth = 8

// ---------------------------------------------------------------------------
// Brand impersonation patterns
// ---------------------------------------------------------------------------

// phishingGenericBrandScoreFloor is the score a page matching only the
// "Generic Login" pseudo-brand must reach before it is flagged. The generic
// title patterns ("Sign In", "Secure Access") are ubiquitous on legitimate
// login pages and, unlike a real brand, are not themselves evidence of
// impersonation. A single equally-ubiquitous JS token (window.location,
// fetch) would otherwise clear the normal brand floor and mislabel a
// customer's own login page. Requiring this higher floor forces multiple
// independent signals (external exfil, trust badge, urgency, server-side
// credential capture) that a plain login page does not carry.
const phishingGenericBrandScoreFloor = 7

var phishingBrands = []struct {
	name          string
	titlePatterns []string
	bodyPatterns  []string
	generic       bool
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
		generic:       true,
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

	homeDirs, err := GetScanHomeDirs(ctx)
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
			scanForPhishing(ctx, docRoot, phishingScanMaxDepth, user, cfg, &findings)
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

		// Bypassed for explicit full-scan / audit requests.
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
		if isExecutablePHPName(nameLower) {
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
		if !strings.HasSuffix(nameLower, ".zip") && isCredentialLogName(nameLower) &&
			size > 0 && size < 10*1024*1024 {
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
			if isPhishingKitZipName(nameLower) && zipLooksLikeKit(fullPath) {
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
	hasCredentialInput := hasHTMLCredentialInput(contentLower)
	if !hasCredentialInput {
		return nil
	}

	var indicators []string
	score := 0

	// --- Brand impersonation ---
	brandMatch := ""
	matchedGeneric := false
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
			matchedGeneric = brand.generic
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
	// Real brand match: need score >= 4 (brand gives 2-3 + at least 1 other
	// signal). Generic pseudo-brand: need a higher floor since its title
	// patterns are ubiquitous on legitimate login pages. No brand: need
	// score >= 6 (multiple strong signals).
	if brandMatch != "" {
		floor := 4
		if matchedGeneric {
			floor = phishingGenericBrandScoreFloor
		}
		if score >= floor {
			return &phishingResult{brand: brandMatch, score: score, indicators: indicators}
		}
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
	for offset := 0; offset < len(contentLower); {
		idx := strings.Index(contentLower[offset:], "<title")
		if idx < 0 {
			return ""
		}
		start := offset + idx
		afterName := start + len("<title")
		if afterName < len(contentLower) && !isTagBoundary(contentLower[afterName]) {
			offset = afterName
			continue
		}
		openEnd := findTagEnd(contentLower, afterName)
		if openEnd < 0 {
			return ""
		}
		closeOffset := strings.Index(contentLower[openEnd+1:], "</title>")
		if closeOffset < 0 {
			return ""
		}
		return strings.TrimSpace(contentLower[openEnd+1 : openEnd+1+closeOffset])
	}
	return ""
}

// hasExternalFormAction checks if a <form> action points to a different domain.
func hasExternalFormAction(content string) bool {
	for _, url := range htmlAttrValues(strings.ToLower(content), "form", "action", false) {
		// External if it starts with http:// or https:// (not relative)
		if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
			return true
		}
	}
	return false
}

func hasHTMLCredentialInput(contentLower string) bool {
	for _, value := range htmlAttrValues(contentLower, "input", "type", true) {
		switch strings.TrimSpace(value) {
		case "email", "password":
			return true
		}
	}
	for _, value := range htmlAttrValues(contentLower, "input", "name", true) {
		switch strings.TrimSpace(value) {
		case "email", "pass", "password", "login":
			return true
		}
	}
	for _, value := range htmlAttrValues(contentLower, "input", "placeholder", true) {
		value = strings.TrimSpace(value)
		if strings.HasPrefix(value, "email") ||
			strings.HasPrefix(value, "you@") ||
			strings.HasPrefix(value, "your email") {
			return true
		}
	}
	return strings.Contains(contentLower, "work or school email") ||
		strings.Contains(contentLower, "corporate email")
}

func htmlAttrValues(contentLower, tagName, attrName string, allowUnquoted bool) []string {
	var values []string
	needle := "<" + tagName
	for offset := 0; offset < len(contentLower); {
		idx := strings.Index(contentLower[offset:], needle)
		if idx < 0 {
			break
		}
		start := offset + idx
		afterName := start + len(needle)
		if afterName < len(contentLower) && !isTagBoundary(contentLower[afterName]) {
			offset = afterName
			continue
		}
		end := findTagEnd(contentLower, afterName)
		if end < 0 {
			break
		}
		if value, ok := tagAttrValue(contentLower[afterName:end], attrName, allowUnquoted); ok {
			values = append(values, value)
		}
		offset = end + 1
	}
	return values
}

func isTagBoundary(c byte) bool {
	return c == '>' || c == '/' || unicode.IsSpace(rune(c))
}

func findTagEnd(content string, start int) int {
	var quote byte
	for i := start; i < len(content); i++ {
		c := content[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == '>' {
			return i
		}
	}
	return -1
}

func tagAttrValue(attrs, attrName string, allowUnquoted bool) (string, bool) {
	for i := 0; i < len(attrs); {
		for i < len(attrs) && (unicode.IsSpace(rune(attrs[i])) || attrs[i] == '/') {
			i++
		}
		nameStart := i
		for i < len(attrs) && attrs[i] != '=' && attrs[i] != '>' &&
			attrs[i] != '/' && !unicode.IsSpace(rune(attrs[i])) {
			i++
		}
		if nameStart == i {
			i++
			continue
		}
		name := attrs[nameStart:i]
		for i < len(attrs) && unicode.IsSpace(rune(attrs[i])) {
			i++
		}
		if i >= len(attrs) || attrs[i] != '=' {
			continue
		}
		i++
		for i < len(attrs) && unicode.IsSpace(rune(attrs[i])) {
			i++
		}
		if i >= len(attrs) {
			return "", false
		}

		value := ""
		if attrs[i] == '"' || attrs[i] == '\'' {
			quote := attrs[i]
			i++
			valueStart := i
			for i < len(attrs) && attrs[i] != quote {
				i++
			}
			value = attrs[valueStart:i]
			if i < len(attrs) {
				i++
			}
		} else {
			valueStart := i
			for i < len(attrs) && attrs[i] != '>' && !unicode.IsSpace(rune(attrs[i])) {
				i++
			}
			if !allowUnquoted {
				continue
			}
			value = attrs[valueStart:i]
		}
		if name == attrName {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
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

// quickPhishingCheck does a fast read of an HTML file and confirms phishing
// shape: a credential-collection form AND at least one phishing-kit signal
// in the page body itself. Used by the directory-anomaly heuristic to
// avoid flagging benign HTML that happens to ship an <input> tag.
//
// A bare "<form> + email/password keyword" gate matches developer demo
// pages, JavaScript login tutorials, contact forms, and password-reset
// stubs. Phishing kits add at least one of:
//   - a form action that posts to an external host (exfiltration target),
//   - a fully self-contained inline-styled HTML body (kits ship one file),
//   - real brand impersonation in the title or visible body (Office/PayPal/etc).
//
// Requiring credential intake plus one of those signals keeps real
// phishing kits in scope while letting tutorials and trivial forms drop
// out without consulting any path-name allowlist.
func quickPhishingCheck(path string) bool {
	f, err := osFS.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, 4096) // first 4KB is enough for the head, form attrs, brand strings
	n, _ := f.Read(buf)
	if n == 0 {
		return false
	}
	content := string(buf[:n])
	contentLower := strings.ToLower(content)

	if !hasHTMLCredentialInput(contentLower) {
		return false
	}

	if hasExternalFormAction(content) {
		return true
	}
	if isSelfContainedHTML(contentLower) {
		return true
	}

	titleContent := extractTitle(contentLower)
	for _, brand := range phishingBrands {
		if brand.generic {
			continue
		}
		for _, tp := range brand.titlePatterns {
			if titleContent != "" && strings.Contains(titleContent, tp) {
				return true
			}
		}
		for _, bp := range brand.bodyPatterns {
			if strings.Contains(contentLower, bp) {
				return true
			}
		}
	}
	return false
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
	hasCredentialInput := hasHTMLCredentialInput(contentLower)

	if !phpCredHandling && (!hasForm || !hasCredentialInput) {
		return nil
	}

	// A title brand is strong evidence on its own. A visible body or logo brand
	// is only accepted when the PHP reads a submitted password. Provider names
	// in backend backup, payment, and AJAX integration code are not page
	// impersonation and must not establish a brand.
	brandMatch := ""
	matchedGeneric := false
	pageMarkup := stripPHPBlocks(contentLower)
	titleContent := extractTitle(pageMarkup)

	if titleContent != "" {
		for _, brand := range phishingBrands {
			for _, tp := range brand.titlePatterns {
				if strings.Contains(titleContent, tp) {
					brandMatch = brand.name
					matchedGeneric = brand.generic
					indicators = append(indicators, fmt.Sprintf("title impersonates '%s'", tp))
					score += 3
					break
				}
			}
			if brandMatch != "" {
				break
			}
		}
	}
	if brandMatch == "" && hasPHPSubmittedPassword(contentLower) {
		bodyContent := visiblePageContent(pageMarkup, true)
		for _, brand := range phishingBrands {
			if brand.generic {
				continue
			}
			for _, bp := range brand.bodyPatterns {
				if strings.Contains(bodyContent, bp) {
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
	// The generic pseudo-brand ("Sign In" titles) matches a customer's own
	// login.php, which legitimately reads $_POST credentials. Require the
	// higher floor so a real brand or genuine exfil behaviour is needed.
	floor := 4
	if matchedGeneric {
		floor = phishingGenericBrandScoreFloor
	}
	if score >= floor {
		return &phishingResult{brand: brandMatch, score: score, indicators: indicators}
	}

	return nil
}

func hasPHPSubmittedPassword(contentLower string) bool {
	passwordKeys := map[string]bool{
		"password": true,
		"pass":     true,
		"passwd":   true,
		"pwd":      true,
		"passcode": true,
	}
	code := stripPHPCommentsFromCode(phpCodeOnly(contentLower))
	for i := 0; i < len(code); {
		if label, bodyStart, ok := phpHeredocOpen(code, i); ok {
			i = phpHeredocEnd(code, bodyStart, label)
			continue
		}
		if isPHPQuote(code[i]) {
			i = skipPHPString(code, i) + 1
			continue
		}

		nameLen := 0
		switch {
		case strings.HasPrefix(code[i:], "$_post"):
			nameLen = len("$_post")
		case strings.HasPrefix(code[i:], "$_request"):
			nameLen = len("$_request")
		}
		if nameLen == 0 || (i+nameLen < len(code) && isPHPIdentifierPart(code[i+nameLen])) {
			i++
			continue
		}

		j := skipPHPWhitespace(code, i+nameLen)
		if j >= len(code) || code[j] != '[' {
			i += nameLen
			continue
		}
		j = skipPHPWhitespace(code, j+1)
		if j >= len(code) || !isPHPQuote(code[j]) {
			i += nameLen
			continue
		}
		keyEnd := skipPHPString(code, j)
		if keyEnd <= j || keyEnd >= len(code) || code[keyEnd] != code[j] {
			return false
		}
		key := code[j+1 : keyEnd]
		j = skipPHPWhitespace(code, keyEnd+1)
		if j < len(code) && code[j] == ']' && passwordKeys[key] {
			return true
		}
		i += nameLen
	}
	return false
}

func stripPHPBlocks(content string) string {
	codeOnly := phpCodeOnly(content)
	visible := []byte(content)
	for i := range visible {
		switch codeOnly[i] {
		case ' ', '\t', '\n', '\r':
		default:
			visible[i] = ' '
		}
	}
	return string(visible)
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

// emailPattern matches a plausibly-real email address. The old heuristic
// counted any line containing '@', which random binary bytes and stray code
// tokens trip constantly. Requiring a local part, host and TLD keeps the count
// tied to actual addresses.
var (
	emailPattern        = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	emailAddressPattern = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)
)

// credentialLogReadLimit bounds how much of a candidate file is read for
// credential analysis.
const credentialLogReadLimit = 10 * 1024 * 1024

// looksBinary reports whether normalized text bytes still look binary. Images,
// video, fonts, and other files can carry result/harvest in their names and
// incidental email delimiters in their bytes. A NUL or a high share of control
// bytes keeps those files out of the credential parser.
func looksBinary(data []byte) bool {
	control := 0
	for _, b := range data {
		if b == 0x00 {
			return true
		}
		// Bytes >= 0x80 are kept as text so UTF-8 (accented names in an email
		// list) is not misread as binary.
		if b < 0x09 || (b > 0x0d && b < 0x20) || b == 0x7f {
			control++
		}
	}
	return control*10 > len(data)
}

func normalizeCredentialLogText(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf {
		return data[3:]
	}
	isLittleEndian := len(data) >= 2 && data[0] == 0xff && data[1] == 0xfe
	isBigEndian := len(data) >= 2 && data[0] == 0xfe && data[1] == 0xff
	body := data
	var order binary.ByteOrder
	switch {
	case isLittleEndian:
		body = data[2:]
		order = binary.LittleEndian
	case isBigEndian:
		body = data[2:]
		order = binary.BigEndian
	default:
		pairs := len(data) / 2
		if pairs < 4 {
			return data
		}
		evenNUL, oddNUL := 0, 0
		for i := 0; i+1 < len(data); i += 2 {
			if data[i] == 0 {
				evenNUL++
			}
			if data[i+1] == 0 {
				oddNUL++
			}
		}
		switch {
		case oddNUL >= 4 && oddNUL*2 >= pairs && evenNUL*20 <= pairs:
			order = binary.LittleEndian
		case evenNUL >= 4 && evenNUL*2 >= pairs && oddNUL*20 <= pairs:
			order = binary.BigEndian
		default:
			return data
		}
	}

	units := make([]uint16, len(body)/2)
	for i := range units {
		units[i] = order.Uint16(body[i*2:])
	}
	return []byte(string(utf16.Decode(units)))
}

// checkCredentialLog reads a text file and checks if it contains harvested
// credentials (email:password pairs, one per line) or a harvested address list.
func checkCredentialLog(path string) string {
	f, err := osFS.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	// Reject binaries from the head before reading the whole file into memory:
	// images, video, and fonts that carry a "result"/"harvest" keyword in their
	// name would otherwise be slurped in full only to be discarded. The head is
	// decoded first so a UTF-16 dump, whose raw bytes look binary, survives the
	// peek.
	head := make([]byte, 8192)
	hn, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return ""
	}
	head = head[:hn]
	if hn == 0 || looksBinary(normalizeCredentialLogText(head)) {
		return ""
	}

	rest, err := io.ReadAll(io.LimitReader(f, credentialLogReadLimit+1-int64(hn)))
	if err != nil {
		return ""
	}
	return analyzeCredentialLog(append(head, rest...), path)
}

// analyzeCredentialLog classifies bounded, already-read file content as a
// harvested credential dump (email:password pairs) or address list, returning
// the finding detail or an empty string.
func analyzeCredentialLog(data []byte, path string) string {
	if len(data) == 0 || len(data) > credentialLogReadLimit {
		return ""
	}
	data = normalizeCredentialLogText(data)
	if looksBinary(data) {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	credentialLines := 0
	emailLines := 0
	nonEmpty := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		nonEmpty++
		if !emailPattern.MatchString(line) {
			continue
		}
		emailLines++
		// Pattern: email:password or email|password or email,password, where the
		// field before the delimiter holds the address and the field after is a
		// non-empty secret token with no whitespace.
		for _, delim := range []string{":", "|", "\t", ","} {
			parts := strings.SplitN(line, delim, 3)
			if len(parts) >= 2 {
				secret := strings.TrimSpace(parts[1])
				address := strings.TrimSpace(parts[0])
				if emailAddressPattern.MatchString(address) && secret != "" && !strings.ContainsAny(secret, " \t") {
					credentialLines++
					break
				}
			}
		}
	}

	// 3+ lines that look like email:password pairs = credential log
	if credentialLines >= 3 {
		return fmt.Sprintf("File contains %d credential-like lines (email:password format) out of %d email lines",
			credentialLines, emailLines)
	}

	// A harvested address list is dominated by addresses (about one per line).
	// Source files (JavaScript modules, Drupal handlers) legitimately embed a
	// handful of contributor/support addresses among mostly-code lines; those
	// are not harvested lists, so require the addresses to be the majority of
	// non-empty lines. .csv exports of a contact list are excluded outright.
	if emailLines >= 10 && emailLines*2 >= nonEmpty && !strings.HasSuffix(strings.ToLower(path), ".csv") {
		return fmt.Sprintf("File contains %d email addresses - possible harvested email list", emailLines)
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

	// A phishing wrapper is essentially just the iframe - its only purpose is to
	// fill the screen with the external page. A documented embed or demo (e.g.
	// software shipping an "iframe-example.html" with an explanatory paragraph)
	// carries prose around the iframe, so real visible text means this is not a
	// bare redirect wrapper.
	if isFullscreen && visibleTextLen(contentLower) <= 40 {
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

// isPhishingKitZipName checks if a ZIP filename matches common phishing kit names.
// Requires 2+ keyword matches to reduce false positives (e.g. "CssCheckboxKit"
// matched "kit" alone, but legitimate UI kits, CSS kits, etc. are common).
func isPhishingKitZipName(nameLower string) bool {
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

// kitCaptureScripts are filenames phishing kits use for the server-side
// credential-capture step. These names are kit idiom, not generic app files.
var kitCaptureScripts = map[string]bool{
	"next.php": true, "post.php": true, "send.php": true, "grab.php": true,
	"result.php": true, "results.php": true,
}

var kitAntibotScripts = map[string]bool{
	"antibots": true, "blocker": true,
	"antibot.php": true, "blocker.php": true, "bots.php": true, "killbot.php": true,
}

// kitLoginPageWords identify login or verification pages inside an archive.
// The archive prefilter already supplies the brand signal, so repeating brand
// names here would misclassify ordinary provider plugins as login pages.
var kitLoginPageWords = []string{
	"signin", "sign-in", "verify", "login", "log-in", "secure",
}

func isKitCredentialSinkName(base string) bool {
	switch strings.ToLower(filepath.Ext(base)) {
	case ".txt", ".log", ".csv":
		return isCredentialLogName(base)
	default:
		return false
	}
}

// zipLooksLikeKit inspects a ZIP's central directory (entry names only, no
// decompression) and reports whether the contents match a phishing kit rather
// than a legitimate plugin/theme distribution archive. Filename brand keywords
// alone flagged legitimate plugin zips (Instagram Feed, Facebook articles,
// cPanel eCRM); the archive body is what actually distinguishes a kit: a
// credential sink file, a capture script, a brand-login page, an anti-bot
// blocker. Two signal categories from at least two distinct entries are
// required so one generic result filename cannot decide the archive alone.
func zipLooksLikeKit(path string) bool {
	f, err := osFS.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return false
	}
	if !info.Mode().IsRegular() || info.Size() <= 1000 || info.Size() >= 50*1024*1024 {
		return false
	}
	return phishingKitZipHasEvidence(f, info.Size())
}

// phishingKitZipHasEvidence confirms a bounded ZIP using independent entry-name
// signals without decompressing attacker-controlled archive contents.
func phishingKitZipHasEvidence(reader io.ReaderAt, size int64) bool {
	if size <= 1000 || size >= 50*1024*1024 {
		return false
	}
	zr, err := zip.NewReader(reader, size)
	if err != nil {
		return false
	}

	capture, credSink, antibot := false, false, false
	brandPages := 0
	evidenceEntries := make(map[string]bool)
	for _, e := range zr.File {
		if e.FileInfo().IsDir() {
			continue
		}
		base := e.Name
		if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
			base = base[i+1:]
		}
		base = strings.ToLower(base)

		hasEvidence := false
		if kitCaptureScripts[base] {
			capture = true
			hasEvidence = true
		}
		if isKitCredentialSinkName(base) {
			credSink = true
			hasEvidence = true
		}
		if kitAntibotScripts[base] || strings.Contains(base, "antibot") {
			antibot = true
			hasEvidence = true
		}
		if strings.HasSuffix(base, ".html") || strings.HasSuffix(base, ".htm") || isExecutablePHPName(base) {
			for _, w := range kitLoginPageWords {
				if strings.Contains(base, w) {
					brandPages++
					hasEvidence = true
					break
				}
			}
		}
		if hasEvidence {
			evidenceEntries[e.Name] = true
		}
	}
	signals := 0
	if capture {
		signals++
	}
	if credSink {
		signals++
	}
	if antibot {
		signals++
	}
	if brandPages >= 1 {
		signals++
	}
	return signals >= 2 && len(evidenceEntries) >= 2
}

func visiblePageContent(s string, includeImageAttrs bool) string {
	doc, err := html.Parse(strings.NewReader(s))
	if err != nil {
		return ""
	}
	hiddenClasses, hiddenIDs := stylesheetHiddenSelectors(doc)

	var content strings.Builder
	var walk func(*html.Node, bool)
	walk = func(node *html.Node, hidden bool) {
		if node.Type == html.ElementNode {
			switch node.Data {
			case "head", "script", "style", "template", "noscript", "iframe":
				hidden = true
			}
			if htmlElementHidden(node, hiddenClasses, hiddenIDs) {
				hidden = true
			}
			if includeImageAttrs && !hidden && node.Data == "img" {
				for _, attr := range node.Attr {
					switch attr.Key {
					case "alt", "title", "aria-label", "src":
						content.WriteByte(' ')
						content.WriteString(attr.Val)
					}
				}
			}
		}
		if node.Type == html.TextNode && !hidden {
			content.WriteByte(' ')
			content.WriteString(node.Data)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child, hidden)
		}
	}
	walk(doc, false)
	return content.String()
}

func htmlElementHidden(node *html.Node, hiddenClasses, hiddenIDs map[string]bool) bool {
	for _, attr := range node.Attr {
		switch attr.Key {
		case "hidden":
			return true
		case "class":
			for _, class := range strings.Fields(attr.Val) {
				if hiddenClasses[class] {
					return true
				}
			}
		case "id":
			if hiddenIDs[attr.Val] {
				return true
			}
		case "aria-hidden":
			if strings.EqualFold(strings.TrimSpace(attr.Val), "true") {
				return true
			}
		case "style":
			if cssDeclarationsHide(attr.Val) {
				return true
			}
		}
	}
	return false
}

func stylesheetHiddenSelectors(doc *html.Node) (map[string]bool, map[string]bool) {
	hiddenClasses := make(map[string]bool)
	hiddenIDs := make(map[string]bool)
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "style" {
			var css strings.Builder
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				if child.Type == html.TextNode {
					css.WriteString(child.Data)
				}
			}
			collectHiddenStylesheetSelectors(css.String(), hiddenClasses, hiddenIDs)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return hiddenClasses, hiddenIDs
}

func collectHiddenStylesheetSelectors(css string, hiddenClasses, hiddenIDs map[string]bool) {
	css = stripCSSComments(css)
	for {
		open := strings.IndexByte(css, '{')
		if open < 0 {
			return
		}
		closeOffset := strings.IndexByte(css[open+1:], '}')
		if closeOffset < 0 {
			return
		}
		closeIndex := open + 1 + closeOffset
		if cssDeclarationsHide(css[open+1 : closeIndex]) {
			for _, selector := range strings.Split(css[:open], ",") {
				selector = strings.TrimSpace(selector)
				if len(selector) < 2 || strings.ContainsAny(selector, " >+~:[]*") {
					continue
				}
				marker := strings.LastIndexAny(selector, ".#")
				if marker < 0 || !isSimpleCSSIdentifier(selector[marker+1:]) {
					continue
				}
				prefix := selector[:marker]
				if prefix != "" && !isSimpleCSSIdentifier(prefix) {
					continue
				}
				switch selector[marker] {
				case '.':
					hiddenClasses[selector[marker+1:]] = true
				case '#':
					hiddenIDs[selector[marker+1:]] = true
				}
			}
		}
		css = css[closeIndex+1:]
	}
}

func stripCSSComments(css string) string {
	var stripped strings.Builder
	for len(css) > 0 {
		start := strings.Index(css, "/*")
		if start < 0 {
			stripped.WriteString(css)
			break
		}
		stripped.WriteString(css[:start])
		end := strings.Index(css[start+2:], "*/")
		if end < 0 {
			break
		}
		css = css[start+2+end+2:]
	}
	return stripped.String()
}

func cssDeclarationsHide(declarations string) bool {
	for _, declaration := range strings.Split(strings.ToLower(declarations), ";") {
		parts := strings.SplitN(declaration, ":", 2)
		if len(parts) != 2 {
			continue
		}
		property := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(parts[1]), "!important"))
		if (property == "display" && value == "none") ||
			(property == "visibility" && (value == "hidden" || value == "collapse")) ||
			(property == "opacity" && value == "0") {
			return true
		}
	}
	return false
}

func isSimpleCSSIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

// visibleTextLen counts rendered non-whitespace characters. Script, style,
// template, noscript, iframe fallback, comment, and head contents do not
// document an embed.
func visibleTextLen(s string) int {
	n := 0
	for _, r := range visiblePageContent(s, false) {
		if !unicode.IsSpace(r) {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// Safe directory list
// ---------------------------------------------------------------------------

// isKnownSafeDir names directories that CheckPhishing does not recurse into.
// The list is deliberately narrow: only heavy, non-servable, or checksum-
// verified trees (WP core, dependency vendor dirs, VCS metadata) and transient
// caches. wp-content and .well-known are NOT here - both are prime real-world
// phishing drop paths (wp-content/uploads date folders, world-writable ACME
// challenge dirs) and must be scanned. Never widen this list to skip a path
// where a file could be dropped and served; fix detection instead.
func isKnownSafeDir(name string) bool {
	safeDirs := map[string]bool{
		"wp-admin": true, "wp-includes": true,
		"node_modules": true, "vendor": true, ".git": true,
		"cgi-bin": true, "mail": true,
		"cache": true, "tmp": true, "logs": true,
	}
	return safeDirs[name]
}
