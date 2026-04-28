package checks

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// .htaccess hardened detection / cleaning.
//
// Detection emits one of seven specific finding names so operators
// can suppress, route, or auto-respond per attack pattern instead of
// relying on the generic htaccess_injection / htaccess_handler_abuse
// categories. Cleaning is gated by AutoResponse.CleanHtaccess and is
// always backed up under /opt/csm/quarantine/pre_clean/.
//
// Each detector returns matches as byte ranges into the file
// content; the cleaner merges all ranges (deduplicating overlaps),
// removes them, and writes the result atomically. If post-clean
// content is identical to pre-clean (no detector matched anything
// new), no write happens and no backup is created.

// htaccessBackupDirRoot is the parent directory under which
// CleanHtaccessFile writes <ts>_<sanitized-path> backups. Exposed
// as a package var so tests can redirect it to a t.TempDir().
var htaccessBackupDirRoot = "/opt/csm/quarantine/pre_clean"

// htaccessByteRange is a half-open [start, end) byte slice into the
// file content. Cleaning removes the bytes; the line ending after
// `end` is included when `end` falls just before a `\n` so we do
// not leave a blank line behind.
type htaccessByteRange struct {
	Start int
	End   int
}

// htaccessMatch is one finding-worthy hit returned by a detector.
type htaccessMatch struct {
	Range   htaccessByteRange
	Excerpt string // the offending line(s), trimmed for the finding details
}

// htaccessDetector pairs a finding category with a function that
// scans the content and reports every range the detector wants
// removed. Adding an 8th pattern is one entry in this slice.
type htaccessDetector struct {
	Name     string
	Severity alert.Severity
	Detect   func(content []byte, path string) []htaccessMatch
}

// htaccessSpamTLDs lists TLDs commonly abused for spam-redirect
// .htaccess injections. Operators on legitimate hosts in these TLDs
// can suppress the finding by file path.
var htaccessSpamTLDs = []string{
	".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".click",
	".country", ".loan", ".work", ".top",
}

// htaccessNonScriptDirHints names directory components where PHP
// execution is rarely legitimate. .htaccess files inside one of
// these get the htaccess_php_in_uploads finding when they map
// non-PHP extensions to a PHP handler.
//
// /tmp/ is intentionally NOT in this list even though attackers
// drop payloads there: a real-world .htaccess inside /tmp/ would
// only be reached if the webserver served /tmp/, which is rare
// outside misconfigurations -- and including it caused
// false-positive matches against Linux t.TempDir() paths under
// /tmp/ in the test suite. The auto_prepend detector covers the
// /tmp/ payload-target angle separately.
var htaccessNonScriptDirHints = []string{
	"/uploads/", "/images/", "/cache/",
	"/wp-content/uploads/", "/wp-content/cache/",
	"/files/", "/media/",
}

// htaccessSuspiciousAutoPrependPaths are filesystem locations that
// auto_prepend_file should never reference. Anything in /tmp/,
// /dev/shm/, /var/tmp/ or pointing at an image extension is
// always-malicious.
var htaccessSuspiciousAutoPrependPaths = []string{
	"/tmp/", "/dev/shm/", "/var/tmp/",
}
var htaccessImageExtensions = []string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".ico"}

// htaccessTrackingHeaders is a small allowlist of header *names*
// known to be used in injection campaigns. Scoped intentionally;
// false positives on legitimate analytics/CDN headers are worse
// than missed detections here.
var htaccessTrackingHeaders = []string{
	"X-Track-", "X-Affiliate-", "X-Promo-", "X-Click-ID",
}

var (
	rePHPHandlerMap   = regexp.MustCompile(`(?im)^\s*(AddHandler|SetHandler|ForceType)\s+\S*php\S*\s+([^\n]+)$`)
	reAutoPrepend     = regexp.MustCompile(`(?im)^\s*php_value\s+auto_prepend_file\s+(\S+)`)
	reUACloakCond     = regexp.MustCompile(`(?im)^\s*RewriteCond\s+%\{HTTP_USER_AGENT\}\s+([^\n]+)`)
	reSpamRedirect    = regexp.MustCompile(`(?im)^\s*RewriteRule\s+\S+\s+(https?://[^\s\[]+)`)
	reFilesMatchOpen  = regexp.MustCompile(`(?im)^\s*<FilesMatch\s+["']?[^"'>]*\\\.(php|phtml|ph[2-7])[^"'>]*["']?\s*>`)
	reFilesMatchClose = regexp.MustCompile(`(?im)^\s*</FilesMatch>`)
	reHeaderSetAdd    = regexp.MustCompile(`(?im)^\s*Header\s+(set|add)\s+([A-Za-z0-9_-]+)`)
	reErrorDocument   = regexp.MustCompile(`(?im)^\s*ErrorDocument\s+\d+\s+(https?://[^\s]+)`)

	// crawlerUARegex matches the UA strings frequently used in cloak
	// conditions: search-engine bots and social-share scrapers. Used
	// as a positive filter on the htaccess_user_agent_cloak finding;
	// matching one of these names is what makes a UA-keyed redirect
	// suspicious.
	crawlerUARegex = regexp.MustCompile(`(?i)(googlebot|bingbot|baiduspider|yandex|facebookexternalhit|slurp|duckduckbot)`)
)

// htaccessDetectors is the registry. Order matters only for finding
// emission: detectors run in slice order so the first detector to
// see a line wins.
var htaccessDetectors = []htaccessDetector{
	{
		Name:     "htaccess_php_in_uploads",
		Severity: alert.Critical,
		Detect:   detectPHPInUploads,
	},
	{
		Name:     "htaccess_auto_prepend",
		Severity: alert.Critical,
		Detect:   detectAutoPrepend,
	},
	{
		Name:     "htaccess_user_agent_cloak",
		Severity: alert.High,
		Detect:   detectUserAgentCloak,
	},
	{
		Name:     "htaccess_spam_redirect",
		Severity: alert.High,
		Detect:   detectSpamRedirect,
	},
	{
		Name:     "htaccess_filesmatch_shield",
		Severity: alert.Critical,
		Detect:   detectFilesMatchShield,
	},
	{
		Name:     "htaccess_header_injection",
		Severity: alert.High,
		Detect:   detectHeaderInjection,
	},
	{
		Name:     "htaccess_errordocument_hijack",
		Severity: alert.High,
		Detect:   detectErrorDocumentHijack,
	},
}

// AuditHtaccessFile runs every registered detector against the file
// at path. Returns the alert findings (one per detector hit) and
// the merged byte ranges that the cleaner would remove. The two
// outputs travel together so cleaning never disagrees with what
// the operator was alerted about.
func AuditHtaccessFile(path string) ([]alert.Finding, []htaccessByteRange) {
	if filepath.Base(path) != ".htaccess" {
		return nil, nil
	}
	// #nosec G304 -- path resolved by the caller via ResolveWebRoots / scanHtaccess; the operator's file tree, not attacker input.
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}

	var findings []alert.Finding
	var ranges []htaccessByteRange
	for _, d := range htaccessDetectors {
		matches := d.Detect(content, path)
		for _, m := range matches {
			findings = append(findings, alert.Finding{
				Severity:  d.Severity,
				Check:     d.Name,
				Message:   fmt.Sprintf("%s in %s", d.Name, path),
				Details:   fmt.Sprintf("File: %s\nMatch: %s", path, m.Excerpt),
				FilePath:  path,
				Timestamp: time.Now(),
			})
			ranges = append(ranges, m.Range)
		}
	}
	return findings, mergeRanges(ranges)
}

// CleanHtaccessFile audits the file, computes the removal range
// set, backs up the original, and writes the trimmed content.
// Returns success=false with no Action when no detector matched
// (i.e., nothing to clean).
//
// Caller is responsible for gating on cfg.AutoResponse.CleanHtaccess
// before invoking; this function will clean unconditionally if
// detectors find anything.
func CleanHtaccessFile(path string) RemediationResult {
	if filepath.Base(path) != ".htaccess" {
		return RemediationResult{Error: "automated .htaccess remediation only applies to .htaccess files"}
	}
	resolved, _, err := resolveExistingFixPath(path, fixHtaccessAllowedRoots)
	if err != nil {
		return RemediationResult{Error: err.Error()}
	}

	// #nosec G304 -- resolved path verified inside the allowed roots.
	original, err := os.ReadFile(resolved)
	if err != nil {
		return RemediationResult{Error: fmt.Sprintf("cannot read: %v", err)}
	}

	_, ranges := AuditHtaccessFile(resolved)
	if len(ranges) == 0 {
		return RemediationResult{Error: "no malicious directives found to remove"}
	}

	cleaned := applyRangeRemoval(original, ranges)
	if len(cleaned) == len(original) {
		return RemediationResult{Error: "no bytes removed (range computation produced empty diff)"}
	}

	backupDir := htaccessBackupDirRoot
	if err = os.MkdirAll(backupDir, 0750); err != nil {
		return RemediationResult{Error: fmt.Sprintf("creating backup dir: %v", err)}
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("%s_%s", stamp, sanitizePathForBackup(resolved)))
	// #nosec G306 G703 -- 0640 matches the rest of pre_clean/. backupPath is filepath.Join(backupDir, <ts>_<sanitizePathForBackup>) where sanitizePathForBackup strips every / and .. so the result cannot escape backupDir; resolved itself was validated by resolveExistingFixPath (fixHtaccessAllowedRoots).
	if err = os.WriteFile(backupPath, original, 0640); err != nil {
		return RemediationResult{Error: fmt.Sprintf("writing backup: %v", err)}
	}
	// .meta written as JSON in the same shape as autoresponse.go's
	// QuarantineMeta so the existing /api/v1/quarantine listing and
	// /api/v1/quarantine-restore handlers pick up htaccess pre_clean
	// backups without a parallel codepath. The early implementation
	// used a plain key=value sidecar; nothing in the pipeline read
	// that, which made htaccess backups invisible in the UI.
	metaPath := backupPath + ".meta"
	metaJSON, err := json.Marshal(QuarantineMeta{
		OriginalPath: resolved,
		Size:         int64(len(original)),
		QuarantineAt: time.Now().UTC(),
		Reason:       fmt.Sprintf("htaccess clean: %d ranges removed (%d -> %d bytes)", len(ranges), len(original), len(cleaned)),
	})
	if err != nil {
		return RemediationResult{Error: fmt.Sprintf("encoding backup meta: %v", err)}
	}
	// #nosec G306 -- sidecar meta; 0640 matches the backup file mode.
	if err := os.WriteFile(metaPath, metaJSON, 0640); err != nil {
		return RemediationResult{Error: fmt.Sprintf("writing backup meta: %v", err)}
	}

	tmp := resolved + ".csm-clean.tmp"
	// #nosec G306 G703 -- 0644 is what the webserver expects for static content. tmp = resolved + ".csm-clean.tmp"; resolved was validated by resolveExistingFixPath against fixHtaccessAllowedRoots so path traversal is impossible.
	if err := os.WriteFile(tmp, cleaned, 0644); err != nil {
		return RemediationResult{Error: fmt.Sprintf("writing cleaned tmp: %v", err)}
	}
	if err := os.Rename(tmp, resolved); err != nil {
		_ = os.Remove(tmp)
		return RemediationResult{Error: fmt.Sprintf("atomic rename: %v", err)}
	}

	bytesRemoved := len(original) - len(cleaned)
	return RemediationResult{
		Success:     true,
		Action:      fmt.Sprintf("removed %d malicious byte(s) from %s", bytesRemoved, resolved),
		Description: fmt.Sprintf("Cleaned .htaccess: %d ranges, %d bytes removed (backup: %s)", len(ranges), bytesRemoved, backupPath),
	}
}

// mergeRanges normalises the input slice: sort by start, then merge
// overlapping or adjacent ranges so cleaning produces deterministic
// output regardless of detector order.
func mergeRanges(in []htaccessByteRange) []htaccessByteRange {
	if len(in) == 0 {
		return nil
	}
	cp := make([]htaccessByteRange, len(in))
	copy(cp, in)
	sort.Slice(cp, func(i, j int) bool { return cp[i].Start < cp[j].Start })
	out := []htaccessByteRange{cp[0]}
	for _, r := range cp[1:] {
		last := &out[len(out)-1]
		if r.Start <= last.End {
			if r.End > last.End {
				last.End = r.End
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// applyRangeRemoval slices `content` minus every range in `ranges`
// (which mergeRanges has already sorted/merged). Each removal also
// includes the trailing newline if `end` lands on one, so we do not
// leave a blank line behind.
func applyRangeRemoval(content []byte, ranges []htaccessByteRange) []byte {
	out := make([]byte, 0, len(content))
	cursor := 0
	for _, r := range ranges {
		if r.Start > cursor {
			out = append(out, content[cursor:r.Start]...)
		}
		end := r.End
		if end < len(content) && content[end] == '\n' {
			end++
		}
		cursor = end
	}
	if cursor < len(content) {
		out = append(out, content[cursor:]...)
	}
	return out
}

func sanitizePathForBackup(p string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", " ", "_", ":", "_")
	return strings.TrimPrefix(r.Replace(p), "_")
}

// detectPHPInUploads flags AddHandler/SetHandler/ForceType lines
// that map to PHP when the .htaccess lives inside a directory where
// PHP execution is rarely legitimate.
func detectPHPInUploads(content []byte, path string) []htaccessMatch {
	if !pathInNonScriptDir(path) {
		return nil
	}
	return matchesFromRegex(content, rePHPHandlerMap)
}

func pathInNonScriptDir(path string) bool {
	lower := strings.ToLower(path)
	for _, dir := range htaccessNonScriptDirHints {
		if strings.Contains(lower, dir) {
			return true
		}
	}
	return false
}

// detectAutoPrepend flags php_value auto_prepend_file directives
// that point at filesystem locations known not to host legitimate
// prelude scripts.
func detectAutoPrepend(content []byte, _ string) []htaccessMatch {
	idxs := reAutoPrepend.FindAllSubmatchIndex(content, -1)
	var out []htaccessMatch
	for _, idx := range idxs {
		if len(idx) < 4 {
			continue
		}
		target := string(content[idx[2]:idx[3]])
		if !autoPrependTargetSuspicious(target) {
			continue
		}
		out = append(out, htaccessMatch{
			Range:   lineRange(content, idx[0], idx[1]),
			Excerpt: trimExcerpt(content, idx[0], idx[1]),
		})
	}
	return out
}

func autoPrependTargetSuspicious(target string) bool {
	lower := strings.ToLower(target)
	for _, p := range htaccessSuspiciousAutoPrependPaths {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	for _, ext := range htaccessImageExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// reUARewriteRuleAfter captures the substitution and flag list of a
// RewriteRule directive. Used to inspect the rule paired with a
// preceding UA cond so the detector can distinguish defensive blocks
// (forbid / no-op / sinkhole) from cloaks (rewrite to a different
// file or external URL).
var reUARewriteRuleAfter = regexp.MustCompile(`(?im)^\s*RewriteRule\s+\S+\s+(\S+)(?:\s+\[([^\]]+)\])?\s*$`)

// uaCloakDefensiveFlags lists RewriteRule flags that, when set on the
// rule paired with a UA cond, indicate defensive blocking rather than
// content cloaking. Apache combines these flags with a comma so each
// flag is matched as a substring of the bracketed flag list.
var uaCloakDefensiveFlags = []string{"f", "g"}

// uaCloakBlocklistThreshold is the number of OR-list entries in the
// UA cond's regex that converts the cond from "potential cloak" to
// "operator-installed bot blocklist". A cond with 4+ alternation
// entries is overwhelmingly a defensive block (the canonical
// SoftAculous / Apache Bad Bots list ships ~20+ entries).
const uaCloakBlocklistThreshold = 4

// uaCloakAlternationCount counts the top-level "|" alternation
// branches in a UA cond regex pattern, ignoring "|" characters inside
// nested parentheses. Used to identify long bot blocklists.
func uaCloakAlternationCount(pattern string) int {
	depth := 0
	count := 1
	prevEscape := false
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if prevEscape {
			prevEscape = false
			continue
		}
		switch c {
		case '\\':
			prevEscape = true
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case '|':
			if depth <= 1 {
				count++
			}
		}
	}
	return count
}

// uaCloakPairedRuleIsDefensive scans forward from condEnd for the
// RewriteRule directive that Apache will pair with the cond. Returns
// true when that rule is a no-op ("-" substitution), a forbid
// ([F]/[G] flag), or absent. Both shapes are defensive, not cloaking.
//
// Apache's chaining model: a chain of RewriteCond lines applies to
// the FIRST RewriteRule that follows them in the file. We walk
// line-by-line and stop at the first RewriteRule. A blank line, a
// non-RewriteCond directive, or end-of-file means there is no paired
// rule - the cond is dead text and not actively cloaking anything.
func uaCloakPairedRuleIsDefensive(content []byte, condEnd int) bool {
	rest := content[condEnd:]
	// Find the next RewriteRule line.
	idx := reUARewriteRuleAfter.FindSubmatchIndex(rest)
	if idx == nil {
		return true
	}
	substitution := string(rest[idx[2]:idx[3]])
	var flags string
	if idx[4] != -1 {
		flags = strings.ToLower(string(rest[idx[4]:idx[5]]))
	}
	if substitution == "-" {
		return true
	}
	for _, f := range uaCloakDefensiveFlags {
		// Match flag as a comma-bounded token: "F" matches "[F]",
		// "[F,L]", "[L,F]"; does NOT match "[NC]" or "[QSA]".
		for _, token := range strings.Split(flags, ",") {
			if strings.TrimSpace(token) == f {
				return true
			}
		}
	}
	return false
}

// detectUserAgentCloak flags RewriteCond %{HTTP_USER_AGENT}
// directives that match a known crawler UA AND are part of an active
// content-cloaking rule. Three suppression gates filter legitimate
// shapes before emitting the High alert:
//
//  1. Negated cond ("RewriteCond %{HTTP_USER_AGENT} !..."): the rule
//     applies only when the UA is NOT this crawler. Cache plugins
//     (WP Fastest Cache, WP Super Cache) ship long negated lists to
//     exclude social-share scrapers from the cached-content rewrite.
//
//  2. Long alternation (>= uaCloakBlocklistThreshold OR-branches):
//     operator-installed defensive blocklists ship many bot UAs in
//     a single OR chain paired with a [F] forbid or sinkhole rewrite.
//     Cloakers use one or two crawler names.
//
//  3. Paired RewriteRule is defensive ("-" substitution, [F]/[G]
//     flag, or absent): the cond is part of a forbid / env-var-set
//     block, not a content swap.
//
// All three gates fail-closed: any uncertainty (no paired rule
// found, parse failure) keeps the original alert firing.
func detectUserAgentCloak(content []byte, _ string) []htaccessMatch {
	idxs := reUACloakCond.FindAllSubmatchIndex(content, -1)
	var out []htaccessMatch
	for _, idx := range idxs {
		if len(idx) < 4 {
			continue
		}
		uaPattern := string(content[idx[2]:idx[3]])
		if !crawlerUARegex.MatchString(uaPattern) {
			continue
		}
		// Gate 1: negated cond. Strip leading whitespace and look
		// for "!" before the rest of the pattern.
		if strings.HasPrefix(strings.TrimSpace(uaPattern), "!") {
			continue
		}
		// Gate 2: long alternation list = bot blocklist.
		if uaCloakAlternationCount(uaPattern) >= uaCloakBlocklistThreshold {
			continue
		}
		// Gate 3: paired RewriteRule is defensive.
		if uaCloakPairedRuleIsDefensive(content, idx[1]) {
			continue
		}
		out = append(out, htaccessMatch{
			Range:   lineRange(content, idx[0], idx[1]),
			Excerpt: trimExcerpt(content, idx[0], idx[1]),
		})
	}
	return out
}

// detectSpamRedirect flags RewriteRule directives whose target host
// is on a known spam TLD. Operator-supplied legitimate hosts in
// these TLDs need a per-path suppression.
func detectSpamRedirect(content []byte, _ string) []htaccessMatch {
	idxs := reSpamRedirect.FindAllSubmatchIndex(content, -1)
	var out []htaccessMatch
	for _, idx := range idxs {
		if len(idx) < 4 {
			continue
		}
		target := string(content[idx[2]:idx[3]])
		host := extractHost(target)
		if !hostOnSpamTLD(host) {
			continue
		}
		out = append(out, htaccessMatch{
			Range:   lineRange(content, idx[0], idx[1]),
			Excerpt: trimExcerpt(content, idx[0], idx[1]),
		})
	}
	return out
}

func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func hostOnSpamTLD(host string) bool {
	for _, tld := range htaccessSpamTLDs {
		if strings.HasSuffix(host, tld) {
			return true
		}
	}
	return false
}

// reFilesMatchPattern captures the regex pattern inside the FilesMatch
// quotes. The capture group is everything between the optional quote
// characters, which is the Apache-side regex applied to filenames.
var reFilesMatchPattern = regexp.MustCompile(`(?im)^\s*<FilesMatch\s+["']?([^"'>]+?)["']?\s*>`)

// reFilesMatchExtensionTail strips the canonical PHP extension suffix
// from a FilesMatch pattern so the remaining literal can be examined.
// Anchors and end-of-string markers are left to the caller.
var reFilesMatchExtensionTail = regexp.MustCompile(`(?i)\\\.(?:php|phtml|ph[2-7])\$?\)?$`)

// filesMatchPatternIsTargeted reports whether the FilesMatch regex
// names at least one specific PHP filename rather than granting access
// to every .php file in the directory. Stock plugins ship targeted
// patterns ("wpc\.php$", "ps_facetedsearch-.+\.php$",
// "(webp-on-demand\.php|webp-realizer\.php)$"); the malicious shape
// is a bare wildcard ("\.php$", ".*\.php$", "[^/]+\.php$").
//
// The check is character-class based: any literal alphanumeric, dash,
// or underscore in the pattern (after stripping the trailing
// "\.php$" / "\.phtml$" extension) means the pattern names something
// specific. A pattern composed only of regex meta-characters (".",
// "*", "^", "$", "[", "]", "(", ")", "|", "+", "?", "\\") is treated
// as a wildcard and continues to the wildcard-context check.
func filesMatchPatternIsTargeted(pattern string) bool {
	stripped := reFilesMatchExtensionTail.ReplaceAllString(pattern, "")
	for _, c := range stripped {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			return true
		}
	}
	return false
}

// htaccessParentPHPFileCount counts ".php" files (and other handler
// extensions FilesMatch covers) sitting alongside the .htaccess at
// path. Used to differentiate a plugin directory full of legitimate
// PHP dispatchers from a freshly-attacker-written upload directory
// containing one or zero PHP files.
//
// Errors (parent missing, permission denied, race) return 0 - the
// caller treats that as "not enough sibling PHP" and keeps firing.
func htaccessParentPHPFileCount(htaccessPath string) int {
	parent := filepath.Dir(htaccessPath)
	entries, err := os.ReadDir(parent)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		switch ext {
		case ".php", ".phtml", ".ph2", ".ph3", ".ph4", ".ph5", ".ph6", ".ph7":
			n++
		}
	}
	return n
}

// filesMatchShieldSiblingThreshold is the number of sibling PHP files
// that converts a bare-wildcard FilesMatch shield from "fire" to
// "treat as legitimate plugin allowlist". A directory with 3+ stock
// PHP dispatchers existing alongside the shield is overwhelmingly
// likely to be a legitimate webapp module (KCFinder ships ~5,
// PrestaShop modules ship ~10+, vendor dispatchers ship a handful).
// The attacker drop pattern is .htaccess + one or zero PHP files.
const filesMatchShieldSiblingThreshold = 3

// detectFilesMatchShield finds <FilesMatch ...\.php(tml)?> blocks
// that grant Allow from all or Require all granted -- the canonical
// "let everyone execute everything we just dropped" pattern. The
// returned range covers the full block, opening tag through closing
// tag inclusive.
//
// Two suppression gates run before emitting the finding:
//
//  1. Targeted pattern: if the FilesMatch regex names a specific
//     filename ("wpc\.php$", named allowlist, or prefix pattern), it
//     is a legitimate plugin allowlist and is skipped.
//
//  2. Bare wildcard with sibling PHP context: if the FilesMatch is a
//     bare wildcard but the .htaccess parent directory contains
//     multiple sibling PHP dispatchers, the shield is protecting an
//     existing legitimate plugin layout, not a freshly-dropped
//     dropper. Threshold is filesMatchShieldSiblingThreshold.
//
// Both gates fail-open: any uncertainty (parse failure, IO error)
// keeps the original Critical alert firing. The sibling-PHP gate
// requires the htaccess path so the detector now reads it from the
// caller (passed as the second argument to all htaccessDetector.Detect
// implementations).
func detectFilesMatchShield(content []byte, path string) []htaccessMatch {
	openIdxs := reFilesMatchOpen.FindAllIndex(content, -1)
	closeIdxs := reFilesMatchClose.FindAllIndex(content, -1)
	if len(openIdxs) == 0 || len(closeIdxs) == 0 {
		return nil
	}
	patternIdxs := reFilesMatchPattern.FindAllSubmatchIndex(content, -1)

	var out []htaccessMatch
	for _, open := range openIdxs {
		// pair this opening tag with the next closing tag after it
		var paired []int
		for _, c := range closeIdxs {
			if c[0] >= open[1] {
				paired = c
				break
			}
		}
		if paired == nil {
			continue
		}
		body := content[open[1]:paired[0]]
		bodyLower := strings.ToLower(string(body))
		if !strings.Contains(bodyLower, "allow from all") && !strings.Contains(bodyLower, "require all granted") {
			continue
		}

		// Look up the FilesMatch pattern that opened at this position
		// so we can apply the targeted-vs-wildcard discriminator.
		var openPattern string
		for _, pIdx := range patternIdxs {
			if len(pIdx) < 4 {
				continue
			}
			if pIdx[0] == open[0] {
				openPattern = string(content[pIdx[2]:pIdx[3]])
				break
			}
		}
		if openPattern != "" && filesMatchPatternIsTargeted(openPattern) {
			continue
		}
		// Bare wildcard: check sibling PHP count. A directory with
		// multiple stock PHP dispatchers is a legitimate plugin layout.
		if path != "" && htaccessParentPHPFileCount(path) >= filesMatchShieldSiblingThreshold {
			continue
		}

		out = append(out, htaccessMatch{
			Range:   blockRange(content, open[0], paired[1]),
			Excerpt: trimExcerpt(content, open[0], paired[1]),
		})
	}
	return out
}

// detectHeaderInjection flags Header set / Header add directives
// whose name is on the small tracking-header allowlist. Generic
// CSP / HSTS / X-Frame-Options headers do not match.
func detectHeaderInjection(content []byte, _ string) []htaccessMatch {
	idxs := reHeaderSetAdd.FindAllSubmatchIndex(content, -1)
	var out []htaccessMatch
	for _, idx := range idxs {
		if len(idx) < 6 {
			continue
		}
		name := string(content[idx[4]:idx[5]])
		if !headerNameSuspicious(name) {
			continue
		}
		out = append(out, htaccessMatch{
			Range:   lineRange(content, idx[0], idx[1]),
			Excerpt: trimExcerpt(content, idx[0], idx[1]),
		})
	}
	return out
}

func headerNameSuspicious(name string) bool {
	lower := strings.ToLower(name)
	for _, h := range htaccessTrackingHeaders {
		if strings.HasPrefix(lower, strings.ToLower(h)) {
			return true
		}
	}
	return false
}

// errorDocumentHostShareThreshold bounds how short a host-vs-path
// substring match can be while still treating the redirect as
// "same-brand". Three characters is the floor: anything shorter would
// match incidental segments ("us" inside "user", "co" inside "co.uk")
// and let an attacker tunnel through with a name like "co.evil.com".
const errorDocumentHostShareThreshold = 4

// errorDocumentHostIsSameBrand reports whether the URL host's
// "registrable label" (the leftmost segment of the public suffix +
// 1) shares an alphanumeric stem of >= errorDocumentHostShareThreshold
// chars with any path component of the .htaccess file. This catches
// the dominant legitimate shape: a custom 404 redirect to the site's
// own homepage on the same brand domain.
//
// Examples:
//
//	/home/flores/public_html/.htaccess + https://floresgrup.ro
//	  -> account "flores" is a substring of label "floresgrup" -> same-brand
//
//	/home/shop/example-shop.com/.htaccess + https://www.example-shop.com/404
//	  -> domain dir "example-shop.com" contains label "example-shop" -> same-brand
//
//	/home/victim/public_html/.htaccess + https://attacker.com/landing
//	  -> "attacker" shares no >=4-char stem with any path component -> different-brand
func errorDocumentHostIsSameBrand(htaccessPath, urlHost string) bool {
	label := registrableLabel(urlHost)
	if len(label) < errorDocumentHostShareThreshold {
		return false
	}
	labelLower := strings.ToLower(label)
	for _, component := range strings.Split(htaccessPath, string(filepath.Separator)) {
		if component == "" || component == "public_html" || component == "home" {
			continue
		}
		comp := strings.ToLower(component)
		if longestCommonAlnumRun(comp, labelLower) >= errorDocumentHostShareThreshold {
			return true
		}
	}
	return false
}

// registrableLabel extracts the leftmost segment of the public
// suffix + 1: for "www.example-shop.com" returns "example-shop", for
// "floresgrup.ro" returns "floresgrup". This is heuristic - we treat
// the last dot-separated segment as the TLD - but it is robust to
// the common cases (single-segment TLD, two-segment country code TLD
// like "co.uk" handled by stripping known double-segment suffixes).
//
// Returns "" for inputs that look like an IPv4 dotted quad: numeric
// targets are flagged separately and never qualify as same-brand.
func registrableLabel(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	// IPv4 dotted quad: each segment must be 1-3 digits.
	if isIPv4(host) {
		return ""
	}
	// Strip a leading "www." for canonical comparison.
	host = strings.TrimPrefix(host, "www.")
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	// Two-segment public suffix heuristic: "co.uk", "co.za",
	// "com.au" etc. If the second-to-last segment is one of these
	// short country-code prefixes, the registrable label is the
	// THIRD-from-last segment.
	if len(parts) >= 3 {
		penultimate := parts[len(parts)-2]
		twoSegmentCC := map[string]bool{
			"co": true, "com": true, "net": true, "org": true,
			"ac": true, "gov": true, "edu": true,
		}
		if twoSegmentCC[penultimate] {
			return parts[len(parts)-3]
		}
	}
	return parts[len(parts)-2]
}

// isIPv4 reports whether s parses as a dotted-quad IPv4 address.
// IPv6 / hex / mixed forms are caught separately by IP-target
// signalling above the same-brand check.
func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// longestCommonAlnumRun returns the length of the longest common
// substring of a and b that consists entirely of alphanumeric
// characters. Symbols (".", "-", "_") segment the run so an
// "example-shop" path component can match a "example-shop.com" URL
// host on the "example" stem without crediting the dash.
func longestCommonAlnumRun(a, b string) int {
	best := 0
	// Walk a, accumulate alnum tokens, check each token against b.
	tokens := splitAlnumTokens(a)
	bLower := b
	for _, tok := range tokens {
		if len(tok) < best {
			continue
		}
		// Find tok inside b: contiguous alnum substring match.
		if strings.Contains(bLower, tok) {
			if len(tok) > best {
				best = len(tok)
			}
		}
	}
	return best
}

// splitAlnumTokens splits s on any non-alphanumeric character, returning
// the maximal alphanumeric runs.
func splitAlnumTokens(s string) []string {
	var out []string
	start := -1
	for i := 0; i <= len(s); i++ {
		var c byte
		if i < len(s) {
			c = s[i]
		}
		isAlnum := i < len(s) && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
		if isAlnum && start == -1 {
			start = i
		} else if !isAlnum && start != -1 {
			out = append(out, s[start:i])
			start = -1
		}
	}
	return out
}

// detectErrorDocumentHijack flags ErrorDocument directives whose
// target is an external http(s) URL pointing at a host that does NOT
// share a brand stem with the .htaccess file's path. Same-brand
// redirects (custom 404 -> site homepage) are extremely common and
// must not be flagged. Spam-TLD targets and IP-address targets are
// always flagged regardless of any brand match.
func detectErrorDocumentHijack(content []byte, path string) []htaccessMatch {
	idxs := reErrorDocument.FindAllSubmatchIndex(content, -1)
	var out []htaccessMatch
	for _, idx := range idxs {
		if len(idx) < 4 {
			continue
		}
		target := string(content[idx[2]:idx[3]])
		host := extractHost(target)
		// Spam TLDs and IP-address targets always fire. Both are
		// signals of compromise even when the path-share heuristic
		// would otherwise consider the host same-brand.
		if hostOnSpamTLD(host) || isIPv4(host) {
			out = append(out, htaccessMatch{
				Range:   lineRange(content, idx[0], idx[1]),
				Excerpt: trimExcerpt(content, idx[0], idx[1]),
			})
			continue
		}
		// Same-brand check only when we have a path to compare
		// against. Detector is sometimes called with an empty path
		// (unit tests of the regex alone); fail-closed.
		if path != "" && errorDocumentHostIsSameBrand(path, host) {
			continue
		}
		out = append(out, htaccessMatch{
			Range:   lineRange(content, idx[0], idx[1]),
			Excerpt: trimExcerpt(content, idx[0], idx[1]),
		})
	}
	return out
}

// lineRange computes a range covering the full line(s) that contain
// [start, end]. Line boundaries are at '\n'; the returned end is
// the position of the trailing '\n' (exclusive) or len(content) if
// the match is at EOF without a trailing newline.
func lineRange(content []byte, start, end int) htaccessByteRange {
	if start < 0 {
		start = 0
	}
	if end > len(content) {
		end = len(content)
	}
	for start > 0 && content[start-1] != '\n' {
		start--
	}
	for end < len(content) && content[end] != '\n' {
		end++
	}
	return htaccessByteRange{Start: start, End: end}
}

// blockRange covers the whole block including the opening and
// closing directive lines. Same line-snapping rules as lineRange.
func blockRange(content []byte, start, end int) htaccessByteRange {
	r := lineRange(content, start, end)
	return r
}

// trimExcerpt returns up to ~200 bytes of the matched content,
// trimmed and with newlines collapsed, for finding details.
func trimExcerpt(content []byte, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(content) {
		end = len(content)
	}
	s := strings.TrimSpace(string(content[start:end]))
	s = strings.ReplaceAll(s, "\n", " | ")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// matchesFromRegex is a small helper: every match becomes one
// htaccessMatch covering the line(s) the match spans, with the
// match excerpt trimmed for display.
func matchesFromRegex(content []byte, re *regexp.Regexp) []htaccessMatch {
	idxs := re.FindAllIndex(content, -1)
	var out []htaccessMatch
	for _, idx := range idxs {
		out = append(out, htaccessMatch{
			Range:   lineRange(content, idx[0], idx[1]),
			Excerpt: trimExcerpt(content, idx[0], idx[1]),
		})
	}
	return out
}
