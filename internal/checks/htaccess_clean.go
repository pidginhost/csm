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
var htaccessNonScriptDirHints = []string{
	"/uploads/", "/images/", "/cache/", "/tmp/",
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
	// #nosec G306 -- backup of an .htaccess; 0640 is the same group-readable mode used elsewhere in pre_clean/.
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
	// #nosec G306 -- .htaccess rewritten for a user's web root; 0644 is the mode the webserver expects.
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

// detectUserAgentCloak flags RewriteCond %{HTTP_USER_AGENT}
// directives that match a known crawler UA. Cleaning removes the
// individual line; if the next line is a paired RewriteRule, the
// adjacent-range merge in mergeRanges will collapse them when both
// detectors fire.
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

// detectFilesMatchShield finds <FilesMatch ...\.php(tml)?> blocks
// that grant Allow from all or Require all granted -- the canonical
// "let everyone execute everything we just dropped" pattern. The
// returned range covers the full block, opening tag through closing
// tag inclusive.
func detectFilesMatchShield(content []byte, _ string) []htaccessMatch {
	openIdxs := reFilesMatchOpen.FindAllIndex(content, -1)
	closeIdxs := reFilesMatchClose.FindAllIndex(content, -1)
	if len(openIdxs) == 0 || len(closeIdxs) == 0 {
		return nil
	}
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

// detectErrorDocumentHijack flags ErrorDocument directives whose
// target is an external http(s) URL. Apache is happy to redirect
// for any status code; attackers chain this to phishing pages.
func detectErrorDocumentHijack(content []byte, _ string) []htaccessMatch {
	idxs := reErrorDocument.FindAllSubmatchIndex(content, -1)
	var out []htaccessMatch
	for _, idx := range idxs {
		if len(idx) < 4 {
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
