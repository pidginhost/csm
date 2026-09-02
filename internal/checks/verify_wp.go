package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/contenttype"
	"github.com/pidginhost/csm/internal/store"
)

// wpVerifyAllowedRoots bounds where a WordPress re-check may run wp-cli. It is a
// var so tests can redirect under t.TempDir(); nil means the platform's
// account roots.
var wpVerifyAllowedRoots []string

// wpVerifyTimeout bounds the synchronous wp-cli re-scan a Re-check click runs.
const wpVerifyTimeout = 30 * time.Second

// findingDetailPath extracts the "Path: <dir>" value emitted in a finding's
// Details (outdated_plugins and the WordPress checks record the install path
// there). Returns "" when no such line is present.
func findingDetailPath(details string) string {
	for _, line := range strings.Split(details, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "Path:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

func wpChecksumLineHasExtraneousCoreFile(line string) bool {
	return strings.Contains(line, "should not exist") && !strings.Contains(line, "error_log")
}

// The two per-file shapes wp-cli has used. The closing summary line
// ("WordPress installation doesn't verify against checksums.") matches
// neither: the current shape needs the colon and the legacy one the singular
// "checksum." directly after the file name.
const (
	wpChecksumMismatchCurrent = "doesn't verify against checksum: "
	wpChecksumMismatchLegacy  = " doesn't verify against checksum."
)

// wpChecksumModifiedCoreFile returns the install-relative path of a core file
// that wp-cli reports as changed, or "" when the line is not such a report.
// Localised packages legitimately ship their own root readme and license,
// which carry no code, so those two are not reported.
func wpChecksumModifiedCoreFile(line string) string {
	var rel string
	if idx := strings.Index(line, wpChecksumMismatchCurrent); idx >= 0 {
		rel = strings.TrimSpace(line[idx+len(wpChecksumMismatchCurrent):])
	} else if idx := strings.Index(line, wpChecksumMismatchLegacy); idx >= 0 {
		if fields := strings.Fields(line[:idx]); len(fields) > 0 {
			rel = fields[len(fields)-1]
		}
	}
	if rel == "" || rel == "readme.html" || rel == "license.txt" {
		return ""
	}
	return rel
}

// wpCoreModifiedSeverity grades a modified core file by what an attacker could
// do with it.
//
// Critical is what auto-response acts on, so it is reserved for files that can
// carry executable content to a visitor: anything a PHP handler runs, and the
// scripts and templates served into the browser. Everything else -- stylesheets,
// images, translations, fonts -- still gets a finding, but a mismatch there is
// far more often an asset optimiser or an install whose version.php no longer
// names the release its files came from than it is an appended backdoor.
func wpCoreModifiedSeverity(path, rel string) alert.Severity {
	if contenttype.IsExecutablePHPName(strings.ToLower(rel)) {
		return alert.Critical
	}
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".js", ".mjs", ".html", ".htm", ".htaccess":
		return alert.Critical
	case ".svg", ".xml", ".xhtml":
		// Markup, not an image format: SVG carries <script> and event
		// handlers and the browser runs them. Judge it by what it holds,
		// because most core SVG mismatches are an optimiser's whitespace.
		if wpCoreMarkupIsActive(path) {
			return alert.Critical
		}
	}
	return alert.High
}

// wpCoreMarkupActiveMarkers are the element-level constructs that make markup
// executable. Event attributes are matched separately: SVG defines dozens of
// them, so any list of names would really be a list of the ones an attacker
// has to avoid.
var wpCoreMarkupActiveMarkers = []string{
	"<script", "javascript:", "<foreignobject", "<!entity", "<handler",
	"<animate", "<set ", "<use ", "data:text/html",
}

// wpCoreMarkupEventAttr matches any on<name>= handler attribute.
var wpCoreMarkupEventAttr = regexp.MustCompile(`(?i)\bon[a-z]+\s*=`)

// wpCoreMarkupPeekBytes bounds the read. A shipped core asset is far smaller;
// anything larger is judged active without reading further, because the part
// that was not read is exactly where content would be hidden.
const wpCoreMarkupPeekBytes = 256 << 10

// wpCoreMarkupIsActive reports whether a markup file carries anything the
// browser would execute.
//
// Every uncertain answer is "active": an unreadable file, one larger than the
// peek, a path raced to something that is not a regular file. None of those is
// evidence of innocence, and the point of the grade is that a core asset which
// cannot be shown inert keeps the higher severity.
func wpCoreMarkupIsActive(path string) bool {
	if path == "" {
		return true
	}
	info, err := osFS.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > wpCoreMarkupPeekBytes {
		return true
	}

	// The path is in a tenant-writable tree, so it can be raced to a FIFO
	// between the report and this read. Use the non-blocking, O_NOFOLLOW,
	// regular-file-verified reader rather than a plain open.
	reader, ok := osFS.(phpRegularFilePrefixReader)
	if !ok {
		return true
	}
	body, err := reader.ReadRegularFilePrefix(path, info, wpCoreMarkupPeekBytes)
	if err != nil {
		return true
	}

	lower := strings.ToLower(string(body))
	for _, marker := range wpCoreMarkupActiveMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return wpCoreMarkupEventAttr.MatchString(lower)
}

// wpCoreFilePathWithin joins a wp-cli reported relative path onto the install
// only when it stays inside it; wp-cli output is not a path oracle for the
// remediation and Re-check code that consumes FilePath.
func wpCoreFilePathWithin(wpPath, rel string) string {
	clean := filepath.Clean(rel)
	if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return ""
	}
	return filepath.Join(wpPath, clean)
}

// verifyOutdatedPlugins re-inventories a single WordPress site with wp-cli (run
// as the site owner) and resolves the finding when no active plugin still has
// an available update. It is heavier than the file re-checks but read-only and
// bounded by wpVerifyTimeout. Any failure to re-scan returns Checked:false so a
// finding is never falsely cleared on a transient wp-cli error.
func verifyOutdatedPlugins(details string) VerifyResult {
	wpPath := findingDetailPath(details)
	if wpPath == "" {
		return VerifyResult{Checked: false, Detail: "could not determine the WordPress path from the finding"}
	}
	clean, _, exists, err := readOnlyFixPath(wpPath, effectiveFixRoots(wpVerifyAllowedRoots))
	if err != nil {
		return VerifyResult{Checked: false, Detail: err.Error()}
	}
	if !exists {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("WordPress install no longer exists: %s", clean)}
	}

	wpConfig, info, exists, err := readOnlyFixPath(filepath.Join(clean, "wp-config.php"), effectiveFixRoots(wpVerifyAllowedRoots))
	if err != nil {
		return VerifyResult{Checked: false, Detail: err.Error()}
	}
	if !exists {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("WordPress install no longer present: %s", clean)}
	}
	if !info.Mode().IsRegular() {
		return VerifyResult{Checked: false, Detail: "wp-config.php path is not a regular file; not auto-verifiable"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), wpVerifyTimeout)
	defer cancel()
	site, err := inventoryWPSiteForVerify(ctx, wpConfig)
	if err != nil {
		return VerifyResult{Checked: false, Detail: fmt.Sprintf("could not re-scan plugins (try again, or run an account scan): %v", err)}
	}

	if n := countOutdatedActivePlugins(site, store.Global()); n > 0 {
		return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("%d active plugin(s) still outdated", n)}
	}
	return VerifyResult{Checked: true, Resolved: true, Detail: "no active plugins are outdated anymore"}
}

// verifyWPCoreIntegrity re-runs `wp core verify-checksums` for one install and
// resolves the finding when no extraneous core file ("should not exist")
// remains -- mirroring CheckWPCore, which only flags those lines. It is
// read-only and bounded by wpVerifyTimeout. To avoid ever clearing a real
// compromise it resolves only when verification is clean or the install is
// gone; any wp-cli error (including modified files with no remaining
// extra-file line) returns Checked:false.
func verifyWPCoreIntegrity(details string) VerifyResult {
	wpPath := findingDetailPath(details)
	if wpPath == "" {
		return VerifyResult{Checked: false, Detail: "could not determine the WordPress path from the finding"}
	}
	clean, _, exists, err := readOnlyFixPath(wpPath, effectiveFixRoots(wpVerifyAllowedRoots))
	if err != nil {
		return VerifyResult{Checked: false, Detail: err.Error()}
	}
	if !exists {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("WordPress install no longer exists: %s", clean)}
	}
	_, info, exists, err := readOnlyFixPath(filepath.Join(clean, "wp-config.php"), effectiveFixRoots(wpVerifyAllowedRoots))
	if err != nil {
		return VerifyResult{Checked: false, Detail: err.Error()}
	}
	if !exists {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("WordPress install no longer present: %s", clean)}
	}
	if !info.Mode().IsRegular() {
		return VerifyResult{Checked: false, Detail: "wp-config.php path is not a regular file; not auto-verifiable"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), wpVerifyTimeout)
	defer cancel()
	// Mirrors CheckWPCore: run as root with --allow-root (not su as the user).
	// Args are passed directly (no shell), so the sanitized path cannot inject.
	out, err := cmdExec.RunContext(ctx, "wp", "core", "verify-checksums", "--path="+clean, "--allow-root")
	if err == nil {
		return VerifyResult{Checked: true, Resolved: true, Detail: "WordPress core checksums verify clean"}
	}
	if len(out) == 0 {
		return VerifyResult{Checked: false, Detail: "could not run wp core verify-checksums (try again, or run an account scan)"}
	}
	for _, line := range strings.Split(string(out), "\n") {
		if wpChecksumLineHasExtraneousCoreFile(line) {
			return VerifyResult{Checked: true, Resolved: false, Detail: "WordPress core still has extraneous files"}
		}
		if wpChecksumModifiedCoreFile(line) != "" {
			return VerifyResult{Checked: true, Resolved: false, Detail: "WordPress core still has modified files"}
		}
	}
	// Non-zero exit with neither an extraneous nor a modified file named: a
	// wp-cli error we cannot interpret. Do not resolve.
	return VerifyResult{Checked: false, Detail: "could not confirm core integrity (verify-checksums reported other issues); re-run or use an account scan"}
}
