package checks

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// timThumbFixedVersion is the last TimThumb release. The project was abandoned
// in 2014; anything below this carries the CVE-2011-4106 remote-code-execution
// bug that let attackers write PHP into the image cache -- the entry vector in
// the 2026-07-20 cross-account compromise.
const timThumbFixedVersion = "2.8.14"

// timThumbReadHead bounds how much of each candidate file is read: the version
// define and feature constants are always near the top.
const timThumbReadHead = 16 * 1024

// timThumbScanDepth bounds the per-docroot recursive descent. TimThumb ships
// bundled in themes, sometimes several directories deep (framework/scripts).
const timThumbScanDepth = 10

var timThumbVersionRE = regexp.MustCompile(`(?i)define\s*\(\s*['"]VERSION['"]\s*,\s*['"]([0-9]+(?:\.[0-9]+)*)['"]`)

// timThumbCandidateName reports whether a filename is a TimThumb-style script by
// convention. Content confirmation happens in looksLikeTimThumb.
func timThumbCandidateName(nameLower string) bool {
	return nameLower == "timthumb.php" || nameLower == "thumb.php"
}

// looksLikeTimThumb confirms a file is actually TimThumb rather than an
// unrelated theme thumbnail helper. It keys on constants unique to TimThumb so
// a generic thumb.php is never flagged.
func looksLikeTimThumb(head []byte) bool {
	lower := bytes.ToLower(head)
	if bytes.Contains(lower, []byte("timthumb")) {
		return true
	}
	// Older or renamed copies without the header name still carry these
	// TimThumb-specific configuration constants.
	if bytes.Contains(lower, []byte("block_external_leechers")) &&
		(bytes.Contains(lower, []byte("webshot")) || bytes.Contains(lower, []byte("allow_external"))) {
		return true
	}
	return false
}

// parseTimThumbVersion extracts the value of TimThumb's VERSION define, or ""
// when it is absent.
func parseTimThumbVersion(head []byte) string {
	m := timThumbVersionRE.FindSubmatch(head)
	if m == nil {
		return ""
	}
	return string(m[1])
}

// timThumbVersionLess reports whether dotted numeric version a is older than b.
func timThumbVersionLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var av, bv int
		if i < len(as) {
			av, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			bv, _ = strconv.Atoi(bs[i])
		}
		if av != bv {
			return av < bv
		}
	}
	return false
}

// assessTimThumb grades a confirmed TimThumb file. A version below the last
// patched release (or an unparseable one) carries the known RCE and is High; a
// patched-but-abandoned copy is a Warning to remove.
func assessTimThumb(head []byte) (alert.Severity, []string) {
	var reasons []string
	version := parseTimThumbVersion(head)
	exploitable := false
	switch {
	case version == "":
		reasons = append(reasons, "version could not be determined")
		exploitable = true
	case timThumbVersionLess(version, timThumbFixedVersion):
		reasons = append(reasons, fmt.Sprintf("version %s predates the last patch %s (CVE-2011-4106 remote code execution)", version, timThumbFixedVersion))
		exploitable = true
	default:
		reasons = append(reasons, fmt.Sprintf("version %s is deprecated and unmaintained", version))
	}
	if timThumbFeatureEnabled(head, "WEBSHOT_ENABLED") {
		reasons = append(reasons, "WebShot feature is enabled (remote command execution)")
		exploitable = true
	}
	if timThumbFeatureEnabled(head, "ALLOW_EXTERNAL") {
		reasons = append(reasons, "external image fetching is enabled (SSRF and cache-poisoning surface)")
		exploitable = true
	}
	if exploitable {
		return alert.High, reasons
	}
	return alert.Warning, reasons
}

// timThumbFeatureEnabled reports whether a TimThumb boolean constant is defined
// true. Matches define('NAME', true) with optional whitespace.
func timThumbFeatureEnabled(head []byte, name string) bool {
	re := regexp.MustCompile(`(?i)define\s*\(\s*['"]` + regexp.QuoteMeta(name) + `['"]\s*,\s*true\s*\)`)
	return re.Match(head)
}

// CheckVulnerableTimThumb scans web document roots for bundled TimThumb scripts
// and reports each confirmed instance. Detection-only: TimThumb is legitimate
// (if abandoned) code, so it is never auto-quarantined -- removing it would
// break the theme.
func CheckVulnerableTimThumb(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if ctx == nil {
		ctx = context.Background()
	}
	var findings []alert.Finding
	homeDirs, _ := GetScanHomeDirs(ctx)
	for _, homeEntry := range homeDirs {
		if ctx.Err() != nil {
			return findings
		}
		if !homeEntry.IsDir() {
			continue
		}
		homeDir := filepath.Join("/home", homeEntry.Name())
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
			scanForTimThumb(ctx, docRoot, timThumbScanDepth, &findings)
			if ctx.Err() != nil {
				return findings
			}
		}
	}
	return findings
}

// scanForTimThumb recursively walks dir for TimThumb scripts and appends a
// finding per confirmed instance.
func scanForTimThumb(ctx context.Context, dir string, maxDepth int, findings *[]alert.Finding) {
	if ctx.Err() != nil || maxDepth <= 0 {
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
		if entry.IsDir() {
			scanForTimThumb(ctx, fullPath, maxDepth-1, findings)
			continue
		}
		if !timThumbCandidateName(strings.ToLower(name)) {
			continue
		}
		head := readFileHead(fullPath, timThumbReadHead)
		if head == nil || !looksLikeTimThumb(head) {
			continue
		}
		severity, reasons := assessTimThumb(head)
		*findings = append(*findings, alert.Finding{
			Severity: severity,
			Check:    "vulnerable_timthumb",
			Message:  fmt.Sprintf("Vulnerable TimThumb image resizer: %s", fullPath),
			Details:  "Remove or replace it. " + strings.Join(reasons, "; ") + ".",
			FilePath: fullPath,
		})
	}
}
