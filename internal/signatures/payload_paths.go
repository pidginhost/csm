package signatures

import (
	"regexp"
	"strings"

	"github.com/pidginhost/csm/internal/contenttype"
)

// maxReferencedPayloadPaths bounds how many payload paths one finding carries.
// Findings travel through alert mail, the audit log and webhooks, so a file
// holding hundreds of include statements must not turn one alert into an
// unbounded message.
const maxReferencedPayloadPaths = 5

// referencedPayloadWindow is how far a quoted path may sit from the
// include/require keyword that consumes it. The keyword and the literal are
// usually in the same statement; a local assigned one line earlier and
// included on the next is the shape the 2026-09-17 loader used.
const referencedPayloadWindow = 300

// nonExecutablePayloadLiteral matches a quoted path whose extension belongs to
// an image, archive or opaque data file. The extension list mirrors the one in
// the backdoor_include_nonexecutable rules; source partials (.php, .html,
// .tpl, .svg) are deliberately absent, because including those is templating.
var nonExecutablePayloadLiteral = regexp.MustCompile(
	`(?i)['"]([^'"\r\n]{1,240}\.(?:png|jpe?g|gif|bmp|ico|cur|webp|tiff?|zip|rar|tar|gz|bz2|7z|txt|log|dat|bin|cache|bak|old|csv|pdf|woff2?|ttf|eot|otf))['"]`,
)

// includeKeyword matches a PHP inclusion keyword in statement position.
var includeKeyword = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_$>])(?:include|require)(?:_once)?[\s(]`)

// ReferencedPayloadPaths returns the non-executable files that PHP content
// pulls in through include or require, in the order they appear and without
// duplicates.
//
// A loader finding names the PHP file that changed. The payload lives
// somewhere else -- in the incident that prompted this, a picture in a plugin
// asset directory two levels away -- and survives a clean-up of the PHP alone,
// so the finding has to name it too.
//
// Association is positional. RE2 cannot prove that the local assigned a path
// is the same local an include consumes, so a quoted payload path counts when
// an inclusion keyword sits within referencedPayloadWindow bytes of it. The
// output is remediation context attached to a finding that already fired, not
// a detection signal.
func ReferencedPayloadPaths(content []byte) []string {
	// Module loaders spell require and include too, and a JavaScript bundle
	// pulling in a sprite is not a loader for a hidden payload.
	if !contenttype.HasPHPOpenTag(content) {
		return nil
	}
	keywords := includeKeyword.FindAllIndex(content, -1)
	if len(keywords) == 0 {
		return nil
	}

	var paths []string
	seen := make(map[string]bool)
	for _, literal := range nonExecutablePayloadLiteral.FindAllSubmatchIndex(content, -1) {
		if !nearKeyword(keywords, literal[0], literal[1]) {
			continue
		}
		path := string(content[literal[2]:literal[3]])
		if seen[path] {
			continue
		}
		seen[path] = true
		paths = append(paths, path)
		if len(paths) == maxReferencedPayloadPaths {
			break
		}
	}
	return paths
}

// nearKeyword reports whether any keyword occurrence overlaps the window
// around [start, end). Matches arrive in offset order, so the scan stops at
// the first keyword past the window instead of walking every occurrence in a
// large file for every literal in it.
func nearKeyword(keywords [][]int, start, end int) bool {
	for _, keyword := range keywords {
		if keyword[0] >= end+referencedPayloadWindow {
			return false
		}
		if keyword[1] > start-referencedPayloadWindow {
			return true
		}
	}
	return false
}

// ReferencedPayloadDetail renders ReferencedPayloadPaths as a line to append
// to a finding's details, or an empty string when the content pulls in no
// non-executable file. Callers concatenate it unconditionally.
func ReferencedPayloadDetail(content []byte) string {
	paths := ReferencedPayloadPaths(content)
	if len(paths) == 0 {
		return ""
	}
	return "\nIncluded payload files: " + strings.Join(paths, ", ")
}
