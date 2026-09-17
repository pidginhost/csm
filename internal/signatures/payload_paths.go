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
// .tpl, .txt, .svg) are deliberately absent, because including those is templating.
var nonExecutablePayloadLiteral = regexp.MustCompile(
	`(?i)['"]([^'"\r\n]{1,240}\.(?:png|jp(?:eg?|g)|gif|bmp|ico|cur|webp|tiff?|zip|rar|tar|gz|bz2|7z|log|dat|bin|cache|bak|old|csv|pdf|woff2?|ttf|eot|otf))['"]`,
)

// includeKeyword matches a PHP inclusion keyword in statement position.
var includeKeyword = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_$>])(?:include|require)(?:_once)?[\s('$"]`)

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
	keyword := includeKeyword.FindIndex(content)
	if keyword == nil {
		return nil
	}

	var paths []string
	seen := make(map[string]bool)
	// Advance both cursors monotonically. Materializing every match before
	// enforcing the output cap wastes memory; restarting the keyword search
	// for each repeated literal makes enrichment quadratic on hostile input.
	for offset := 0; offset < len(content); {
		literal := nonExecutablePayloadLiteral.FindSubmatchIndex(content[offset:])
		if literal == nil {
			break
		}
		for i := range literal {
			literal[i] += offset
		}
		offset = literal[1]
		for keyword[1] <= literal[0]-referencedPayloadWindow {
			next := keyword[1]
			keyword = includeKeyword.FindIndex(content[next:])
			if keyword == nil {
				return paths
			}
			keyword[0] += next
			keyword[1] += next
		}
		if keyword[0] >= literal[1]+referencedPayloadWindow {
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
