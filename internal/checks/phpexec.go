package checks

import (
	"strings"
)

// executablePHPExtensions are the extensions a stock PHP-capable web server
// (Apache mod_php / PHP-FPM via EasyApache4, LiteSpeed LSAPI, Nginx + php-fpm)
// routes to the PHP interpreter by default. Any file with one of these names
// can execute PHP, so a content scan that skipped them would let a webshell
// hide behind a non-".php" name. ".phps" is deliberately excluded: the stock
// handler renders it as highlighted source, it does not execute. Lowercase,
// leading dot.
var executablePHPExtensions = []string{
	".php", ".php2", ".php3", ".php4", ".php5", ".php6", ".php7", ".php8",
	".phtml", ".pht",
}

// IsExecutablePHPName reports whether a (lowercased) filename has an extension
// that a stock PHP handler executes. Shared by the realtime fanotify path and
// the periodic content scanners so the two never drift apart. It is a coarse,
// default-deny gate for content analysis only; per-directory .htaccess handler
// remappings are layered on top via phpHandlerOverlay.
func IsExecutablePHPName(nameLower string) bool {
	return isExecutablePHPName(nameLower)
}

func isExecutablePHPName(nameLower string) bool {
	for _, ext := range executablePHPExtensions {
		if strings.HasSuffix(nameLower, ext) {
			return true
		}
	}
	return false
}

// phpHandlerOverlay carries the extra PHP execution mappings discovered from
// .htaccess files while walking a directory tree. Apache merges a parent
// directory's directives into its children, so the overlay accumulates down
// the recursion: a mapping declared in a parent applies to every descendant.
type phpHandlerOverlay struct {
	// exts holds extra ".ext" entries (lowercase, leading dot) that a local
	// AddHandler/AddType maps to a PHP handler, e.g. "AddHandler
	// application/x-httpd-php .inc".
	exts map[string]struct{}
	// scanAll is set when a SetHandler/ForceType routes the PHP interpreter
	// for the whole directory with no extension filter. Every file in the
	// subtree then executes as PHP and must be content-analysed.
	scanAll bool
}

// executes reports whether a file named nameLower (lowercased) runs as PHP
// under this overlay, either by a stock extension, a directory-wide handler,
// or an .htaccess-mapped extension.
func (o phpHandlerOverlay) executes(nameLower string) bool {
	if o.scanAll {
		return true
	}
	if isExecutablePHPName(nameLower) {
		return true
	}
	for ext := range o.exts {
		if strings.HasSuffix(nameLower, ext) {
			return true
		}
	}
	return false
}

// mergeHtaccess returns a new overlay combining the receiver (inherited from
// the parent directory) with any PHP handler directives found in the .htaccess
// at dirHtaccessContent. The receiver is never mutated, so sibling directories
// do not see each other's mappings.
func (o phpHandlerOverlay) mergeHtaccess(content []byte) phpHandlerOverlay {
	if len(content) == 0 {
		return o
	}
	exts, scanAll := parsePHPHandlerDirectives(content)
	if len(exts) == 0 && !scanAll {
		return o
	}

	merged := phpHandlerOverlay{scanAll: o.scanAll || scanAll}
	if len(o.exts) > 0 || len(exts) > 0 {
		merged.exts = make(map[string]struct{}, len(o.exts)+len(exts))
		for e := range o.exts {
			merged.exts[e] = struct{}{}
		}
		for _, e := range exts {
			merged.exts[e] = struct{}{}
		}
	}
	return merged
}

// parsePHPHandlerDirectives extracts extension-to-PHP mappings from .htaccess
// content. It recognises:
//
//	AddHandler <php-handler> .ext [.ext...]
//	AddType    <php-mime>    .ext [.ext...]
//	SetHandler <php-handler>            (no extension -> whole directory)
//	ForceType  <php-mime>               (no extension -> whole directory)
//
// A directive counts as PHP only when its handler/MIME token contains "php"
// (e.g. application/x-httpd-php, php5-script, x-httpd-php-source is excluded
// because it ends in -source... we keep it simple and conservative: any token
// containing "php" except the source viewer). Matching is case-insensitive.
func parsePHPHandlerDirectives(content []byte) (exts []string, scanAll bool) {
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		directive := strings.ToLower(fields[0])
		handler := strings.ToLower(fields[1])

		switch directive {
		case "addhandler", "addtype":
			if !handlerIsPHP(handler) {
				continue
			}
			// Remaining fields are extensions.
			for _, f := range fields[2:] {
				if ext := normalizeExt(f); ext != "" {
					exts = append(exts, ext)
				}
			}
		case "sethandler", "forcetype":
			if !handlerIsPHP(handler) {
				continue
			}
			// No extension filter: the handler applies to every file in the
			// directory. If extensions are present anyway, honour them too.
			if len(fields) == 2 {
				scanAll = true
				continue
			}
			for _, f := range fields[2:] {
				if ext := normalizeExt(f); ext != "" {
					exts = append(exts, ext)
				}
			}
		}
	}
	return exts, scanAll
}

func handlerIsPHP(token string) bool {
	if !strings.Contains(token, "php") {
		return false
	}
	// The source viewer renders highlighted source instead of executing.
	if strings.Contains(token, "php-source") {
		return false
	}
	return true
}

// normalizeExt turns an .htaccess extension token into a lowercase
// leading-dot extension, rejecting anything that is not a plain extension
// token (e.g. a stray flag or MIME fragment).
func normalizeExt(token string) string {
	t := strings.ToLower(strings.TrimSpace(token))
	t = strings.TrimPrefix(t, ".")
	if t == "" {
		return ""
	}
	for _, r := range t {
		alnum := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if !alnum && r != '_' && r != '-' {
			return ""
		}
	}
	return "." + t
}
