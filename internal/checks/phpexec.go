package checks

import (
	"path/filepath"
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
	// names holds exact lowercase basenames matched by a <Files> container.
	names map[string]struct{}
	// scanAll is set when a SetHandler/ForceType routes the PHP interpreter
	// for the whole directory with no extension filter. Every file in the
	// subtree then executes as PHP and must be content-analysed.
	scanAll bool
}

func (o phpHandlerOverlay) active() bool {
	return o.scanAll || len(o.exts) > 0 || len(o.names) > 0
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
	if _, ok := o.names[nameLower]; ok {
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
	parsed := parsePHPHandlerDirectives(content)
	if !parsed.active() {
		return o
	}

	merged := phpHandlerOverlay{scanAll: o.scanAll || parsed.scanAll}
	if len(o.exts) > 0 || len(parsed.exts) > 0 {
		merged.exts = make(map[string]struct{}, len(o.exts)+len(parsed.exts))
		for e := range o.exts {
			merged.exts[e] = struct{}{}
		}
		for e := range parsed.exts {
			merged.exts[e] = struct{}{}
		}
	}
	if len(o.names) > 0 || len(parsed.names) > 0 {
		merged.names = make(map[string]struct{}, len(o.names)+len(parsed.names))
		for name := range o.names {
			merged.names[name] = struct{}{}
		}
		for name := range parsed.names {
			merged.names[name] = struct{}{}
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
// A directive counts as PHP when its handler/MIME token names PHP directly or
// routes through proxy-fcgi. x-httpd-php-source is excluded because it renders
// highlighted source instead of executing. Matching is case-insensitive.
func parsePHPHandlerDirectives(content []byte) phpHandlerOverlay {
	var overlay phpHandlerOverlay
	var contexts []phpHandlerOverlay

	for _, logical := range joinHtaccessContinuations(strings.Split(string(content), "\n")) {
		line := strings.TrimSpace(logical.text)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if ctx, ok := openPHPHandlerContext(line); ok {
			contexts = append(contexts, ctx)
			continue
		}
		if closesPHPHandlerContext(line) {
			if len(contexts) > 0 {
				contexts = contexts[:len(contexts)-1]
			}
			continue
		}

		fields := apacheDirectiveFields(line)
		if len(fields) < 2 {
			continue
		}
		directive := strings.ToLower(fields[0])
		handler := fields[1]

		switch directive {
		case "addhandler", "addtype":
			if !handlerIsPHP(handler) {
				continue
			}
			// Remaining fields are extensions.
			addExtensions(&overlay, normalizedExts(fields[2:]))
			if len(fields) == 2 {
				mergeContext(&overlay, contexts)
			}
		case "sethandler", "forcetype":
			if !handlerIsPHP(handler) {
				continue
			}
			exts := normalizedExts(fields[2:])
			if len(exts) > 0 {
				addExtensions(&overlay, exts)
				continue
			}
			if mergeContext(&overlay, contexts) {
				continue
			}
			if len(contexts) > 0 {
				continue
			}
			// No extension or file filter: the handler applies to every
			// file in this directory.
			overlay.scanAll = true
		}
	}
	return overlay
}

func handlerIsPHP(token string) bool {
	token = strings.ToLower(strings.Trim(strings.TrimSpace(token), `"'`))
	// The source viewer renders highlighted source instead of executing.
	if strings.Contains(token, "php-source") {
		return false
	}
	if strings.Contains(token, "php") {
		return true
	}
	// cPanel/PHP-FPM .htaccess wiring can use a custom socket alias whose
	// path does not include the literal "php". A proxy-fcgi handler still
	// routes matching files to an executable backend, so remapped extensions
	// must be treated as PHP-executed for scanning and .htaccess alerts.
	return strings.HasPrefix(token, "proxy:") && strings.Contains(token, "fcgi://")
}

// normalizeExt turns an .htaccess extension token into a lowercase
// leading-dot extension, rejecting anything that is not a plain extension
// token (e.g. a stray flag or MIME fragment).
func normalizeExt(token string) string {
	t := strings.ToLower(strings.Trim(strings.TrimSpace(token), `"'`))
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

// htaccessLogicalLine is one Apache directive after joining physical
// continuation lines. text is the joined directive (continuation backslashes
// removed); lines are the original physical lines it spans, so a per-line
// rewrite can drop or keep them together. start is the 0-based index of the
// first physical line.
type htaccessLogicalLine struct {
	text  string
	lines []string
	start int
}

// joinHtaccessContinuations groups physical .htaccess lines into logical
// directives, honoring Apache's trailing-backslash line continuation: a line
// ending in "\" is joined with the next. Without this, a directive split as
// "AddHandler ...php \" + ".jpg" reads as two harmless physical lines and
// every per-line scanner misses the remap.
func joinHtaccessContinuations(physical []string) []htaccessLogicalLine {
	var out []htaccessLogicalLine
	for i := 0; i < len(physical); {
		start := i
		var sb strings.Builder
		var span []string
		for {
			cur := physical[i]
			span = append(span, cur)
			// On CRLF input (strings.Split keeps the trailing "\r") the
			// continuation backslash sits before the carriage return, so
			// strip it before the suffix test and from the joined text.
			body := strings.TrimRight(cur, "\r")
			// A trailing backslash continues only when a next line exists;
			// a backslash on the final line is left literal, matching Apache.
			if i < len(physical)-1 && strings.HasSuffix(body, `\`) {
				sb.WriteString(body[:len(body)-1])
				i++
				continue
			}
			sb.WriteString(body)
			break
		}
		out = append(out, htaccessLogicalLine{text: sb.String(), lines: span, start: start})
		i++
	}
	return out
}

func apacheDirectiveFields(line string) []string {
	fields := strings.Fields(line)
	for i, field := range fields {
		if strings.HasPrefix(field, "#") {
			return fields[:i]
		}
	}
	return fields
}

func normalizedExts(tokens []string) []string {
	var exts []string
	for _, token := range tokens {
		if ext := normalizeExt(token); ext != "" {
			exts = append(exts, ext)
		}
	}
	return exts
}

func addExtensions(overlay *phpHandlerOverlay, exts []string) {
	if len(exts) == 0 {
		return
	}
	for _, ext := range exts {
		if isExecutablePHPName("x" + ext) {
			continue
		}
		if overlay.exts == nil {
			overlay.exts = make(map[string]struct{}, len(exts))
		}
		overlay.exts[ext] = struct{}{}
	}
}

func mergeContext(overlay *phpHandlerOverlay, contexts []phpHandlerOverlay) bool {
	merged := false
	for _, ctx := range contexts {
		if len(ctx.exts) > 0 {
			if overlay.exts == nil {
				overlay.exts = make(map[string]struct{}, len(ctx.exts))
			}
			for ext := range ctx.exts {
				overlay.exts[ext] = struct{}{}
				merged = true
			}
		}
		if len(ctx.names) > 0 {
			if overlay.names == nil {
				overlay.names = make(map[string]struct{}, len(ctx.names))
			}
			for name := range ctx.names {
				overlay.names[name] = struct{}{}
				merged = true
			}
		}
	}
	return merged
}

func openPHPHandlerContext(line string) (phpHandlerOverlay, bool) {
	lower := strings.ToLower(line)
	switch {
	case strings.HasPrefix(lower, "<filesmatch"):
		pattern := apacheContainerArgument(line)
		return overlayForFilesMatch(pattern), true
	case strings.HasPrefix(lower, "<files"):
		name := apacheContainerArgument(line)
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || strings.Contains(name, "/") {
			return phpHandlerOverlay{}, true
		}
		if strings.ContainsAny(name, "*?[") {
			overlay := phpHandlerOverlay{}
			addExtensions(&overlay, []string{filepath.Ext(name)})
			return overlay, true
		}
		overlay := phpHandlerOverlay{names: map[string]struct{}{name: {}}}
		return overlay, true
	default:
		return phpHandlerOverlay{}, false
	}
}

func closesPHPHandlerContext(line string) bool {
	lower := strings.ToLower(line)
	return strings.HasPrefix(lower, "</filesmatch") || strings.HasPrefix(lower, "</files")
}

func apacheContainerArgument(line string) string {
	start := strings.IndexByte(line, ' ')
	end := strings.LastIndexByte(line, '>')
	if start < 0 || end <= start {
		return ""
	}
	arg := strings.TrimSpace(line[start:end])
	if len(arg) >= 2 {
		quote := arg[0]
		if (quote == '"' || quote == '\'') && arg[len(arg)-1] == quote {
			arg = arg[1 : len(arg)-1]
		}
	}
	return arg
}

func overlayForFilesMatch(pattern string) phpHandlerOverlay {
	overlay := phpHandlerOverlay{}
	addExtensions(&overlay, extensionsFromFilesMatchPattern(pattern))
	return overlay
}

func extensionsFromFilesMatchPattern(pattern string) []string {
	pattern = strings.ToLower(pattern)
	seen := make(map[string]struct{})
	var exts []string

	add := func(ext string) {
		ext = normalizeExt(ext)
		if ext == "" {
			return
		}
		if _, ok := seen[ext]; ok {
			return
		}
		seen[ext] = struct{}{}
		exts = append(exts, ext)
	}

	for i := 0; i+1 < len(pattern); i++ {
		if pattern[i] != '\\' || pattern[i+1] != '.' {
			continue
		}
		j := i + 2
		if j < len(pattern) && pattern[j] == '(' {
			end := strings.IndexByte(pattern[j+1:], ')')
			if end >= 0 {
				group := pattern[j+1 : j+1+end]
				group = strings.TrimPrefix(group, "?:")
				for _, part := range strings.Split(group, "|") {
					add(part)
				}
			}
			continue
		}
		start := j
		for j < len(pattern) {
			c := pattern[j]
			alnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
			if !alnum && c != '_' && c != '-' {
				break
			}
			j++
		}
		add(pattern[start:j])
		i = j
	}
	return exts
}

func phpPathExecutes(path, nameLower string) bool {
	if isExecutablePHPName(nameLower) {
		return true
	}

	overlay := phpHandlerOverlay{}
	for _, dir := range htaccessAncestorDirs(path) {
		if htaccess, err := osFS.ReadFile(filepath.Join(dir, ".htaccess")); err == nil {
			overlay = overlay.mergeHtaccess(htaccess)
		}
	}
	return overlay.executes(nameLower)
}

func htaccessAncestorDirs(path string) []string {
	dir := filepath.Clean(filepath.Dir(path))
	if dir == "." {
		return nil
	}

	var dirs []string
	for {
		dirs = append(dirs, dir)
		if stopHtaccessAncestorWalk(dir) {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	for i, j := 0, len(dirs)-1; i < j; i, j = i+1, j-1 {
		dirs[i], dirs[j] = dirs[j], dirs[i]
	}
	return dirs
}

func stopHtaccessAncestorWalk(dir string) bool {
	if !strings.HasPrefix(dir, "/home/") {
		return false
	}
	rest := strings.TrimPrefix(dir, "/home/")
	return rest != "" && !strings.Contains(rest, "/")
}
