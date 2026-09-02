package checks

import (
	"path/filepath"
	"strings"
)

// unwrapOuterGroup returns the inside of pattern when the whole pattern is
// one parenthesised group, so its alternatives can be judged one by one.
func unwrapOuterGroup(pattern string) (string, bool) {
	if len(pattern) < 2 || pattern[0] != '(' || pattern[len(pattern)-1] != ')' {
		return pattern, false
	}
	depth := 0
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 && i != len(pattern)-1 {
				// The first group closes before the end: not one outer group.
				return pattern, false
			}
		}
	}
	if depth != 0 {
		return pattern, false
	}
	return pattern[1 : len(pattern)-1], true
}

// regexAlternativeNamesSomething reports whether one regex alternative
// carries a literal name character. Escaped sequences (`\w`, `\.`) and
// character classes are skipped: they describe shapes, not names.
func regexAlternativeNamesSomething(alt string) bool {
	inClass := false
	for i := 0; i < len(alt); i++ {
		c := alt[i]
		switch {
		case c == '\\':
			i++
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-':
			return true
		}
	}
	return false
}

// uploadTreeDirNames are directory names under which web-writable content
// lands. Findings there are judged without the sibling-PHP gate.
var uploadTreeDirNames = map[string]bool{
	"uploads": true, "upload": true, "cache": true, "tmp": true, "temp": true,
	"files": true, "media": true, "attachments": true, "images": true,
}

// htaccessInUploadTree reports whether the .htaccess at path sits under an
// upload-style directory. The top-level directory (/home, /var, /tmp) is
// never a docroot-relative upload dir and is skipped, so a system temp root
// does not make every path below it an upload tree.
func htaccessInUploadTree(path string) bool {
	for _, part := range webTreeComponents(filepath.Dir(path)) {
		if uploadTreeDirNames[strings.ToLower(part)] {
			return true
		}
	}
	return false
}

// docrootMarkerNames are directory names that begin a web tree on hosts
// whose layout is not one of the configured account roots.
var docrootMarkerNames = map[string]bool{
	"public_html": true, "www": true, "htdocs": true, "httpdocs": true,
	"web": true, "html": true, "public": true,
}

// webTreeComponents returns the directory components that lie inside the
// account's web tree: everything below <root>/<account> when dir is under
// an account root, otherwise everything below the first document-root
// marker. The prefix above the web tree (a temp root, /var/www, an account
// literally named tmp) never counts: it is not attacker-writable content.
func webTreeComponents(dir string) []string {
	clean := filepath.ToSlash(filepath.Clean(dir))
	if root, account, ok := accountRootOf(clean); ok {
		rel := strings.TrimPrefix(clean, filepath.ToSlash(filepath.Join(root, account))+"/")
		return strings.Split(rel, "/")
	}
	parts := strings.Split(strings.Trim(clean, "/"), "/")
	for i, part := range parts {
		if docrootMarkerNames[strings.ToLower(part)] {
			return parts[i+1:]
		}
	}
	return nil
}
