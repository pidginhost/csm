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
// upload-style directory.
func htaccessInUploadTree(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(filepath.Dir(path)), "/") {
		if uploadTreeDirNames[strings.ToLower(part)] {
			return true
		}
	}
	return false
}
