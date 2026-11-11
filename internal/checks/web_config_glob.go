package checks

import (
	"path/filepath"
	"strings"
)

// Web servers use shell glob syntax, whereas account root patterns use Go's
// filepath syntax. Keep their matching rules separate while checking the same
// directory read errors.
func checkedWebConfigGlob(pattern string) ([]string, bool) {
	return checkedPathGlob(pattern, 0, pathGlobSyntax{matchWebConfigGlob, joinWebConfigPath, pathGlobHasMeta})
}

func checkedApacheConfigGlob(pattern string) ([]string, bool) {
	return checkedPathGlob(pattern, 0, pathGlobSyntax{matchWebConfigGlob, filepath.Join, apacheIncludeHasGlob})
}

// apr_fnmatch_test lets Apache open literal components without unescaping
// them, even within an include pattern that has wildcards elsewhere.
func apacheIncludeHasGlob(pattern string) bool {
	bracket := false
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
		case '*', '?':
			return true
		case '[':
			bracket = true
		case ']':
			if bracket {
				return true
			}
		}
	}
	return false
}

// nginx leaves symlinks followed by ".." to the filesystem. filepath.Join
// would silently switch to a different file by cleaning those components.
func joinWebConfigPath(parts ...string) string {
	return strings.Join(parts, string(filepath.Separator))
}

func matchWebConfigGlob(pattern, name string) (bool, error) {
	goPattern, err := webConfigGlobPattern(pattern)
	if err != nil {
		return false, err
	}
	// Both httpd's APR_FNM_PERIOD and nginx's glob require an explicit dot.
	if strings.HasPrefix(name, ".") && !strings.HasPrefix(pattern, ".") && !strings.HasPrefix(pattern, `\.`) {
		return false, nil
	}
	return filepath.Match(goPattern, name)
}

// Translate the shared shell bracket syntax. Named, collating and equivalence
// classes differ between APR and libc and can depend on the server's locale;
// leave those trees incomplete instead of claiming they matched no files.
func webConfigGlobPattern(pattern string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			if i+1 == len(pattern) {
				return "", filepath.ErrBadPattern
			}
			out.WriteString(pattern[i : i+2])
			i++
		case '[':
			out.WriteByte('[')
			i++
			if i < len(pattern) && (pattern[i] == '!' || pattern[i] == '^') {
				out.WriteByte('^')
				i++
			}
			first := true
			for ; i < len(pattern); i++ {
				c := pattern[i]
				if c == ']' && !first {
					break
				}
				if c == '[' && i+1 < len(pattern) && strings.ContainsRune(":.=", rune(pattern[i+1])) {
					return "", filepath.ErrBadPattern
				}
				if c == '\\' {
					if i+1 == len(pattern) {
						return "", filepath.ErrBadPattern
					}
					out.WriteByte(c)
					i++
				} else if c == ']' || c == '-' && (first || i+1 < len(pattern) && pattern[i+1] == ']') {
					out.WriteByte('\\')
				}
				out.WriteByte(pattern[i])
				first = false
			}
			if i == len(pattern) {
				return "", filepath.ErrBadPattern
			}
			out.WriteByte(']')
		default:
			out.WriteByte(pattern[i])
		}
	}
	return out.String(), nil
}
