package checks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// filepath.Glob hides filesystem errors. Expand roots with an explicit
// completeness result so inaccessible roots cannot look like removed ones.
func checkedWebRootGlob(pattern string) ([]string, bool) {
	return checkedPathGlob(pattern, 0, pathGlobSyntax{filepath.Match, filepath.Join, pathGlobHasMeta})
}

type pathGlobSyntax struct {
	match   func(string, string) (bool, error)
	join    func(...string) string
	hasMeta func(string) bool
}

func pathGlobHasMeta(pattern string) bool { return strings.ContainsAny(pattern, `*?[\`) }

func checkedPathGlob(pattern string, depth int, syntax pathGlobSyntax) ([]string, bool) {
	// Keep filepath.Glob's bound against stack exhaustion from configuration.
	const pathSeparatorsLimit = 10000
	if depth == pathSeparatorsLimit {
		return nil, false
	}
	if !syntax.hasMeta(pattern) {
		if _, err := osFS.Lstat(pattern); err != nil {
			return nil, webRootAbsent(err)
		}
		return []string{pattern}, true
	}
	if _, err := syntax.match(pattern, ""); err != nil {
		return nil, false
	}

	dir, leaf := filepath.Split(pattern)
	if dir == "" {
		dir = "."
	} else if dir != string(filepath.Separator) {
		dir = strings.TrimSuffix(dir, string(filepath.Separator))
	}
	parents, complete := checkedPathGlob(dir, depth+1, syntax)
	var matches []string
	for _, parent := range parents {
		info, err := osFS.Stat(parent)
		if err != nil {
			complete = complete && webRootAbsent(err)
			continue
		}
		if !info.IsDir() {
			continue
		}
		entries, err := osFS.ReadDir(parent)
		if err != nil {
			complete = complete && webRootAbsent(err)
		}
		for _, entry := range entries {
			matched, err := syntax.match(leaf, entry.Name())
			if err != nil {
				return nil, false
			}
			if matched {
				matches = append(matches, syntax.join(parent, entry.Name()))
			}
		}
	}
	return matches, complete
}

func webRootAbsent(err error) bool {
	return os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR)
}
