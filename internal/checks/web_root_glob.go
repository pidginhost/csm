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
	return checkedWebRootGlobAtDepth(pattern, 0)
}

func checkedWebRootGlobAtDepth(pattern string, depth int) ([]string, bool) {
	// Keep filepath.Glob's bound against stack exhaustion from configuration.
	const pathSeparatorsLimit = 10000
	if depth == pathSeparatorsLimit {
		return nil, false
	}
	if _, err := filepath.Match(pattern, ""); err != nil {
		return nil, false
	}
	if !strings.ContainsAny(pattern, `*?[\`) {
		if _, err := osFS.Lstat(pattern); err != nil {
			return nil, webRootAbsent(err)
		}
		return []string{pattern}, true
	}

	dir, leaf := filepath.Split(pattern)
	if dir == "" {
		dir = "."
	} else if dir != string(filepath.Separator) {
		dir = strings.TrimSuffix(dir, string(filepath.Separator))
	}
	parents, complete := checkedWebRootGlobAtDepth(dir, depth+1)
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
			matched, err := filepath.Match(leaf, entry.Name())
			if err != nil {
				return nil, false
			}
			if matched {
				matches = append(matches, filepath.Join(parent, entry.Name()))
			}
		}
	}
	return matches, complete
}

func webRootAbsent(err error) bool {
	return os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR)
}
