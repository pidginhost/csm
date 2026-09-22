package daemon

import (
	"path/filepath"
	"strings"
)

// maxWebRootGlobs bounds the per-call glob table kept on the stack. Hosts
// configure a handful of account and document root globs; a longer list
// still matches correctly, through the unfiltered path.
const maxWebRootGlobs = 16

// pathMatchesWebRootPatterns reports whether any directory containing path,
// from its parent up to the root, matches one of the root globs.
//
// It runs for every watched write that reaches the account and document root
// tests, so it avoids matching a glob against a directory it cannot match: a
// glob with no character class and no escape matches only a name with as many
// separators as itself, because its wildcards never match one. A glob with a
// class or an escape may match a separator and is tried at every level.
func pathMatchesWebRootPatterns(path string, patterns []string) bool {
	if len(patterns) > maxWebRootGlobs {
		return matchWebRootsAtEveryLevel(path, patterns)
	}
	var globs [maxWebRootGlobs]string
	var depths [maxWebRootGlobs]int
	for i, pattern := range patterns {
		globs[i] = filepath.Clean(pattern)
		depths[i] = -1
		if !strings.ContainsAny(globs[i], `[\`) {
			depths[i] = strings.Count(globs[i], "/")
		}
	}
	dir := filepath.Clean(filepath.Dir(path))
	depth := strings.Count(dir, "/")
	for {
		for i := range patterns {
			if depths[i] >= 0 && depths[i] != depth {
				continue
			}
			if matched, err := filepath.Match(globs[i], dir); err == nil && matched {
				return true
			}
		}
		// dir is clean, so its parent is the prefix before the last
		// separator; filepath.Dir would clean each one again.
		switch i := strings.LastIndexByte(dir, '/'); {
		case i > 0:
			dir, depth = dir[:i], depth-1
		case dir == "/" || dir == ".":
			return false
		case i == 0:
			dir, depth = "/", 1
		default:
			dir, depth = ".", 0
		}
	}
}

func matchWebRootsAtEveryLevel(path string, patterns []string) bool {
	dir := filepath.Clean(filepath.Dir(path))
	for {
		for _, pattern := range patterns {
			if matched, err := filepath.Match(filepath.Clean(pattern), dir); err == nil && matched {
				return true
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}
