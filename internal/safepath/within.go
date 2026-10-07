package safepath

import (
	"path/filepath"
	"strings"
)

// Within reports whether path is base or sits below it, comparing cleaned
// lexical paths: no symlinks are followed and nothing is read. The root
// directory contains every absolute path. An empty path is nowhere.
func Within(path, base string) bool {
	if path == "" {
		return false
	}
	path = filepath.Clean(path)
	base = filepath.Clean(base)
	if base == string(filepath.Separator) {
		return filepath.IsAbs(path)
	}
	return path == base || strings.HasPrefix(path, base+string(filepath.Separator))
}
