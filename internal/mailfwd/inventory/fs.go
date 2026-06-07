package inventory

import (
	"os"
	"path/filepath"
)

// osFS is the production FS backed by the real filesystem.
type osFS struct{}

func (osFS) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }

// ReadFile reads a file. Paths come from a fixed glob of operator-owned mail
// config directories, not from untrusted input.
func (osFS) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name) // #nosec G304 -- name is a valias path from a fixed glob, operator-scoped.
}
