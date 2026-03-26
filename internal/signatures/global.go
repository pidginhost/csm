package signatures

import "sync"

var (
	globalScanner *Scanner
	globalOnce    sync.Once
)

// Init initializes the global scanner with rules from the given directory.
// Safe to call multiple times — only the first call takes effect.
// Call Reload() on the returned scanner to reload rules (e.g., on SIGHUP).
func Init(rulesDir string) *Scanner {
	globalOnce.Do(func() {
		globalScanner = NewScanner(rulesDir)
	})
	return globalScanner
}

// Global returns the global scanner, or nil if Init() hasn't been called.
func Global() *Scanner {
	return globalScanner
}
