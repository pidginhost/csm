package signatures

import "sync"

var (
	globalScanner *Scanner
	globalOnce    sync.Once
)

// Init initializes the global scanner with rules from the given directory.
// Safe to call multiple times - only the first call takes effect.
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

// SetGlobal replaces the global scanner and returns the previous one.
//
// Init is guarded by a sync.Once, so only the first call in a process takes
// effect. That is right for the daemon, which initializes once, but it means
// a test helper that calls Init to install its own rules silently does
// nothing after the first test has run -- and its cleanup silently fails to
// restore anything. Tests that need to swap rules use this instead, and put
// the previous scanner back when they finish.
func SetGlobal(s *Scanner) *Scanner {
	previous := globalScanner
	globalScanner = s
	return previous
}
