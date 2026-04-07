package yara

import (
	"fmt"
	"os"
	"sync"
)

var (
	globalScanner *Scanner
	globalOnce    sync.Once
)

// Init initializes the global YARA-X scanner.
// Returns nil scanner if YARA-X is not compiled in or no rules found.
func Init(rulesDir string) *Scanner {
	if !Available() {
		return nil
	}
	globalOnce.Do(func() {
		s, err := NewScanner(rulesDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "yara: init error: %v\n", err)
			return
		}
		globalScanner = s
	})
	return globalScanner
}

// Global returns the global YARA-X scanner, or nil if not initialized.
func Global() *Scanner {
	return globalScanner
}
