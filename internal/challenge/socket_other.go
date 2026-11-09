//go:build !linux

package challenge

// Linux is the daemon's supported runtime; other platforms build the tests.
func clearSocketACL(string) error { return nil }
