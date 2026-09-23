//go:build !linux

package daemon

import "os"

// fileChangeIdentity has nothing beyond size and mtime off Linux, where the
// daemon only runs in tests.
func fileChangeIdentity(os.FileInfo) string {
	return ""
}
