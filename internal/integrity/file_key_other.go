//go:build !linux

package integrity

import "os"

// fileChangeIdentity has nothing beyond size and mtime off Linux, where CSM
// only runs in tests.
func fileChangeIdentity(os.FileInfo) string {
	return ""
}
