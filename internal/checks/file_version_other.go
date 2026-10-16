//go:build !linux

package checks

import "os"

// SameFileVersion uses the portable identity, size, and mtime proof on
// non-Linux development hosts. Production file response is Linux-only.
func SameFileVersion(a, b os.FileInfo) bool {
	return sameFileIdentity(a, b) && sameContentShape(a, b)
}
