//go:build !darwin && !linux

package checks

import "os"

func sensitiveFileOwnership(os.FileInfo) (uid, gid uint32, ok bool) {
	return 0, 0, false
}
