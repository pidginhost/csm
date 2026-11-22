//go:build !linux

package platform

import (
	"io/fs"
	"time"
)

// fileChanged is a file's modification time where no status change time is
// read.
func fileChanged(fi fs.FileInfo) time.Time {
	return fi.ModTime()
}
