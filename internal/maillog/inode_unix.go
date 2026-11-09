//go:build unix

package maillog

import (
	"os"
	"syscall"
)

// fileIdentity is the device and inode that name a log file.
func fileIdentity(fi os.FileInfo) (dev, ino uint64) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev), st.Ino // #nosec G115 -- device IDs are non-negative on supported Unix hosts
	}
	return 0, 0
}
