//go:build linux

package daemon

import (
	"fmt"
	"os"
	"syscall"
)

// fileChangeIdentity adds the device, inode and change time, which a
// replaced or rewritten file cannot keep even if its size and mtime match.
func fileChangeIdentity(info os.FileInfo) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d:%d.%d", st.Dev, st.Ino, st.Ctim.Sec, st.Ctim.Nsec)
}
