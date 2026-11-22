//go:build linux

package platform

import (
	"io/fs"
	"syscall"
	"time"
)

// fileChanged is the later of a file's modification and status change.
func fileChanged(fi fs.FileInfo) time.Time {
	changed := fi.ModTime()
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if ctime := time.Unix(st.Ctim.Sec, st.Ctim.Nsec); ctime.After(changed) {
			changed = ctime
		}
	}
	return changed
}
