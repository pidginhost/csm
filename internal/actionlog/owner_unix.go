//go:build unix

package actionlog

import (
	"os"
	"syscall"
)

func fillOwner(st *FileState, info os.FileInfo) {
	if sys, ok := info.Sys().(*syscall.Stat_t); ok {
		st.UID, st.GID = sys.Uid, sys.Gid
	}
}
