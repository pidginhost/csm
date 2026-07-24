//go:build linux

package checks

import (
	"os"
	"syscall"
)

func selfWriteIdentityFromFileInfo(info os.FileInfo) (selfWriteFileIdentity, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return selfWriteFileIdentity{}, false
	}
	return selfWriteFileIdentity{
		Device:     uint64(st.Dev),
		Inode:      st.Ino,
		ChangeSec:  st.Ctim.Sec,
		ChangeNsec: st.Ctim.Nsec,
	}, true
}
