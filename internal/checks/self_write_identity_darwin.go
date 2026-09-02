//go:build darwin

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
		// #nosec G115 -- darwin's Dev is int32; the widening is deliberate and
		// only ever compared against another identity built the same way.
		Device:     uint64(st.Dev),
		Inode:      st.Ino,
		ChangeSec:  st.Ctimespec.Sec,
		ChangeNsec: st.Ctimespec.Nsec,
	}, true
}
