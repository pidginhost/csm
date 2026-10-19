//go:build linux

package learnwatch

import (
	"os"
	"syscall"

	"github.com/pidginhost/csm/internal/safepath"
)

func metaOf(fi os.FileInfo) (Meta, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return Meta{}, false
	}
	return Meta{
		Dev: st.Dev, Ino: st.Ino, UID: int(st.Uid), Nlink: uint64(st.Nlink),
		Size: st.Size, MtimeNs: st.Mtim.Nano(), CtimeNs: st.Ctim.Nano(),
	}, true
}

func lstatAt(d *safepath.Dir, name string) (os.FileInfo, error) { return d.Lstat(name) }
