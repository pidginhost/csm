//go:build linux

package checks

import (
	"os"
	"syscall"
)

// SameFileVersion requires the same observed Linux file version. Ctime closes
// the same-inode, same-size rewrite case where an attacker restores mtime after
// changing content.
func SameFileVersion(a, b os.FileInfo) bool {
	if !sameFileIdentity(a, b) || !sameContentShape(a, b) {
		return false
	}
	as, aok := a.Sys().(*syscall.Stat_t)
	bs, bok := b.Sys().(*syscall.Stat_t)
	return aok && bok && as.Ctim == bs.Ctim
}
