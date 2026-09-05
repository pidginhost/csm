package safepath

import "golang.org/x/sys/unix"

func renameat(oldfd int, old string, newfd int, name string, exchange bool) error {
	flags := uint32(unix.RENAME_EXCL)
	if exchange {
		flags = unix.RENAME_SWAP
	}
	return unix.RenameatxNp(oldfd, old, newfd, name, flags)
}
