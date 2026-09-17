package safepath

import "golang.org/x/sys/unix"

func renameat(oldfd int, old string, newfd int, name string, exchange bool) error {
	flags := uint(unix.RENAME_NOREPLACE)
	if exchange {
		flags = unix.RENAME_EXCHANGE
	}
	return unix.Renameat2(oldfd, old, newfd, name, flags)
}
