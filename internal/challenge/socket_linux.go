//go:build linux

package challenge

import (
	"errors"

	"golang.org/x/sys/unix"
)

// chmod changes an ACL's mask, not its named grants. Clear inherited grants
// while the socket is still hidden so only its owner and listen_group get
// access when it is published.
func clearSocketACL(path string) error {
	err := unix.Lremovexattr(path, "system.posix_acl_access")
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.EOPNOTSUPP) {
		return nil
	}
	return err
}
