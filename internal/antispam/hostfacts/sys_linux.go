//go:build linux

package hostfacts

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// hasExtACL reports whether p carries a POSIX access ACL. Without one, the
// mode bits are the whole permission story.
func hasExtACL(p string) (bool, error) {
	_, err := unix.Lgetxattr(p, "system.posix_acl_access", nil)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.ENODATA), errors.Is(err, unix.EOPNOTSUPP):
		return false, nil
	}
	return false, err
}

// peerUID is the uid SO_PEERCRED reports for the listener behind conn, or -1.
func peerUID(conn net.Conn) int {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return -1
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1
	}
	uid := -1
	_ = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) // #nosec G115 -- a socket fd fits in int
		if err == nil {
			uid = int(cred.Uid)
		}
	})
	return uid
}
