//go:build linux

package hostfacts

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// Default ACLs also matter: they can grant access to the files CSM creates
// even when the directory's current access permissions are safe.
func hasExtACL(p string) (bool, error) {
	for _, attribute := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		_, err := unix.Lgetxattr(p, attribute, nil)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, unix.ENODATA), errors.Is(err, unix.EOPNOTSUPP):
			continue
		default:
			return false, err
		}
	}
	return false, nil
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
