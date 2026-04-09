//go:build linux

package daemon

import (
	"net"

	"golang.org/x/sys/unix"
)

func isTrustedPAMPeer(conn net.Conn) bool {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return false
	}

	trusted := false
	controlErr := rawConn.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err == nil && cred != nil && cred.Uid == 0 {
			trusted = true
		}
	})
	return controlErr == nil && trusted
}
