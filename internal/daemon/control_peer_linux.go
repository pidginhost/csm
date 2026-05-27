//go:build linux

package daemon

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

var controlPeerRequiredUID uint32

// verifyControlPeer reads SO_PEERCRED and refuses any caller whose
// effective uid is not root. Returns nil when the peer is acceptable.
func verifyControlPeer(conn net.Conn) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok || uc == nil {
		return fmt.Errorf("peer credentials: unsupported connection %T", conn)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return fmt.Errorf("peer raw conn: %w", err)
	}
	var ucred *unix.Ucred
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		// #nosec G115 -- POSIX fd fits in int on Linux.
		ucred, optErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return fmt.Errorf("peer credentials: %w", err)
	}
	if optErr != nil {
		return fmt.Errorf("peer credentials: %w", optErr)
	}
	if ucred == nil {
		return fmt.Errorf("peer credentials: empty result")
	}
	if ucred.Uid != controlPeerRequiredUID {
		return fmt.Errorf("peer uid=%d, want %d", ucred.Uid, controlPeerRequiredUID)
	}
	return nil
}
