//go:build !linux

package daemon

import "net"

func isTrustedPAMPeer(_ net.Conn) bool {
	return true
}
