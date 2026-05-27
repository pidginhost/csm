//go:build !linux

package daemon

import "net"

// verifyControlPeer is a no-op outside Linux. The control listener is
// Linux-only in production; darwin/BSD builds exist only for local
// development and tests where SO_PEERCRED has no equivalent surface.
func verifyControlPeer(_ net.Conn) error { return nil }
