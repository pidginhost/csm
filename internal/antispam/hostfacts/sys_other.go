//go:build !linux

package hostfacts

import "net"

// Antispam runs only on Linux cPanel hosts; other builds exist for
// development, where these facts read as absent and unknown.

func hasExtACL(string) (bool, error) { return false, nil }

func peerUID(net.Conn) int { return -1 }
