//go:build linux

package daemon

import "testing"

func TestIsTrustedPAMPeerLinuxNil(t *testing.T) {
	// A peer with no Unix credentials to read is not trusted.
	if isTrustedPAMPeer(nil) {
		t.Fatal("nil connection was trusted as a PAM peer")
	}
}
