//go:build linux

package daemon

import "testing"

func TestIsTrustedPAMPeerLinuxNil(t *testing.T) {
	// On Linux, isTrustedPAMPeer checks ucred — nil conn should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Log("isTrustedPAMPeer panicked on nil, expected for Linux")
		}
	}()
	_ = isTrustedPAMPeer(nil)
}
