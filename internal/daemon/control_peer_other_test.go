//go:build !linux

package daemon

import "testing"

func allowCurrentControlPeerUID(t *testing.T) {
	t.Helper()
}
