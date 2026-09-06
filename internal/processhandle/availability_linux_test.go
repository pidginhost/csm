//go:build linux

package processhandle

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// A transient resource failure must not leave health degraded forever once
// safe process signaling is available again.
func TestAvailableRecoversAfterDescriptorExhaustion(t *testing.T) {
	oldOpen := pidfdOpen
	t.Cleanup(func() { pidfdOpen = oldOpen })
	pidfdOpen = func(int, int) (int, error) { return -1, unix.EMFILE }
	if err := Available(); !errors.Is(err, unix.EMFILE) {
		t.Fatalf("descriptor exhaustion was not reported: %v", err)
	}
	pidfdOpen = oldOpen
	if err := Available(); err != nil {
		t.Fatalf("recovered process signaling is still reported unavailable: %v", err)
	}
}
