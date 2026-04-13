//go:build linux

package daemon

import "testing"

func TestNewForwarderWatcherLinuxNilAlert(t *testing.T) {
	_, err := NewForwarderWatcher(nil, nil)
	// Should handle nil alertCh gracefully or return error
	if err == nil {
		t.Log("ForwarderWatcher accepted nil alertCh")
	}
}
