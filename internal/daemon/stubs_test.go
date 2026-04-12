//go:build !linux

package daemon

import (
	"net"
	"testing"
)

// --- SpoolWatcher stub ------------------------------------------------

func TestNewSpoolWatcherReturnsError(t *testing.T) {
	_, err := NewSpoolWatcher(nil, nil, nil, nil)
	if err == nil {
		t.Error("expected error on non-linux")
	}
}

func TestSpoolWatcherStubMethods(t *testing.T) {
	sw := &SpoolWatcher{}
	sw.Run()  // no-op
	sw.Stop() // no-op
	if sw.PermissionMode() {
		t.Error("stub should return false")
	}
}

// --- FileMonitor stub -------------------------------------------------

func TestNewFileMonitorReturnsError(t *testing.T) {
	_, err := NewFileMonitor(nil, nil)
	if err == nil {
		t.Error("expected error on non-linux")
	}
}

func TestFileMonitorStubMethods(t *testing.T) {
	fm := &FileMonitor{}
	ch := make(chan struct{})
	close(ch)
	fm.Run(ch) // no-op
	fm.Stop()  // no-op
}

// --- ForwarderWatcher stub --------------------------------------------

func TestNewForwarderWatcherReturnsError(t *testing.T) {
	_, err := NewForwarderWatcher(nil, nil)
	if err == nil {
		t.Error("expected error on non-linux")
	}
}

func TestForwarderWatcherStubRun(t *testing.T) {
	fw := &ForwarderWatcher{}
	ch := make(chan struct{})
	close(ch)
	fw.Run(ch) // no-op
}

// --- PAM peer stub ----------------------------------------------------

func TestIsTrustedPAMPeerStub(t *testing.T) {
	// On non-Linux, always returns true.
	if !isTrustedPAMPeer((*net.TCPConn)(nil)) {
		t.Error("stub should return true")
	}
}
