//go:build !linux

package daemon

import (
	"net"
	"testing"
	"time"
)

// --- SpoolWatcher stub ------------------------------------------------

func TestNewSpoolWatcherReturnsError(t *testing.T) {
	_, err := NewSpoolWatcher(nil, nil, nil, nil, nil, nil, nil)
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
	// The stub does not wait for a stop it has nothing to stop on.
	done := make(chan struct{})
	go func() {
		fm.Run(make(chan struct{}))
		fm.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stub Run blocked on an open stop channel")
	}
	if got := fm.WatchScopeSummary(); got != "" {
		t.Errorf("stub watches %q, want nothing", got)
	}
	if got := fm.queueStatuses(time.Now()); got != nil {
		t.Errorf("stub reports queues %v, want none", got)
	}
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
	done := make(chan struct{})
	go func() {
		fw.Run(make(chan struct{}))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stub Run blocked on an open stop channel")
	}
	if got := fw.QueueStatuses(time.Now()); got != nil {
		t.Errorf("stub reports queues %v, want none", got)
	}
}

// --- PAM peer stub ----------------------------------------------------

func TestIsTrustedPAMPeerStub(t *testing.T) {
	// On non-Linux, always returns true.
	if !isTrustedPAMPeer((*net.TCPConn)(nil)) {
		t.Error("stub should return true")
	}
}
