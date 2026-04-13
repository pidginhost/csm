//go:build integration

package e2e

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/daemon"
)

func TestFanotifyDetectsPHPWrite(t *testing.T) {
	// Create a temp directory to monitor
	watchDir := t.TempDir()

	ch := make(chan alert.Finding, 50)
	cfg := &config.Config{}
	cfg.Monitoring.WatchPaths = []string{watchDir}

	fm, err := daemon.NewFileMonitor(cfg, ch)
	if err != nil {
		t.Fatalf("NewFileMonitor: %v", err)
	}

	stopCh := make(chan struct{})
	go fm.Run(stopCh)
	defer func() {
		close(stopCh)
		fm.Stop()
	}()

	// Give fanotify a moment to set up
	time.Sleep(500 * time.Millisecond)

	// Write a suspicious PHP file
	phpPath := filepath.Join(watchDir, "webshell.php")
	phpContent := []byte("<?php system($_GET['cmd']); ?>")
	if err := os.WriteFile(phpPath, phpContent, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Wait for alert (up to 10 seconds)
	select {
	case f := <-ch:
		t.Logf("Received alert: check=%s message=%s", f.Check, f.Message)
		// Verify it's a realtime detection
		if f.FilePath != phpPath {
			t.Errorf("FilePath = %q, want %q", f.FilePath, phpPath)
		}
	case <-time.After(10 * time.Second):
		t.Error("no alert received within 10s — fanotify may not be watching the directory")
	}
}

func TestFanotifyIgnoresNonPHP(t *testing.T) {
	watchDir := t.TempDir()

	ch := make(chan alert.Finding, 50)
	cfg := &config.Config{}
	cfg.Monitoring.WatchPaths = []string{watchDir}

	fm, err := daemon.NewFileMonitor(cfg, ch)
	if err != nil {
		t.Fatalf("NewFileMonitor: %v", err)
	}

	stopCh := make(chan struct{})
	go fm.Run(stopCh)
	defer func() {
		close(stopCh)
		fm.Stop()
	}()

	time.Sleep(500 * time.Millisecond)

	// Write a non-PHP file — should not trigger alert
	txtPath := filepath.Join(watchDir, "readme.txt")
	if err := os.WriteFile(txtPath, []byte("just text"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	select {
	case f := <-ch:
		t.Errorf("non-PHP should not trigger alert, got: %+v", f)
	case <-time.After(2 * time.Second):
		// Expected: no alert
	}
}

func TestSpoolWatcherCreateAndStop(t *testing.T) {
	ch := make(chan alert.Finding, 50)
	cfg := &config.Config{}

	sw, err := daemon.NewSpoolWatcher(cfg, ch, nil, nil)
	if err != nil {
		t.Skipf("SpoolWatcher not available: %v", err)
	}
	if sw == nil {
		t.Skip("SpoolWatcher returned nil")
	}

	// Just verify it can be created and stopped without panic
	sw.Stop()
}
