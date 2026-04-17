//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Item 4 regression: when the analyzer queue overflows, dropped events are
// recovered by a reconcile pass that walks tracked drop-directories and
// analyses any interesting file modified within the drop window. This
// preserves detection coverage during bulk filesystem operations (unzip,
// backup restore, mass plugin update) that would otherwise blind the
// monitor to actual threats landing in the storm.

func TestReconcileDropsScansRecentWebshellInTrackedDir(t *testing.T) {
	dir := t.TempDir()
	// Webshell written mid-"burst": reconcile must find it even though the
	// fanotify event for it was never delivered.
	webshellPath := filepath.Join(dir, "pwn.php")
	if err := os.WriteFile(webshellPath, []byte(`<?php system($_GET['c']); ?>`), 0644); err != nil {
		t.Fatal(err)
	}

	ch := make(chan alert.Finding, 16)
	fm := &FileMonitor{
		cfg:           &config.Config{},
		alertCh:       ch,
		reconcileDirs: make(map[string]time.Time),
	}

	// Simulate: handleEvent saw a drop for a path under this dir.
	fm.recordDroppedDir(webshellPath)

	fm.reconcileDrops()

	var got []alert.Finding
	timeout := time.After(250 * time.Millisecond)
drain:
	for {
		select {
		case a := <-ch:
			got = append(got, a)
		case <-timeout:
			break drain
		}
	}

	found := false
	for _, a := range got {
		if a.Check == "webshell_content_realtime" && a.Severity == alert.Critical {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("reconcile did not surface webshell in dropped dir, got: %+v", got)
	}
}

func TestReconcileDropsIgnoresStaleFiles(t *testing.T) {
	dir := t.TempDir()
	stalePath := filepath.Join(dir, "stale.php")
	if err := os.WriteFile(stalePath, []byte(`<?php system($_GET['c']); ?>`), 0644); err != nil {
		t.Fatal(err)
	}
	// Age the file past the reconcile window.
	old := time.Now().Add(-5 * time.Minute)
	if err := os.Chtimes(stalePath, old, old); err != nil {
		t.Fatal(err)
	}

	ch := make(chan alert.Finding, 16)
	fm := &FileMonitor{
		cfg:           &config.Config{},
		alertCh:       ch,
		reconcileDirs: make(map[string]time.Time),
	}
	fm.recordDroppedDir(stalePath)
	fm.reconcileDrops()

	select {
	case a := <-ch:
		t.Fatalf("reconcile should skip files older than window, got %+v", a)
	case <-time.After(100 * time.Millisecond):
		// OK
	}
}

func TestRecordDroppedDirCapsMapSize(t *testing.T) {
	fm := &FileMonitor{
		reconcileDirs: make(map[string]time.Time),
	}
	// Flood well past the cap.
	for i := 0; i < reconcileDirCap*3; i++ {
		fm.recordDroppedDir(filepath.Join("/tmp", "b", "x"+time.Now().Format("150405.000000000"), "f.php"))
		time.Sleep(50 * time.Microsecond)
	}
	if len(fm.reconcileDirs) > reconcileDirCap {
		t.Errorf("reconcileDirs size = %d, want <= %d", len(fm.reconcileDirs), reconcileDirCap)
	}
}
