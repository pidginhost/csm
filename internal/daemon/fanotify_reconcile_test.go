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

// 2026-04-28 cpanel package restore: a single restore extracted ~4189 file
// events into the analyzer in seconds, blowing past the 4000-entry channel
// buffer. The minute-tick reconcileDrops walked tracked dirs after the
// burst, but two failure modes were exposed:
//
//  1. reconcileDirCap=64 was way smaller than the number of unique parent
//     directories a cpanel restore touches (one per WP-content subdir).
//     Older entries got evicted before reconcileDrops ran.
//  2. The minute-tick latency (up to 60s) meant files dropped at the
//     beginning of a tick aged past reconcileWindow before the reconcile
//     could read them.
//
// The tests below pin the new constants and the new eager-trigger behaviour
// so a future regression that drops them back gets caught immediately.

func TestReconcileDirCap_BumpedAbsorbsCpanelRestoreBurst(t *testing.T) {
	// A cpanel package restore touches several hundred unique parent
	// directories within the reconcile window; the cap must be large
	// enough that none of them get evicted before reconcileDrops runs.
	const minCpanelRestoreDirs = 256
	if reconcileDirCap < minCpanelRestoreDirs {
		t.Errorf("reconcileDirCap = %d, want >= %d (cpanel package restore touches that many unique dirs)", reconcileDirCap, minCpanelRestoreDirs)
	}
}

func TestAnalyzerChBuffer_BumpedAbsorbsBulkBursts(t *testing.T) {
	// The analyzer channel is created from analyzerChBufferSize. A
	// cpanel restore observed in production produced ~4189 file events
	// in seconds; the buffer must be large enough that a typical burst
	// does not overflow at all (overflow recovery via reconcileDrops is
	// a fallback, not the primary path).
	const minBurstAbsorbed = 8192
	if analyzerChBufferSize < minBurstAbsorbed {
		t.Errorf("analyzerChBufferSize = %d, want >= %d (cpanel package restore observed at ~4189 events)", analyzerChBufferSize, minBurstAbsorbed)
	}
}
