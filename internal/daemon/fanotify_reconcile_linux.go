//go:build linux

package daemon

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/queuehealth"
)

type reconcileDirectory struct {
	firstDrop time.Time
	lastDrop  time.Time
	ticket    queuehealth.Ticket
}

// Repeated drops refresh eviction priority without postponing recovery age.
func (fm *FileMonitor) recordDroppedDir(path string) {
	fm.initQueueHealth()
	dir := filepath.Dir(path)
	fm.reconcileMu.Lock()
	defer fm.reconcileMu.Unlock()
	if fm.reconcileDirs == nil {
		fm.reconcileDirs = make(map[string]reconcileDirectory)
	}
	now := time.Now()
	entry, exists := fm.reconcileDirs[dir]
	if !exists {
		entry.firstDrop = now
		entry.ticket = fm.reconcileHealth.Begin(now)
	}
	entry.lastDrop = now
	fm.reconcileDirs[dir] = entry
	fm.evictOverflowDirLocked(now)
}

// evictOverflowDirLocked drops the least recently refreshed directory once the
// tracker is over its cap. The caller holds reconcileMu.
func (fm *FileMonitor) evictOverflowDirLocked(now time.Time) {
	if len(fm.reconcileDirs) <= reconcileDirCap {
		return
	}
	var oldestKey string
	var oldestTime time.Time
	first := true
	for path, candidate := range fm.reconcileDirs {
		if first || candidate.lastDrop.Before(oldestTime) {
			oldestKey, oldestTime, first = path, candidate.lastDrop, false
		}
	}
	fm.reconcileDirs[oldestKey].ticket.Reject(now)
	delete(fm.reconcileDirs, oldestKey)
}

// startReconcile runs one recovery pass off the caller's goroutine. Passes
// never overlap and never run closer together than reconcileMinInterval: the
// eager trigger fires on drop volume, and a storm produces that volume far
// faster than a pass can absorb it.
func (fm *FileMonitor) startReconcile() {
	select {
	case <-fm.stopCh:
		return
	default:
	}
	now := time.Now()
	if last := fm.reconcileLastPass.Load(); last != 0 && now.Sub(time.Unix(0, last)) < reconcileMinInterval {
		return
	}
	if !fm.reconcileRunning.CompareAndSwap(false, true) {
		return
	}
	fm.wg.Add(1)
	obs.Go("fanotify-reconcile", func() {
		defer fm.wg.Done()
		defer func() {
			fm.reconcileLastPass.Store(time.Now().UnixNano())
			fm.reconcileRunning.Store(false)
		}()
		fm.reconcileDrops()
	})
}

func (fm *FileMonitor) reconcileDrops() {
	fm.initQueueHealth()
	fm.reconcileMu.Lock()
	dirs := fm.reconcileDirs
	fm.reconcileDirs = make(map[string]reconcileDirectory)
	started := time.Now()
	for _, entry := range dirs {
		entry.ticket.Start(started)
	}
	fm.reconcileMu.Unlock()
	if len(dirs) == 0 {
		return
	}
	// A panic abandons every unfinished directory in this detached batch.
	defer func() {
		now := time.Now()
		for _, entry := range dirs {
			entry.ticket.Reject(now)
		}
	}()
	if fanotifyReconcileDur != nil {
		defer func() { fanotifyReconcileDur.Observe(time.Since(started).Seconds()) }()
	}
	cutoff := started.Add(-reconcileWindow)
	deadline := started.Add(reconcileBudget)
	for dir, entry := range dirs {
		if fm.reconcilePassDone(deadline) {
			fm.deferReconcileDirs(dirs)
			return
		}
		complete := fm.reconcileDirectory(dir, cutoff)
		// A refreshed drop cannot recover an older obligation outside this scan's window.
		if complete && !entry.firstDrop.Before(cutoff) {
			entry.ticket.Finish(time.Now())
		} else {
			entry.ticket.Reject(time.Now())
		}
		delete(dirs, dir)
	}
}

// reconcilePassDone reports whether this pass must stop: its budget is spent,
// or the monitor is shutting down.
func (fm *FileMonitor) reconcilePassDone(deadline time.Time) bool {
	select {
	case <-fm.stopCh:
		return true
	default:
	}
	return time.Now().After(deadline)
}

// deferReconcileDirs returns directories this pass did not reach to the
// tracker so the next pass takes them, and empties the detached batch so the
// panic guard does not count them as lost. A directory that took a new drop
// while the pass ran is already represented by a waiting ticket; merging keeps
// the older admission age rather than restarting the clock on it.
func (fm *FileMonitor) deferReconcileDirs(dirs map[string]reconcileDirectory) {
	now := time.Now()
	fm.reconcileMu.Lock()
	defer fm.reconcileMu.Unlock()
	if fm.reconcileDirs == nil {
		fm.reconcileDirs = make(map[string]reconcileDirectory)
	}
	for dir, entry := range dirs {
		delete(dirs, dir)
		if waiting, exists := fm.reconcileDirs[dir]; exists {
			waiting.ticket.MergeRunning(entry.ticket, now)
			if entry.firstDrop.Before(waiting.firstDrop) {
				waiting.firstDrop = entry.firstDrop
				fm.reconcileDirs[dir] = waiting
			}
			continue
		}
		entry.ticket.Requeue(now)
		fm.reconcileDirs[dir] = entry
		fm.evictOverflowDirLocked(now)
	}
}

// A tree removed before recovery ran holds nothing left to scan, so the
// kernel loss that started the recovery is the only loss. Reads that failed
// for any other reason left work the operator can still act on.
func (fm *FileMonitor) reconcileDirectory(dir string, cutoff time.Time) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return errors.Is(err, fs.ErrNotExist)
	}
	complete := true
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if !fm.isInteresting(path) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				complete = false
			}
			continue
		}
		if info.ModTime().Before(cutoff) {
			continue
		}
		if !fm.reconcileFile(path) {
			complete = false
		}
	}
	return complete
}

func (fm *FileMonitor) reconcileFile(path string) bool {
	// #nosec G304 -- path is a candidate in a directory recorded after a dropped event; its original event fd is no longer available.
	file, err := os.Open(path)
	if err != nil {
		return errors.Is(err, fs.ErrNotExist)
	}
	// Close per file, including panic, rather than retaining the whole batch's fds.
	defer func() { _ = file.Close() }()
	// #nosec G115 -- Linux file descriptors are nonnegative int32 values and fit Go int.
	fileAnalyzer(fm, fileEvent{path: path, fd: int(file.Fd())})
	return true
}

// Reader and worker producers have joined before shutdown discards this map.
func (fm *FileMonitor) discardReconcilePending() {
	fm.reconcileMu.Lock()
	defer fm.reconcileMu.Unlock()
	now := time.Now()
	for dir, entry := range fm.reconcileDirs {
		entry.ticket.Reject(now)
		delete(fm.reconcileDirs, dir)
	}
}
