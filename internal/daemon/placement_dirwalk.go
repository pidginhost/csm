//go:build linux

package daemon

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/queuehealth"
)

const (
	// placedDirEntryBudget bounds what one placed directory may cost
	// realtime protection; the deep scan covers anything past it.
	placedDirEntryBudget = 20000
	// placedDirTimeBudget bounds one pass so a slow tree cannot hold back
	// the directories queued behind it. The walk resumes on a later pass.
	placedDirTimeBudget = 30 * time.Second
	// placedDirQueueCap bounds waiting directories. Eviction is oldest
	// first and always reported.
	placedDirQueueCap = 256
)

// Vars so tests can lower the budgets.
var (
	placedDirEntryLimit = placedDirEntryBudget
	placedDirTimeLimit  = placedDirTimeBudget
	placedDirQueueLimit = placedDirQueueCap
)

const (
	// placedDirHeadroomPoll is how often a walk waiting for analyzer
	// headroom looks again; a channel offers no wake on free space.
	placedDirHeadroomPoll = 10 * time.Millisecond
	// placedDirReadBatch bounds each directory read, so a listing stops
	// soon after it outgrows the entry budget.
	placedDirReadBatch = 256
)

// placedDirReadNames lets tests count what a walk reads.
var placedDirReadNames = (*os.File).Readdirnames

const placedDirIncompleteCheck = "placed_dir_incomplete_realtime"

// placedDir is a directory renamed or linked into a watched tree. Its files
// raised no events of their own, so the walk is their realtime check.
type placedDir struct {
	path     string
	dev, ino uint64
	pid      int32
	// at is when the directory was placed. Walked files carry it, not the
	// walk time: restore detection checks the writer started before it.
	at       time.Time
	procInfo string
	ticket   queuehealth.Ticket
	// Unverified BPF overflow events wait for the rename before walking.
	ready time.Time
	// cursor is the last entry visited, as components below path. Names
	// are walked in sorted order, so a resumed pass skips up to it.
	cursor  []string
	entries int
	failed  bool
	// overflowed is sticky: an over-budget listing walks a readdir-order
	// subset, so names below a later cursor may never have been read.
	overflowed bool
	// Only time waiting for analyzer room counts as starvation. Preserve it
	// across passes so slow directory reads cannot cause endless retries.
	headroomWait time.Duration
}

// queuePlacedDir hands a placed-in directory to the walk worker. It never
// walks on the caller's goroutine.
func (fm *FileMonitor) queuePlacedDir(path string, dev, ino uint64, pid int32, at, ready time.Time) {
	fm.initQueueHealth()
	// Resolved now: by the time a walk is cut the renamer may be gone.
	procInfo := resolveProcessInfo(pid)
	now := time.Now()
	fm.placedDirMu.Lock()
	fm.placedDirs = append(fm.placedDirs, placedDir{
		path: path, dev: dev, ino: ino, pid: pid, at: at, procInfo: procInfo,
		ticket: fm.placedDirHealth.Begin(now), ready: ready,
	})
	evicted := fm.evictPlacedDirsLocked(now)
	fm.placedDirMu.Unlock()
	fm.reportEvictedPlacedDirs(evicted)
	select {
	case fm.placedDirSig <- struct{}{}:
	default:
	}
}

// evictPlacedDirsLocked drops the oldest waiting directories past the cap.
// The caller holds placedDirMu and reports what it returns.
func (fm *FileMonitor) evictPlacedDirsLocked(now time.Time) []placedDir {
	over := len(fm.placedDirs) - placedDirQueueLimit
	if over <= 0 {
		return nil
	}
	evicted := slices.Clone(fm.placedDirs[:over])
	fm.placedDirs = slices.Delete(fm.placedDirs, 0, over)
	for _, dir := range evicted {
		dir.ticket.Reject(now)
	}
	return evicted
}

func (fm *FileMonitor) reportEvictedPlacedDirs(evicted []placedDir) {
	for _, dir := range evicted {
		fm.reportPlacedDirIncomplete(dir, fmt.Sprintf("more than %d moved-in directories were waiting", placedDirQueueLimit))
	}
}

func (fm *FileMonitor) reportPlacedDirIncomplete(dir placedDir, reason string) {
	fm.sendAlertWithPath(alert.High, placedDirIncompleteCheck,
		fmt.Sprintf("Realtime protection did not finish checking a directory moved into a site: %s", dir.path),
		fmt.Sprintf("Realtime protection stopped before it reached every file in this directory: %s. The next deep scan covers the files it did not check.", reason),
		dir.path, dir.procInfo)
}

// placedDirLoop is the single walk worker. Run starts it; drainAndClose
// waits for it before closing the analyzer queue the walk feeds.
func (fm *FileMonitor) placedDirLoop() {
	defer fm.placedDirWG.Done()
	for {
		select {
		case <-fm.stopCh:
			return
		case <-fm.placedDirSig:
		}
		for fm.walkNextPlacedDir() {
		}
	}
}

// walkNextPlacedDir runs one bounded pass over the oldest waiting directory
// and reports whether there was one.
func (fm *FileMonitor) walkNextPlacedDir() bool {
	select {
	case <-fm.stopCh:
		return false
	default:
	}
	fm.placedDirMu.Lock()
	if len(fm.placedDirs) == 0 {
		fm.placedDirMu.Unlock()
		return false
	}
	dir := fm.placedDirs[0]
	fm.placedDirs = slices.Delete(fm.placedDirs, 0, 1)
	fm.placedDirMu.Unlock()

	dir.ticket.Start(time.Now())
	if wait := time.Until(dir.ready); wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-fm.stopCh:
			timer.Stop()
			dir.ticket.Reject(time.Now())
			return false
		case <-timer.C:
		}
	}
	yield, reason := fm.walkPlacedDirSafe(&dir)
	now := time.Now()
	switch {
	case yield:
		// Behind newer arrivals, so one large tree cannot starve them.
		dir.ticket.Requeue(now)
		fm.placedDirMu.Lock()
		fm.placedDirs = append(fm.placedDirs, dir)
		evicted := fm.evictPlacedDirsLocked(now)
		fm.placedDirMu.Unlock()
		fm.reportEvictedPlacedDirs(evicted)
	case reason != "":
		dir.ticket.Reject(now)
		fm.reportPlacedDirIncomplete(dir, reason)
	default:
		dir.ticket.Finish(now)
	}
	return true
}

// walkPlacedDirSafe contains a panic the way analyzeFileSafe does: one
// crafted tree must not stop the walks queued behind it.
func (fm *FileMonitor) walkPlacedDirSafe(dir *placedDir) (yield bool, reason string) {
	defer func() {
		if r := recover(); r != nil {
			fm.reportScannerPanic(dir.path, r)
			yield, reason = false, "the walk failed"
		}
	}()
	w := placedDirWalk{fm: fm, dir: dir, deadline: time.Now().Add(placedDirTimeLimit)}
	yield, reason = w.walk(nil, dir.dev, dir.ino, dir.cursor)
	switch {
	case yield && w.starved && w.files == 0:
		// A whole pass without analyzer headroom: realtime is saturated,
		// so say so instead of retrying this directory indefinitely.
		return false, "the realtime analyzers stayed busy for a whole walk pass"
	case yield || reason != "":
		return yield, reason
	case dir.overflowed:
		return false, fmt.Sprintf("it holds more than %d entries", placedDirEntryLimit)
	case dir.failed:
		return false, "some entries could not be read"
	}
	return false, ""
}

type placedDirWalk struct {
	fm       *FileMonitor
	dir      *placedDir
	deadline time.Time
	visited  int
	// files counts files handed to analysis this pass; starved records
	// that the pass ended waiting for analyzer headroom.
	files   int
	starved bool
}

// yield reports whether this pass must stop: the monitor is stopping, or
// the time budget is spent after at least one entry, so every pass advances.
func (w *placedDirWalk) yield() bool {
	return w.stopping() || w.visited > 0 && !time.Now().Before(w.deadline)
}

func (w *placedDirWalk) stopping() bool {
	select {
	case <-w.fm.stopCh:
		return true
	default:
	}
	return false
}

// headroom waits until the analyzer queue is at most half full, so a walk
// never admits faster than the analyzers drain and leaves room for live
// events. It reports false when the pass must end first.
func (w *placedDirWalk) headroom() bool {
	limit := max(cap(w.fm.analyzerCh)/2, 1)
	started := time.Now()
	deadline := w.deadline
	// A slow listing may already have spent this pass. Give the first
	// pending file its remaining congestion budget before repeating that I/O.
	if !started.Before(deadline) {
		deadline = started.Add(placedDirTimeLimit - w.dir.headroomWait)
	}
	for len(w.fm.analyzerCh) >= limit {
		waited := w.dir.headroomWait + time.Since(started)
		if waited >= placedDirTimeLimit {
			w.starved = true
			return false
		}
		wait := min(time.Until(deadline), placedDirTimeLimit-waited)
		if wait <= 0 {
			w.dir.headroomWait = waited
			return false
		}
		select {
		case <-w.fm.stopCh:
			return false
		case <-time.After(min(wait, placedDirHeadroomPoll)):
		}
	}
	w.dir.headroomWait = 0
	return true
}

// walk visits rel, the directory below the placed root that its parent's
// listing saw as dev+ino, from after, the rest of the resume cursor.
func (w *placedDirWalk) walk(rel []string, dev, ino uint64, after []string) (yield bool, reason string) {
	fd, ok := w.open(rel, dev, ino)
	if !ok {
		return false, ""
	}
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	from := ""
	if len(after) > 0 {
		from = after[0]
	}
	names, over, err := readDirNames(fd, from, placedDirEntryLimit-w.dir.entries)
	if err != nil {
		w.dir.failed = true
		return false, ""
	}
	w.dir.overflowed = w.dir.overflowed || over
	budgetCut := fmt.Sprintf("it holds more than %d entries", placedDirEntryLimit)
	for _, name := range names {
		var below []string
		revisit := false
		if len(after) > 0 {
			if name < after[0] {
				continue
			}
			if name == after[0] {
				revisit, below = true, after[1:]
			}
		}
		path := append(slices.Clip(rel), name)
		if !revisit {
			if w.yield() {
				return true, ""
			}
			if w.dir.entries >= placedDirEntryLimit {
				return false, budgetCut
			}
		}
		var st unix.Stat_t
		statErr := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
		regular := statErr == nil && st.Mode&unix.S_IFMT == unix.S_IFREG
		if !revisit {
			// Yield before the file, so the next pass starts with it.
			if regular && !w.headroom() {
				return true, ""
			}
			w.dir.entries++
			w.visited++
			w.dir.cursor = path
		}
		if statErr != nil {
			w.dir.failed = w.dir.failed || !errors.Is(statErr, unix.ENOENT)
			continue
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			if !revisit {
				w.file(fd, name, &st)
			}
		case unix.S_IFDIR:
			// Hold no descriptor for this level while below it, so a deep
			// tree cannot exhaust the daemon's descriptors.
			_ = unix.Close(fd)
			fd = -1
			if yield, reason = w.walk(path, uint64(st.Dev), st.Ino, below); yield || reason != "" {
				return yield, reason
			}
			if fd, ok = w.open(rel, dev, ino); !ok {
				return false, ""
			}
		}
	}
	return false, ""
}

// open reopens a directory of the walk by path. Only the final component is
// opened without following a symlink; the identity check then accepts only
// the directory the walk listed, so a swapped ancestor makes the reopen fail
// rather than read another tree. A directory moved away or replaced raised
// its own event and is not lost.
func (w *placedDirWalk) open(rel []string, dev, ino uint64) (int, bool) {
	path := filepath.Join(append([]string{w.dir.path}, rel...)...)
	fd, isDir, retry, err := openPlacedOnce(path, dev, ino)
	if err != nil {
		w.dir.failed = w.dir.failed || !retry
		return -1, false
	}
	if !isDir {
		_ = unix.Close(fd)
		return -1, false
	}
	return fd, true
}

// file runs one walked file through the placed-file path, opened relative
// to its listed directory with the identity the listing saw.
func (w *placedDirWalk) file(dirfd int, name string, st *unix.Stat_t) {
	fd, isDir, retry, err := openPlacedAt(dirfd, name, uint64(st.Dev), st.Ino)
	if err != nil {
		w.dir.failed = w.dir.failed || !retry
		return
	}
	if isDir {
		_ = unix.Close(fd)
		return
	}
	w.files++
	w.fm.handlePlacedFile(fd, w.dir.pid, w.dir.at)
}

// readDirNames lists the names of fd's directory from from on, sorted,
// without consuming fd. It stops reading once more than limit names past
// from are held: those alone exceed the entry budget, so the walk is cut and
// their order no longer matters. Names before the cursor count against the
// full entry budget too, or a growing directory could make a resume unbounded.
func readDirNames(fd int, from string, limit int) (names []string, over bool, err error) {
	dup, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, false, err
	}
	// #nosec G115 -- Openat returned a non-negative descriptor because err is nil.
	dir := os.NewFile(uintptr(dup), ".")
	defer func() { _ = dir.Close() }()
	fresh, read := 0, 0
	for {
		batch, err := placedDirReadNames(dir, placedDirReadBatch)
		for _, name := range batch {
			read++
			if name >= from {
				names = append(names, name)
				if name > from {
					fresh++
				}
			}
			if fresh > limit || read > placedDirEntryLimit {
				slices.Sort(names)
				return names, true, nil
			}
		}
		if errors.Is(err, io.EOF) {
			slices.Sort(names)
			return names, false, nil
		}
		if err != nil {
			return nil, false, err
		}
	}
}

// discardPlacedDirs counts directories still waiting at shutdown as lost.
// The walk worker has exited before this runs.
func (fm *FileMonitor) discardPlacedDirs() {
	fm.placedDirMu.Lock()
	defer fm.placedDirMu.Unlock()
	now := time.Now()
	for _, dir := range fm.placedDirs {
		dir.ticket.Reject(now)
	}
	fm.placedDirs = nil
}
