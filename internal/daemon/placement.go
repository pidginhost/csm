//go:build linux

package daemon

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/checks"
)

// placementKind names how a directory entry appeared in a watched tree.
type placementKind uint8

const (
	placementRename placementKind = iota + 1
	placementLink
	placementCreate
)

// placementEvent is a file or directory renamed, linked or created into a
// watched tree. Close-write never fires for these, so a placement backend
// reports them with the identity the kernel saw at the time.
type placementEvent struct {
	Path     string
	Dev, Ino uint64
	IsDir    bool
	PID      int32
	Kind     placementKind
	At       time.Time
}

// eventPlacedIn is the synthetic mask bit for a placed-in file. No fanotify
// event uses bit 63. The file's content is complete: it was written elsewhere
// before it appeared at this path.
const eventPlacedIn uint64 = 1 << 63

var errPlacementUnverified = errors.New("placed file not found with the reported identity")

// placementRetryDelays cover a backend that reports the entry before the
// rename or link is visible to a lookup.
var placementRetryDelays = [...]time.Duration{50 * time.Millisecond, 200 * time.Millisecond}

// handlePlacement runs a placed-in file through the same admission, analysis
// and response as a write at that path. It waits out a rename or link the
// kernel reported before it took effect.
func (fm *FileMonitor) handlePlacement(ev placementEvent) {
	fm.verifyPlacement(ev, placementRetryDelays[:])
}

// handleResolvedPlacement is handlePlacement for a backend that read the
// identity from the entry after the event: a mismatch is a replacement made
// since, which no wait undoes.
func (fm *FileMonitor) handleResolvedPlacement(ev placementEvent) {
	fm.verifyPlacement(ev, nil)
}

func (fm *FileMonitor) verifyPlacement(ev placementEvent, retryDelays []time.Duration) {
	// Recovery copies keep their original names; analysing them repeats
	// detections CSM already acted on.
	if checks.InQuarantine(ev.Path) {
		return
	}
	fd, isDir, err := openPlacedFile(ev.Path, ev.Dev, ev.Ino, retryDelays)
	if err != nil {
		fm.placementUnverified.Add(1)
		if fanotifyPlacementUnverified != nil {
			fanotifyPlacementUnverified.Inc()
		}
		return
	}
	if isDir {
		_ = unix.Close(fd)
		fm.queuePlacedDir(ev.Path, ev.Dev, ev.Ino, ev.PID, ev.At, time.Time{})
		return
	}
	fm.handlePlacedFile(fd, ev.PID, ev.At)
}

// recoverDroppedPlacement hands a placement a full backend queue refused to
// overflow recovery: a rescan of a file's directory in placement mode, or the
// walk of a moved-in directory, which the rescan does not descend into.
func (fm *FileMonitor) recoverDroppedPlacement(ev placementEvent) {
	// The ring reports intent before the syscall commits. Recovery has no
	// descriptor to prove completion, so give it the same visibility window
	// as the identity-checking workers without blocking the ring reader.
	ready := time.Now()
	for _, delay := range placementRetryDelays {
		ready = ready.Add(delay)
	}
	fm.recoverPlacementAfter(ev, ready)
}

func (fm *FileMonitor) recoverPlacementAfter(ev placementEvent, ready time.Time) {
	if ev.IsDir {
		fm.queuePlacedDir(ev.Path, ev.Dev, ev.Ino, ev.PID, ev.At, ready)
		return
	}
	fm.recordDroppedEventAfter(fileEvent{path: ev.Path, mask: eventPlacedIn}, ready)
}

// handlePlacedFile takes ownership of fd, a regular file whose identity the
// caller already verified.
func (fm *FileMonitor) handlePlacedFile(fd int, pid int32, at time.Time) {
	path, _, ok := eventFDPath(fd)
	if !ok {
		fm.rejectUnresolved(fd)
		return
	}
	event, admit := fm.classifyEvent(path, fd)
	if admit && fm.analyzedUnchanged(event) {
		fm.placementSkipped.Add(1)
		if fanotifyPlacementSkipped != nil {
			fanotifyPlacementSkipped.Inc()
		}
		// Only the content analysis is redundant. The deletion probe checks
		// the path a candidate was tracked at, and this path is new.
		event.pid, event.mask, event.at = pid, eventPlacedIn, at
		fm.observeDropperCandidate(event, resolveProcessInfo(pid))
		_ = unix.Close(fd)
		return
	}
	fm.admitEvent(fd, event, admit, pid, eventPlacedIn, at)
}

// analyzedUnchanged reports whether this file version was analysed recently
// with the same outcome-relevant class it gets at its new path.
func (fm *FileMonitor) analyzedUnchanged(ev fileEvent) bool {
	// Restore detection keys on the destination: a payload renamed back over
	// the path it was removed from is the restore, whatever ran before.
	if _, removed := removedFileAt(ev.path); removed {
		return false
	}
	snapshot, ok := snapshotForAnalysis(ev.fd, fm.eventClass(ev))
	return ok && fm.recent.Seen(snapshot.key, time.Now())
}

// openPlacedFile opens path without following a final symlink and returns the
// descriptor only when it is the regular file or directory the kernel
// reported. A different inode at the path is never analysed in its place.
func openPlacedFile(path string, dev, ino uint64, retryDelays []time.Duration) (fd int, isDir bool, err error) {
	for attempt := 0; ; attempt++ {
		fd, isDir, retry, err := openPlacedOnce(path, dev, ino)
		if err == nil {
			return fd, isDir, nil
		}
		if !retry || attempt == len(retryDelays) {
			return -1, false, fmt.Errorf("%w: %s: %v", errPlacementUnverified, path, err)
		}
		time.Sleep(retryDelays[attempt])
	}
}

// openPlacedOnce reports retry for the two states a pending rename or link
// can leave behind: no entry yet, or the old inode still in place.
func openPlacedOnce(path string, dev, ino uint64) (fd int, isDir, retry bool, err error) {
	return openPlacedAt(unix.AT_FDCWD, path, dev, ino)
}

// openPlacedAt is openPlacedOnce for name relative to dirfd.
func openPlacedAt(dirfd int, name string, dev, ino uint64) (fd int, isDir, retry bool, err error) {
	// A pending rename may replace any entry, including a socket or device.
	// O_PATH lets identity checks precede I/O and keeps mismatches retryable.
	probe, err := unix.Openat(dirfd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, false, errors.Is(err, unix.ENOENT), err
	}
	defer func() { _ = unix.Close(probe) }()
	var st unix.Stat_t
	if err = unix.Fstat(probe, &st); err != nil {
		return -1, false, false, err
	}
	if uint64(st.Dev) != dev || st.Ino != ino {
		return -1, false, true, errors.New("identity mismatch")
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
	case unix.S_IFDIR:
		isDir = true
	default:
		return -1, false, false, errors.New("not a regular file or directory")
	}
	// Follow only our own procfs descriptor link, not the mutable entry.
	// The pinned inode cannot become a special file between stat and open.
	fd, err = unix.Open(fmt.Sprintf("/proc/self/fd/%d", probe), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, false, false, err
	}
	return fd, isDir, false, nil
}

// Recovery runs inline under the existing reconcile budget; enqueueing again
// would lose the file to the same backpressure that started recovery.
func (fm *FileMonitor) reconcilePlacedFile(path string, dev, ino uint64) bool {
	fd, isDir, _, err := openPlacedOnce(path, dev, ino)
	if err != nil {
		return errors.Is(err, unix.ENOENT)
	}
	defer func() { _ = unix.Close(fd) }()
	if isDir {
		return true
	}
	if event, admit := fm.classifyEvent(path, fd); admit {
		event.mask, event.at = eventPlacedIn, time.Now()
		fileAnalyzer(fm, event)
	}
	return true
}
