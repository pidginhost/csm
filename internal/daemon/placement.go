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
// and response as a write at that path.
func (fm *FileMonitor) handlePlacement(ev placementEvent) {
	// Recovery copies keep their original names; analysing them repeats
	// detections CSM already acted on.
	if checks.InQuarantine(ev.Path) {
		return
	}
	fd, isDir, err := openPlacedFile(ev.Path, ev.Dev, ev.Ino)
	if err != nil {
		fm.placementUnverified.Add(1)
		return
	}
	if isDir {
		_ = unix.Close(fd)
		fm.queuePlacedDir(ev.Path, ev.Dev, ev.Ino, ev.PID)
		return
	}
	fm.handlePlacedFile(fd, ev.PID, ev.At)
}

// handlePlacedFile takes ownership of fd, a regular file whose identity the
// caller already verified.
func (fm *FileMonitor) handlePlacedFile(fd int, pid int32, at time.Time) {
	fm.handleEventAt(fd, pid, eventPlacedIn, at)
}

// queuePlacedDir hands a placed-in directory to the bounded walk. Until that
// walk exists, only the directory's later writes are seen.
func (fm *FileMonitor) queuePlacedDir(path string, dev, ino uint64, pid int32) {}

// openPlacedFile opens path without following a final symlink and returns the
// descriptor only when it is the regular file or directory the kernel
// reported. A different inode at the path is never analysed in its place.
func openPlacedFile(path string, dev, ino uint64) (fd int, isDir bool, err error) {
	for attempt := 0; ; attempt++ {
		fd, isDir, retry, err := openPlacedOnce(path, dev, ino)
		if err == nil {
			return fd, isDir, nil
		}
		if !retry || attempt == len(placementRetryDelays) {
			return -1, false, fmt.Errorf("%w: %s: %v", errPlacementUnverified, path, err)
		}
		time.Sleep(placementRetryDelays[attempt])
	}
}

// openPlacedOnce reports retry for the two states a pending rename or link
// can leave behind: no entry yet, or the old inode still in place.
func openPlacedOnce(path string, dev, ino uint64) (fd int, isDir, retry bool, err error) {
	fd, err = unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, false, errors.Is(err, unix.ENOENT), err
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, false, false, err
	}
	if uint64(st.Dev) != dev || st.Ino != ino {
		_ = unix.Close(fd)
		return -1, false, true, errors.New("identity mismatch")
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		return fd, false, false, nil
	case unix.S_IFDIR:
		return fd, true, false, nil
	}
	_ = unix.Close(fd)
	return -1, false, false, errors.New("not a regular file or directory")
}
