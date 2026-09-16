//go:build linux

package daemon

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/emailav"
)

// A verdict deadline can let Exim start delivery while we scan. Take its body
// lock before touching either spool file, even if the deadline has not fired
// yet: it may fire during the move. An OFD lock also excludes other workers
// and survives unrelated parser closes, unlike process-wide F_SETLK locks.
func (sw *SpoolWatcher) quarantineSpoolEvent(evt spoolEvent, msgID, spoolDir string, result *emailav.ScanResult, env emailav.QuarantineEnvelope) error {
	fd, err := unix.Open(evt.path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("opening spool body for quarantine: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: int16(io.SeekStart)}
	// #nosec G115 -- successful unix.Open returned a nonnegative POSIX fd.
	if err := unix.FcntlFlock(uintptr(fd), unix.F_OFD_SETLK, &lock); err != nil {
		return fmt.Errorf("locking spool body for quarantine: %w", err)
	}
	var original, current unix.Stat_t
	if err := unix.Fstat(evt.fd, &original); err != nil {
		return fmt.Errorf("checking event body for quarantine: %w", err)
	}
	if err := unix.Lstat(evt.path, &current); err != nil {
		return fmt.Errorf("checking spool body for quarantine: %w", err)
	}
	var locked unix.Stat_t
	if err := unix.Fstat(fd, &locked); err != nil {
		return fmt.Errorf("checking locked body for quarantine: %w", err)
	}
	if current.Mode&unix.S_IFMT != unix.S_IFREG || original.Dev != current.Dev || original.Ino != current.Ino || locked.Dev != current.Dev || locked.Ino != current.Ino {
		return fmt.Errorf("spool body changed before quarantine")
	}
	// A delivery journal contains recipients already delivered. The quarantine
	// format stores only H/D; separating a surviving journal would lose that
	// state on release and could send duplicates. Leave it for Exim recovery.
	if _, err := os.Lstat(filepath.Join(spoolDir, msgID+"-J")); !os.IsNotExist(err) {
		if err != nil {
			return fmt.Errorf("checking delivery journal: %w", err)
		}
		return fmt.Errorf("spool delivery journal requires Exim recovery before quarantine")
	}
	if _, err := os.Lstat(filepath.Join(spoolDir, msgID+"-H")); err != nil {
		return fmt.Errorf("checking spool header for quarantine: %w", err)
	}
	return sw.quarantine.QuarantineMessage(msgID, spoolDir, result, env)
}
