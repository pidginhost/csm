//go:build !linux

package safepath

import (
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// SetModTime uses the host's fd-bound microsecond API on development platforms.
func SetModTime(file *os.File, mtime time.Time) error {
	ts, err := unix.TimeToTimespec(mtime)
	if err != nil {
		return err
	}
	tv := unix.NsecToTimeval(int64(mtime.Nanosecond()/1000) * 1000)
	tv.Sec = ts.Sec
	err = unix.Futimes(fileFD(file), []unix.Timeval{tv, tv})
	runtime.KeepAlive(file)
	return err
}
