//go:build linux

package admissionowner

import (
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"golang.org/x/sys/unix"
)

// ReadClock reads the host clocks. Time since boot is the boot-time clock,
// which keeps counting while the host is suspended, so a same-boot restart
// resumes from where the ledger left off.
func ReadClock() (admission.ClockReading, error) {
	return readClock(bootIDPath, time.Now, func() (time.Duration, error) {
		var ts unix.Timespec
		if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
			return 0, err
		}
		return time.Duration(ts.Nano()), nil
	})
}
