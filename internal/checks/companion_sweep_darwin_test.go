//go:build darwin

package checks

import (
	"syscall"
	"time"
)

func setStatChangeTime(st *syscall.Stat_t, at time.Time) {
	st.Ctimespec = syscall.NsecToTimespec(at.UnixNano())
}
