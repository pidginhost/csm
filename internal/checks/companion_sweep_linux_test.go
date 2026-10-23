//go:build linux

package checks

import (
	"syscall"
	"time"
)

func setStatChangeTime(st *syscall.Stat_t, at time.Time) {
	st.Ctim = syscall.NsecToTimespec(at.UnixNano())
}
