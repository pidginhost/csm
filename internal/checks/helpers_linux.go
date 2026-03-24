//go:build linux

package checks

import (
	"syscall"
	"time"
)

func statBirthTime(stat *syscall.Stat_t) time.Time {
	return time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec)
}
