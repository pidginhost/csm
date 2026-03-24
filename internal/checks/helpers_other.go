//go:build !linux

package checks

import (
	"syscall"
	"time"
)

func statBirthTime(_ *syscall.Stat_t) time.Time {
	return time.Time{}
}
