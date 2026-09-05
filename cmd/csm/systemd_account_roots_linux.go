//go:build linux

package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func serviceRootWritable(pid uint32, path string) (bool, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(fmt.Sprintf("/proc/%d/root%s", pid, path), &stat); err != nil {
		return false, err
	}
	return stat.Flags&unix.ST_RDONLY == 0, nil
}
