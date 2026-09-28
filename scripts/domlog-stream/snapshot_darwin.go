package main

import (
	"os"
	"syscall"
)

// A writer can restore mtime after rewriting a copy, but not ctime.
func sameInputChangeTime(before, after os.FileInfo) bool {
	a, aOK := before.Sys().(*syscall.Stat_t)
	b, bOK := after.Sys().(*syscall.Stat_t)
	return aOK && bOK && a.Ctimespec == b.Ctimespec
}
